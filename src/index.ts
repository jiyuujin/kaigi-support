/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.jsonc`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

interface Env {
  GOOGLE_SERVICE_ACCOUNT_EMAIL: string;
  GOOGLE_PRIVATE_KEY: string;
  GEMINI_API_KEY: string;
  KAIGI_MAP: string; // JSON: { "TEAM_ID": { "folderId": "...", "token": "xoxb-...", "sub": "email@domain.jp" } }
  KAIGI_CACHE_KV: KVNamespace;
  KAIGI_VECTORIZE: VectorizeIndex;
  CRON_SECRET?: string;
}

type ConferenceConfig = Record<
  string,
  {
    folderId: string;
    token: string;
    sub: string; // サービスアカウントの委任先メールアドレス
  }
>;

interface FileMetadata {
  id: string;
  name: string;
  mimeType: string;
  modifiedTime: string;
  path: string;
}

const SEMANTIC_CACHE_THRESHOLD = 1.0; // 0.92;
const TOP_K_FILES = 25;

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/cron/update-cache' && request.method === 'POST') {
      const authHeader = request.headers.get('Authorization');
      if (authHeader !== `Bearer ${env.CRON_SECRET || 'your-secret-here'}`) {
        return new Response('Unauthorized', { status: 401 });
      }

      const teamId = url.searchParams.get('team') ?? undefined;
      const phase = url.searchParams.get('phase') ?? 'files';
      const offset = parseInt(url.searchParams.get('offset') ?? '0', 10);

      if (phase === 'files') {
        ctx.waitUntil(updateFileCache(env, teamId));
      } else {
        ctx.waitUntil(updateEmbedCache(env, teamId, offset, 5));
      }
      return new Response(`Cache update started: phase=${phase}${teamId ? ` team=${teamId}` : ''}`);
    }

    if (url.pathname === '/slack/events' && request.method === 'POST') {
      const contentType = request.headers.get('content-type') || '';

      // 1. Slash コマンド
      if (contentType.includes('application/x-www-form-urlencoded')) {
        const formData = await request.formData();
        const slackTeamId = formData.get('team_id') as string;
        const userQuestion = formData.get('text') as string;
        const channelId = formData.get('channel_id') as string;
        const userId = formData.get('user_id') as string;

        const confMap: ConferenceConfig = JSON.parse(env.KAIGI_MAP);
        const config = confMap[slackTeamId];

        if (config) {
          ctx.waitUntil(handleAiResponse(env, { channel: channelId, user: userId }, config, userQuestion));
          return new Response('📚 議事録を調べています。少々お待ちください...');
        }
        return new Response(`設定が見つかりません (Team ID: ${slackTeamId})`, { status: 200 });
      }

      // 2. メンション
      if (contentType.includes('application/json')) {
        const body: any = await request.json();

        // Slack の URL 検証
        if (body.type === 'url_verification') {
          return new Response(body.challenge);
        }

        if (body.event?.type === 'app_mention') {
          const slackTeamId = body.team_id;
          const userQuestion = body.event.text.replace(/<@[A-Z0-9]+>/g, '').trim(); // メンション部分を削除
          const confMap: ConferenceConfig = JSON.parse(env.KAIGI_MAP);
          const config = confMap[slackTeamId];

          if (config) {
            ctx.waitUntil(handleAiResponse(env, body.event, config, userQuestion));
            return new Response('OK', { status: 200 });
          }
        }
      }
    }

    return new Response('Not Found', { status: 404 });
  },
  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext) {
    await updateFileCache(env);

    for (const teamId of Object.keys(JSON.parse(env.KAIGI_MAP) as ConferenceConfig)) {
      for (let offset = 0; offset < 30; offset += 5) {
        ctx.waitUntil(updateEmbedCache(env, teamId, offset, 5));
        await sleep(15000); // 15s 間隔
      }
      await sleep(60000); // チーム間で 1-minute 待機する
    }
  },
} satisfies ExportedHandler<Env>;

async function updateFileCache(env: Env, targetTeamId?: string) {
  const confMap: ConferenceConfig = JSON.parse(env.KAIGI_MAP);
  const entries = Object.entries(confMap).filter(([teamId]) => !targetTeamId || teamId === targetTeamId);

  for (const [teamId, config] of entries) {
    try {
      console.log(`Fetching files for team: ${teamId}`);
      const gToken = await getGoogleWorkspaceAccessToken(env, config.sub);
      const files = await fetchFilesLimited(config.folderId, gToken, 30);
      await env.KAIGI_CACHE_KV.put(`meta:${config.folderId}`, JSON.stringify(files), { expirationTtl: 86400 });
      console.log(`✅ File list cached for team ${teamId}: ${files.length} files`);
    } catch (e: any) {
      console.error(`❌ Failed for team ${teamId}:`, e.message);
    }
  }
}

async function updateEmbedCache(env: Env, targetTeamId?: string, offset: number = 0, batchSize: number = 5) {
  const confMap: ConferenceConfig = JSON.parse(env.KAIGI_MAP);
  const entries = Object.entries(confMap).filter(([teamId]) => !targetTeamId || teamId === targetTeamId);

  for (const [teamId, config] of entries) {
    try {
      const fileList = (await env.KAIGI_CACHE_KV.get(`meta:${config.folderId}`, { type: 'json' })) as FileMetadata[] | null;
      if (!fileList) {
        console.error(`No file list found for team ${teamId}`);
        continue;
      }

      const batch = fileList.slice(offset, offset + batchSize);
      if (batch.length === 0) {
        console.log(`✅ All files embedded for team ${teamId}`);
        continue;
      }

      console.log(`Embedding files for team ${teamId}: ${offset + 1}〜${offset + batch.length} / ${fileList.length}`);
      const gToken = await getGoogleWorkspaceAccessToken(env, config.sub);
      await Promise.all(batch.map((file) => cacheFileAndEmbed(env, file, gToken, config.folderId)));
      console.log(`✅ Done: ${offset + batch.length} / ${fileList.length}`);
    } catch (e: any) {
      console.error(`❌ Failed for team ${teamId}:`, e.message);
    }
  }
}

// async function updateAllCaches(env: Env, targetTeamId?: string) {
//   const confMap: ConferenceConfig = JSON.parse(env.KAIGI_MAP);
//   const entries = Object.entries(confMap).filter(([teamId]) => !targetTeamId || teamId === targetTeamId);

//   for (const [teamId, config] of entries) {
//     try {
//       console.log(`Updating cache for team: ${teamId}`);
//       const gToken = await getGoogleWorkspaceAccessToken(env, config.sub);

//       const files = await fetchFilesLimited(config.folderId, gToken, 30);

//       await env.KAIGI_CACHE_KV.put(
//         `meta:${config.folderId}`,
//         JSON.stringify(files),
//         { expirationTtl: 7200 * 12 }, // 24 hours
//       );

//       const chunks = chunkArray(files, 2);
//       for (const chunk of chunks) {
//         await Promise.all(chunk.map((file) => cacheFileAndEmbed(env, file, gToken, config.folderId)));
//         await sleep(200); // チャンク間で 200ms 待機する
//       }

//       console.log(`✅ Cache + vectors updated for team ${teamId}: ${files.length} files`);
//     } catch (e: any) {
//       console.error(`❌ Failed to update cache for team ${teamId}:`, e.message);
//     }

//     await sleep(1000); // チーム間でも待機する
//   }
// }

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function cacheFileAndEmbed(env: Env, file: FileMetadata, accessToken: string, folderId: string) {
  let content = '';
  try {
    if (file.mimeType === 'application/vnd.google-apps.document') {
      content = await exportDocText(file.id, accessToken);
    } else if (file.mimeType === 'application/vnd.google-apps.spreadsheet') {
      content = await exportSheetText(file.id, accessToken);
    }
    if (!content) return;

    const contentCacheKey = `content:${folderId}:${file.id}:${file.modifiedTime}`;
    await env.KAIGI_CACHE_KV.put(contentCacheKey, content, { expirationTtl: 86400 });

    const snippet = content.slice(0, 3000);
    const embedding = await getEmbedding(env, snippet);

    // file.id をハッシュ化して 16 文字に短縮する
    const shortId = await hashString(`${folderId}:${file.id}`);
    await env.KAIGI_VECTORIZE.upsert([
      {
        id: shortId,
        values: embedding,
        metadata: {
          folderId,
          fileId: file.id,
          path: file.path,
          modifiedTime: file.modifiedTime,
        },
      },
    ]);
  } catch (e: any) {
    console.error(`Failed to cache/embed ${file.path}:`, e.message);
  }
}

async function handleAiResponse(env: Env, event: any, config: ConferenceConfig[string], question: string) {
  const startTime = Date.now();
  const debug = (msg: string) => console.log(`[${((Date.now() - startTime) / 1000).toFixed(1)}s] ${msg}`);

  try {
    debug('🔍 セマンティックキャッシュ確認中...');
    const questionEmbedding = await getEmbedding(env, question);
    const cacheHit = await searchSemanticCache(env, config.folderId, questionEmbedding);
    if (cacheHit) {
      debug('⚡ セマンティックキャッシュヒット');
      await postToSlack(event.channel, `<@${event.user}>\n\n${cacheHit}\n\n_※ 過去の類似質問より_`, config.token);
      return;
    }

    debug('🔑 キーワード抽出中 (Flash Lite)...');
    const keywords = await extractKeywords(env, question);
    debug(`   キーワード: ${keywords.join(', ')}`);

    debug('🔎 Vectorize でファイル選択中...');
    const topFiles = await searchRelevantFiles(env, config.folderId, questionEmbedding, keywords);
    debug(`   選択されたファイル: ${topFiles.map((f) => f.path).join(', ')}`);

    if (topFiles.length === 0) {
      await postToSlack(event.channel, `<@${event.user}> 関連する資料が見つかりませんでした。`, config.token);
      return;
    }

    debug('📂 ファイルコンテンツ取得中...');
    const gToken = await getGoogleWorkspaceAccessToken(env, config.sub);
    const contents = await Promise.all(topFiles.map((file) => getFileContentCached(env, file, gToken, config.folderId)));

    const validContents = contents.filter((c) => c.content.length > 0);
    const context = validContents.map((c) => `\n\n=== ${c.path} ===\n${c.content}`).join('');

    debug(`✅ コンテキスト準備完了 (${context.length} 文字, ${validContents.length} ファイル)`);

    if (context.length < 100) {
      await postToSlack(event.channel, `<@${event.user}> 資料の内容が取得できませんでした。`, config.token);
      return;
    }

    debug('🤖 Gemini Flash で回答生成中...');
    const answer = await askGemini(
      env,
      question,
      context,
      validContents.map((c) => c.path),
    );

    await postToSlack(event.channel, `<@${event.user}>\n\n${answer}`, config.token);
    await saveSemanticCache(env, config.folderId, questionEmbedding, question, answer);
    debug('🎉 完了！');
  } catch (error: any) {
    console.error('❌ Error:', error);
    await postToSlack(event.channel, `<@${event.user}> エラー: ${error.message}`, config.token).catch(() => {});
  }
}

async function searchSemanticCache(env: Env, folderId: string, embedding: number[]): Promise<string | null> {
  try {
    const results = await env.KAIGI_VECTORIZE.query(embedding, {
      topK: 50,
      returnMetadata: 'all',
      // filter を削除
    });
    const top = results.matches?.filter((m) => m.metadata?.folderId === folderId && m.metadata?.type === 'qa_cache')?.[0];
    if (top && top.score >= SEMANTIC_CACHE_THRESHOLD) {
      const cached = await env.KAIGI_CACHE_KV.get(`qa_vec:${folderId}:${top.id}`);
      if (cached) return cached;
    }
  } catch (e: any) {
    console.warn('Semantic cache search failed:', e.message);
  }
  return null;
}

async function saveSemanticCache(env: Env, folderId: string, embedding: number[], question: string, answer: string) {
  try {
    const id = await hashString(`qa:${folderId}:${question}`);
    await env.KAIGI_VECTORIZE.upsert([
      {
        id,
        values: embedding,
        metadata: { folderId, type: 'qa_cache', question: question.slice(0, 200) },
      },
    ]);
    await env.KAIGI_CACHE_KV.put(`qa_vec:${folderId}:${id}`, answer, { expirationTtl: 86400 });
  } catch (e: any) {
    console.warn('Semantic cache save failed:', e.message);
  }
}

async function searchRelevantFiles(env: Env, folderId: string, embedding: number[], keywords: string[]): Promise<FileMetadata[]> {
  const results = await env.KAIGI_VECTORIZE.query(embedding, {
    topK: TOP_K_FILES * 2,
    returnMetadata: 'all',
    // filter を削除
  });

  const matches = results.matches ?? [];
  console.log('Vectorize raw matches count:', matches.length);

  const scored = matches
    .filter((m) => m.metadata?.type !== 'qa_cache')
    .filter((m) => m.metadata?.folderId === folderId)
    .map((m) => {
      const path = (m.metadata?.path as string) ?? '';
      const modifiedTime = (m.metadata?.modifiedTime as string) ?? '';
      const keywordBonus = keywords.filter((kw) => path.toLowerCase().includes(kw.toLowerCase())).length * 0.05;

      // 更新日時が新しいほどボーナス（最大 0.1）
      const ageBonus = modifiedTime ? Math.max(0, 0.1 - (Date.now() - new Date(modifiedTime).getTime()) / (1000 * 60 * 60 * 24 * 365)) : 0;

      return { match: m, score: m.score + keywordBonus + ageBonus };
    })
    .sort((a, b) => b.score - a.score)
    .slice(0, TOP_K_FILES);

  return scored.map((s) => ({
    id: (s.match.metadata?.fileId as string) ?? '',
    name: (s.match.metadata?.path as string) ?? '',
    mimeType: 'application/vnd.google-apps.document',
    modifiedTime: (s.match.metadata?.modifiedTime as string) ?? '',
    path: (s.match.metadata?.path as string) ?? '',
  }));
}

async function getEmbedding(env: Env, text: string): Promise<number[]> {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-embedding-001:embedContent?key=${env.GEMINI_API_KEY}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: 'models/gemini-embedding-001',
      content: { parts: [{ text: text.slice(0, 2048) }] },
      outputDimensionality: 768,
    }),
  });
  if (!res.ok) throw new Error(`Embedding API Error: ${res.status}`);
  const data: any = await res.json();
  return data.embedding.values;
}

async function extractKeywords(env: Env, question: string): Promise<string[]> {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent?key=${env.GEMINI_API_KEY}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [
        {
          parts: [
            {
              text: `以下の質問から、議事録ファイル名に含まれそうな重要キーワードを最大5つ抽出してください。
特に年度の指定がない場合は "${new Date().getFullYear()}" を必ず含めてください。
JSON配列のみを返してください（説明不要）。

質問: ${question}

例: ["予算", "${new Date().getFullYear()}年", "スポンサー"]`,
            },
          ],
        },
      ],
      generationConfig: { maxOutputTokens: 100, temperature: 0 },
    }),
  });
  if (!res.ok) {
    console.error('Flash Lite error:', res.status, await res.text());
    return [];
  }
  const data: any = await res.json();
  const text = data.candidates?.[0]?.content?.parts?.[0]?.text ?? '[]';
  console.log('Flash Lite raw response:', text);
  try {
    const clean = text.replace(/```json|```/g, '').trim();
    return JSON.parse(clean);
  } catch {
    return [];
  }
}

async function askGemini(env: Env, question: string, context: string, fileNames: string[]): Promise<string> {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${env.GEMINI_API_KEY}`;

  const prompt = `あなたはカンファレンス運営を支援する優秀なアシスタントです。

以下の【運営議事録・資料】に基づいて、運営スタッフからの【質問】に正確かつ簡潔に答えてください。

【回答の指針】
- 資料に記載されている情報のみを使用してください
- 資料にない情報は推測せず、「資料には記載がありません」と答えてください
- 可能な限り具体的な情報（日付、担当者、金額など）を含めてください
- どの資料に記載があったかを明記してください
- 簡潔に、要点を絞って回答してください（箇条書き推奨）

【参照資料】
${fileNames.map((name, i) => `${i + 1}. ${name}`).join('\n')}

【運営議事録・資料】
${context.slice(0, 800000)}

---

【質問】
${question}`;

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: {
        maxOutputTokens: 2000,
        temperature: 0.1,
      },
    }),
  });
  if (!res.ok) throw new Error(`Gemini API Error: ${res.status}`);
  const data: any = await res.json();
  return data.candidates?.[0]?.content?.parts?.[0]?.text || '回答を生成できませんでした。';
}

async function fetchFilesLimited(
  folderId: string,
  accessToken: string,
  maxFiles: number = 30,
  parentPath: string = '',
  depth: number = 0,
): Promise<FileMetadata[]> {
  if (depth > 3) return [];

  const allFiles: FileMetadata[] = [];

  const params = new URLSearchParams({
    q: `'${folderId}' in parents and trashed = false`,
    fields: 'files(id,name,mimeType,modifiedTime)',
    orderBy: 'modifiedTime desc',
    pageSize: '50',
    supportsAllDrives: 'true',
    includeItemsFromAllDrives: 'true',
  });

  const listRes = await fetch(`https://www.googleapis.com/drive/v3/files?${params}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!listRes.ok) {
    throw new Error(`Drive API Error: ${listRes.status}`);
  }

  const listData: any = await listRes.json();
  const items = listData.files ?? [];
  const currentYear = new Date().getFullYear().toString();

  const sorted = [...items.filter((i: any) => i.name.includes(currentYear)), ...items.filter((i: any) => !i.name.includes(currentYear))];

  for (const item of sorted) {
    if (allFiles.length >= maxFiles) break;

    const itemPath = parentPath ? `${parentPath}/${item.name}` : item.name;

    if (item.mimeType === 'application/vnd.google-apps.document' || item.mimeType === 'application/vnd.google-apps.spreadsheet') {
      allFiles.push({
        id: item.id,
        name: item.name,
        mimeType: item.mimeType,
        modifiedTime: item.modifiedTime,
        path: itemPath,
      });
    } else if (item.mimeType === 'application/vnd.google-apps.folder') {
      const subFiles = await fetchFilesLimited(item.id, accessToken, maxFiles - allFiles.length, itemPath, depth + 1);
      allFiles.push(...subFiles);
    }
  }

  return allFiles;
}

async function getFileContentCached(
  env: Env,
  file: FileMetadata,
  accessToken: string,
  folderId: string,
): Promise<{ path: string; content: string }> {
  const key = `content:${folderId}:${file.id}:${file.modifiedTime}`;
  const cached = await env.KAIGI_CACHE_KV.get(key);

  if (cached) {
    return { path: file.path, content: cached };
  }

  let content = '';
  if (file.mimeType === 'application/vnd.google-apps.document') {
    content = await exportDocText(file.id, accessToken);
  } else if (file.mimeType === 'application/vnd.google-apps.spreadsheet') {
    content = await exportSheetText(file.id, accessToken);
  }
  if (content) {
    await env.KAIGI_CACHE_KV.put(key, content, { expirationTtl: 86400 });
  }

  return { path: file.path, content };
}

async function exportDocText(fileId: string, accessToken: string): Promise<string> {
  const res = await fetch(`https://www.googleapis.com/drive/v3/files/${fileId}/export?mimeType=text/plain`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  return res.ok ? (await res.text()).trim() : '';
}

async function exportSheetText(fileId: string, accessToken: string): Promise<string> {
  const res = await fetch(`https://www.googleapis.com/drive/v3/files/${fileId}/export?mimeType=text/csv`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!res.ok) return '';

  const lines = (await res.text()).trim().split('\n');
  return lines.map((line, i) => (i === 0 ? `[ヘッダー] ${line}` : line)).join('\n');
}

async function postToSlack(channel: string, text: string, slackToken: string) {
  const res = await fetch('https://slack.com/api/chat.postMessage', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${slackToken}`,
    },
    body: JSON.stringify({
      channel,
      text,
      unfurl_links: false,
      unfurl_media: false,
    }),
  });

  const result: any = await res.json();
  if (!result.ok) {
    throw new Error(`Slack Post Error: ${result.error}`);
  }
}

async function getGoogleWorkspaceAccessToken(env: Env, subEmail: string): Promise<string> {
  const cacheKey = `gtoken:${subEmail}`;
  const cached = await env.KAIGI_CACHE_KV.get(cacheKey);
  if (cached) return cached;
  const now = Math.floor(Date.now() / 1000);
  const token = await signJWT(
    { alg: 'RS256', typ: 'JWT' },
    {
      iss: env.GOOGLE_SERVICE_ACCOUNT_EMAIL,
      scope: 'https://www.googleapis.com/auth/drive.readonly',
      aud: 'https://oauth2.googleapis.com/token',
      exp: now + 3600,
      iat: now,
      sub: subEmail,
    },
    env.GOOGLE_PRIVATE_KEY,
  );
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: token }),
  });
  const data: any = await res.json();
  if (!res.ok) throw new Error(`Google Auth Error: ${data.error_description || data.error}`);
  await env.KAIGI_CACHE_KV.put(cacheKey, data.access_token, { expirationTtl: 3300 });
  return data.access_token;
}

function chunkArray<T>(array: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < array.length; i += size) chunks.push(array.slice(i, i + size));
  return chunks;
}

async function signJWT(header: any, payload: any, privateKey: string): Promise<string> {
  const encoder = new TextEncoder();
  const b64 = (s: string) => btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const data = `${b64(JSON.stringify(header))}.${b64(JSON.stringify(payload))}`;
  const key = await crypto.subtle.importKey('pkcs8', pemToArrayBuffer(privateKey), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, [
    'sign',
  ]);
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, encoder.encode(data));
  return `${data}.${btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')}`;
}

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const rawBase64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\\n/g, '')
    .replace(/\s/g, '');

  const binary = atob(rawBase64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

async function hashString(s: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s.toLowerCase().trim()));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, 16);
}
