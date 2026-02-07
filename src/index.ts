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
}

type ConferenceConfig = Record<
  string,
  {
    folderId: string;
    token: string;
    sub: string; // サービスアカウントの委任先メールアドレス
  }
>;

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

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

        if (body.event && body.event.type === 'app_mention') {
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
} satisfies ExportedHandler<Env>;

async function handleAiResponse(env: Env, event: any, config: ConferenceConfig[string], question: string) {
  const startTime = Date.now();

  const debug = (msg: string) => {
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`[${elapsed}s] ${msg}`);
  };

  try {
    debug('🔐 Google 認証開始');
    const gToken = await getGoogleWorkspaceAccessToken(env, config.sub);
    debug('✅ Google 認証完了');

	const docCacheKey = `docs:${config.folderId}`;
    let docsData = await env.KAIGI_CACHE_KV.get(docCacheKey, { type: 'json' }) as { context: string, fileNames: string[] } | null;

	debug('📂 資料検索開始');
    if (!docsData) {
      debug('🆕 キャッシュがないため Google Drive から取得します');
      docsData = await fetchAllDocsContentInFolder(config.folderId, gToken);
      // 30 分間キャッシュ (頻繁に更新されるなら短めに)
      await env.KAIGI_CACHE_KV.put(docCacheKey, JSON.stringify(docsData), { expirationTtl: 1800 });
    } else {
      debug('⚡ カンファレンス個別のキャッシュから資料を読み込みました');
    }
    const { context, fileNames } = docsData;
    debug(`✅ 資料取得完了 (${context.length} 文字, ${fileNames.length} ファイル)`);

    if (context.length < 100) {
      await postToSlack(event.channel, `<@${event.user}> 資料が見つかりませんでした。フォルダIDを確認してください。`, config.token);
      return;
    }

    debug('🤖 Gemini で回答生成中...');
    const answer = await askGemini(env, question, context, fileNames);
    debug('✅ 回答生成完了');

    debug('📨 Slack へ投稿中...');
    await postToSlack(event.channel, `<@${event.user}>\n\n${answer}`, config.token);
    debug('🎉 全工程完了！');
  } catch (error: any) {
    console.error('❌ Error:', error);
    const errorMsg = error.message || 'Unknown error';
    await postToSlack(event.channel, `<@${event.user}> エラーが発生しました: ${errorMsg}`, config.token);
  }
}

async function getGoogleWorkspaceAccessToken(env: Env, subEmail: string): Promise<string> {
  const cacheKey = `gtoken:${subEmail}`;
  const cachedToken = await env.KAIGI_CACHE_KV.get(cacheKey);
  if (cachedToken) return cachedToken;

  const now = Math.floor(Date.now() / 1000);
  const expiry = now + 3600;

  const header = { alg: 'RS256', typ: 'JWT' };
  const claim = {
    iss: env.GOOGLE_SERVICE_ACCOUNT_EMAIL,
    scope: 'https://www.googleapis.com/auth/drive.readonly',
    aud: 'https://oauth2.googleapis.com/token',
    exp: expiry,
    iat: now,
    sub: subEmail, // チームごとに設定された委任先メールアドレス
  };

  try {
    const token = await signJWT(header, claim, env.GOOGLE_PRIVATE_KEY);

    const response = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: token,
      }),
    });

    const data: any = await response.json();
    if (!response.ok) {
      console.error('Google Auth Error:', JSON.stringify(data));
      throw new Error(`Google Auth Error: ${data.error_description || data.error}`);
    }
    await env.KAIGI_CACHE_KV.put(cacheKey, data.access_token, { expirationTtl: 3300 });
    return data.access_token;
  } catch (e: any) {
    console.error('Auth Exception:', e.message);
    throw e;
  }
}

async function fetchAllDocsContentInFolder(folderId: string, accessToken: string): Promise<{ context: string; fileNames: string[] }> {
  // ファイル一覧取得（最大 10 件、最新順）
  const listUrl =
    `https://www.googleapis.com/drive/v3/files?` +
    `q=${encodeURIComponent(`'${folderId}' in parents and trashed = false`)}` +
    `&fields=files(id,name,mimeType,modifiedTime)` +
    `&orderBy=modifiedTime desc` +
    `&pageSize=10` +
    `&supportsAllDrives=true` +
    `&includeItemsFromAllDrives=true`;

  const listRes = await fetch(listUrl, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!listRes.ok) {
    throw new Error(`Drive API Error: ${listRes.status} ${await listRes.text()}`);
  }

  const listData: any = await listRes.json();
  const items = listData.files || [];

  let allContent = '';
  const fileNames: string[] = [];
  const maxContentLength = 50000;

  for (const item of items) {
    if (allContent.length > maxContentLength) break;

    if (item.mimeType === 'application/vnd.google-apps.document') {
      const text = await exportDocText(item.id, accessToken);
      if (text) {
        allContent += `\n\n=== ${item.name} ===\n${text}`;
        fileNames.push(item.name);
      }
    } else if (item.mimeType === 'application/vnd.google-apps.spreadsheet') {
      const text = await exportSheetText(item.id, accessToken);
      if (text) {
        allContent += `\n\n=== ${item.name} (Google Sheets) ===\n${text}`;
        fileNames.push(item.name);
      }
    } else if (item.mimeType === 'application/vnd.google-apps.folder') {
      // サブフォルダ内のドキュメントも取得（最大 3 件）
      const subUrl =
        `https://www.googleapis.com/drive/v3/files?` +
        `q=${encodeURIComponent(`'${item.id}' in parents and mimeType = 'application/vnd.google-apps.document' and trashed = false`)}` +
        `&fields=files(id,name)` +
        `&pageSize=3` +
        `&supportsAllDrives=true` +
        `&includeItemsFromAllDrives=true`;

      const subRes = await fetch(subUrl, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });

      if (subRes.ok) {
        const subData: any = await subRes.json();
        const subFiles = subData.files || [];

        for (const subFile of subFiles) {
          if (allContent.length > maxContentLength) break;

          const text = await exportDocText(subFile.id, accessToken);
          if (text) {
            allContent += `\n\n=== ${item.name}/${subFile.name} ===\n${text}`;
            fileNames.push(`${item.name}/${subFile.name}`);
          }
        }
      }
    }
  }

  return {
    context: allContent || '資料が見つかりませんでした。',
    fileNames,
  };
}

async function exportDocText(fileId: string, accessToken: string): Promise<string> {
  const exportUrl = `https://www.googleapis.com/drive/v3/files/${fileId}/export?mimeType=text/plain`;

  try {
    const res = await fetch(exportUrl, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (res.ok) {
      const text = await res.text();
      return text.trim();
    } else {
      console.error(`Export failed for ${fileId}: ${res.status}`);
      return '';
    }
  } catch (e) {
    console.error(`Export exception for ${fileId}:`, e);
    return '';
  }
}

async function exportSheetText(fileId: string, accessToken: string): Promise<string> {
  const exportUrl = `https://www.googleapis.com/drive/v3/files/${fileId}/export?mimeType=text/csv`;

  try {
    const res = await fetch(exportUrl, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (res.ok) {
      const csvText = await res.text();
      const lines = csvText.trim().split('\n');
      const formattedLines = lines.map((line, index) => {
        if (index === 0) {
          return `[ヘッダー] ${line}`;
        }
        return line;
      });
      return formattedLines.join('\n');
    } else {
      console.error(`Sheet export failed for ${fileId}: ${res.status}`);
      return '';
    }
  } catch (e) {
    console.error(`Sheet export exception for ${fileId}:`, e);
    return '';
  }
}

async function askGemini(env: Env, question: string, context: string, fileNames: string[]): Promise<string> {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key=${env.GEMINI_API_KEY}`;

  const prompt = `あなたはカンファレンス運営を支援する優秀なアシスタントです。

以下の【運営議事録・資料】に基づいて、運営スタッフからの【質問】に正確かつ簡潔に答えてください。

【回答の指針】
- 資料に記載されている情報のみを使用してください
- 資料にない情報は推測せず、「資料には記載がありません」と答えてください  
- 可能な限り具体的な情報（日付、担当者、金額など）を含めてください
- 必要に応じて、どの資料に記載があったかを明記してください
- 簡潔に、要点を絞って回答してください（箇条書き推奨）

【参照可能な資料】
${fileNames.map((name, i) => `${i + 1}. ${name}`).join('\n')}

【運営議事録・資料】
${context}

---

【質問】
${question}`;

  try {
    const response = await fetch(url, {
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

    if (!response.ok) {
      const errorText = await response.text();
      console.error('Gemini API Error:', errorText);
      throw new Error(`Gemini API Error: ${response.status}`);
    }

    const data: any = await response.json();
    return data.candidates?.[0]?.content?.parts?.[0]?.text || '回答を生成できませんでした。';
  } catch (e: any) {
    console.error('Gemini Exception:', e);
    throw new Error(`AI回答生成エラー: ${e.message}`);
  }
}

async function postToSlack(channel: string, text: string, slackToken: string) {
  try {
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
      console.error('Slack API Error:', result.error);
      throw new Error(`Slack Post Error: ${result.error}`);
    }
  } catch (e: any) {
    console.error('Slack Post Exception:', e);
    throw e;
  }
}

async function signJWT(header: any, payload: any, privateKey: string): Promise<string> {
  const encoder = new TextEncoder();
  const headerB64 = btoa(JSON.stringify(header)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const payloadB64 = btoa(JSON.stringify(payload)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const data = `${headerB64}.${payloadB64}`;

  const key = await crypto.subtle.importKey('pkcs8', pemToArrayBuffer(privateKey), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, [
    'sign',
  ]);

  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, encoder.encode(data));

  const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  return `${data}.${signatureB64}`;
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
