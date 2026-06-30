#!/bin/bash
TEAM=$1
SECRET="your-secret-here"
URL="https://kaigi-support.nekohack.me/cron/update-cache"

for offset in 0 5 10 15 20 25; do
  echo "Embedding offset=$offset..."
  curl -s -X POST "$URL?phase=embed&team=$TEAM&offset=$offset" \
    -H "Authorization: Bearer $SECRET"
  echo ""
  sleep 20
done
echo "Done!"
