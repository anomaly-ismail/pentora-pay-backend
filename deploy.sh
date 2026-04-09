#!/bin/bash
set -e

git pull
docker stop pentora-api 2>/dev/null || true
docker rm pentora-api 2>/dev/null || true
docker build -t pentora-backend .

# DB'yi mevcut head'e stamp'la (tablolar var ama alembic_version eksikse düzeltir)
# Idempotent: zaten stamp'lıysa hata vermez
echo "Alembic stamp çalıştırılıyor..."
docker run --rm --env-file .env pentora-backend \
    python -c "
from alembic.config import Config
from alembic import command
cfg = Config('alembic.ini')
command.stamp(cfg, 'head')
print('Stamp OK')
"

docker run -d --name pentora-api --env-file .env -p 127.0.0.1:80:8080 pentora-backend
echo "DEPLOY BAŞARILI!"
echo "Loglar Açıldı!"
docker logs -f pentora-api
