git pull
docker rm -f pentora-api
docker run -d --name pentora-api --env-file .env -p 80:8080 pentora-backend
echo DEPLOY BAŞARILI!