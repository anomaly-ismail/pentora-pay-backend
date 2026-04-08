git pull
docker stop pentora-api
docker rm pentora-api
docker build -t pentora-backend .
docker run -d --name pentora-api --env-file .env -p 127.0.0.1:80:8080 pentora-backend
echo DEPLOY BAŞARILI!
echo Loglar Açıldı!
docker logs -f pentora-api