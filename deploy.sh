git pull
docker rm -f pentora-api
# -p 80:8080 yerine -p 127.0.0.1:80:8080 yapıyoruz
docker run -d --name pentora-api --env-file .env -p 127.0.0.1:80:8080 pentora-backend
echo DEPLOY BAŞARILI!
echo Loglar Açıldı!
docker logs -f pentora-api