# 1time messaging service  
  
cd 1time-master  
mv configs/systemd/custom_1time.service /usr/lib/systemd/system/  
systemctl daemon-reload  
mv ./configs/nginx/1time.conf /etc/nginx/sites-enabled/1time.conf  
mv ./configs/redis/redis.conf /etc/redis/redis.conf  
systemctl restart nginx  
systemctl restart redis  
  
make build  
mv ./bin /usr/local/bin/go_onetime  
  
cd frontend   
npm install  
npm audit fix  
npm run build  
mv ./build /var/www/onetime  
  
