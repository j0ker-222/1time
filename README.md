# 1time messaging service  

## Requirements

apt install npm golang-go git nginx redis-server

## Install  
### Debian/Ubuntu

cd 1time  
mv configs/systemd/custom_1time.service /usr/lib/systemd/system/custom_onetime.service
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
  
systemctl enable --now custom_onetime.service  
