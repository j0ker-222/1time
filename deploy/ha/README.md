# 1time: два узла приложения, два балансировщика, общий vIP

Схема для работы onetime на нескольких серверах. Пользователи ходят только
на виртуальный IP (vIP), балансировщик равномерно раскидывает запросы по
двум серверам приложения, а сообщения лежат в общей базе PostgreSQL.
Поэтому ссылку, созданную через один сервер, можно открыть через другой,
и любой сервер можно остановить без потери ссылок.

```
                 пользователи
                      │  https://onetime.j0ker.site  (A-запись = vIP 203.0.113.10)
          ┌───────────┴───────────┐
          │      vIP (VRRP)       │   keepalived: vIP живёт на одном LB,
   ┌──────┴──────┐         ┌──────┴──────┐  при отказе переезжает за ~3 с
   │ lb1         │         │ lb2         │
   │ nginx + TLS │         │ nginx + TLS │   статика фронтенда, rate limit
   │ 10.10.0.11  │         │ 10.10.0.12  │
   └──────┬──────┘         └──────┬──────┘
          │   round robin, 50/50  │
   ┌──────┴──────────────┬────────┴──────┐
   │ app1  10.10.0.21    │ app2 10.10.0.22│
   │ custom_1time :8080  │ custom_1time   │   STORE=postgres
   │ PostgreSQL primary ═══► standby      │   синхронная репликация
   └─────────────────────┴───────────────┘
```

Адреса в файлах условные (`203.0.113.10` для vIP, сеть `10.10.0.0/24`
для внутреннего сегмента), их надо заменить на свои.

## Что в каталоге

| Файл | Куда | Узлы |
|---|---|---|
| `keepalived/keepalived-lb1.conf`, `keepalived-lb2.conf` | `/etc/keepalived/keepalived.conf` | lb1, lb2 |
| `keepalived/check_nginx.sh` | `/etc/keepalived/check_nginx.sh` | lb1, lb2 |
| `sysctl/99-onetime-lb.conf` | `/etc/sysctl.d/` | lb1, lb2 |
| `nginx/onetime-lb.conf` | `/etc/nginx/sites-enabled/1time.conf` | lb1, lb2 |
| `certs/sync-certs.sh` | `/etc/letsencrypt/renewal-hooks/deploy/` | lb1, lb2 |
| `certs/certbot-only-on-vip.conf` | `/etc/systemd/system/certbot.service.d/` | lb1, lb2 |
| `app/custom_1time.env` | `/etc/custom_1time/env` | app1, app2 |
| `app/custom_1time.service.d/ha.conf` | `/etc/systemd/system/custom_1time.service.d/` | app1, app2 |
| `postgresql/onetime.conf` | `/etc/postgresql/<ver>/main/conf.d/` | app1, app2 |
| `postgresql/pg_hba.conf.snippet` | дописать в `pg_hba.conf` | app1, app2 |
| `postgresql/init-standby.sh` | запуск на реплике | app2 (или app1 при возврате) |
| `postgresql/schema.sql` | если `DB_MIGRATE=false` | primary |

## Как это работает

**vIP.** keepalived на lb1 и lb2 обменивается VRRP (unicast, мультикаст не
нужен). vIP держит узел с бо́льшим приоритетом (lb1). Скрипт
`check_nginx.sh` раз в 2 с проверяет nginx; две неудачи подряд переводят
узел в FAULT, и vIP уходит на соседа. `nopreempt`: когда lb1 вернётся,
vIP останется на lb2, лишнего переключения не будет.

**Балансировка.** В `upstream` оба сервера приложения с одинаковым весом,
nginx чередует их по кругу. Если сервер не принимает соединение или не
отвечает, nginx на 10 с исключает его и отправляет запрос на другой.
POST, который уже дошёл до бэкенда, nginx повторно не отправляет, так что
одно сообщение не может быть прочитано дважды. Какой сервер ответил,
видно в заголовке: `curl -sD - https://onetime.j0ker.site/api/health | grep X-Upstream`.

**Данные.** Оба сервера приложения работают с одной базой. В
`DATABASE_URL` перечислены оба узла PostgreSQL и стоит
`target_session_attrs=read-write`: новое соединение всегда идёт на
текущий primary, поэтому после переключения базы приложение само находит
новый primary без рестарта. Чтение сообщения сделано одним
`DELETE ... RETURNING`: даже при одновременных запросах на разные серверы
сообщение отдаётся ровно один раз. Время жизни считается по часам базы,
расхождение часов на серверах не мешает. Просроченные строки удаляются
фоном раз в `CLEANUP_INTERVAL`.

**Репликация.** app1 primary, app2 hot standby. Репликация синхронная:
ссылка возвращается пользователю только после того, как запись есть на
реплике. Поэтому при отказе primary и повышении реплики ни одна выданная
ссылка не теряется.

## Требования

- lb1 и lb2 в одном L2-сегменте, и хостинг разрешает перемещаемый IP
  (VRRP и gratuitous ARP). На многих VPS это отдельная услуга «плавающий
  IP»; если хостер переносит IP только через свой API, вызов API кладётся
  в `notify_master` keepalived.
- Внутренняя сеть между всеми четырьмя серверами (порты 8080 и 5432
  наружу не открывать).
- Debian 12/13: `nginx`, `keepalived`, `postgresql`, `rsync`, `curl`.

## Установка

### 1. PostgreSQL на app1 и app2

На обоих узлах:

```shell
apt install postgresql
PGVER=$(ls /usr/lib/postgresql | sort -n | tail -1)
install -m 644 deploy/ha/postgresql/onetime.conf /etc/postgresql/$PGVER/main/conf.d/onetime.conf
# на app2 поправить listen_addresses и cluster_name (см. комментарии в файле)
cat deploy/ha/postgresql/pg_hba.conf.snippet >> /etc/postgresql/$PGVER/main/pg_hba.conf
```

На app1 (primary). Пока реплики нет, синхронную репликацию надо временно
выключить, иначе запись будет ждать реплику:

```shell
systemctl restart postgresql
sudo -u postgres psql <<'SQL'
ALTER SYSTEM SET synchronous_standby_names = '';
SELECT pg_reload_conf();
CREATE ROLE replicator LOGIN REPLICATION PASSWORD 'REPL_SECRET';
CREATE ROLE onetime LOGIN PASSWORD 'APP_SECRET';
CREATE DATABASE onetime OWNER onetime;
SQL
```

На app2 (реплика). В `~postgres/.pgpass` (chmod 600) пароль replicator
для обоих адресов, затем:

```shell
deploy/ha/postgresql/init-standby.sh 10.10.0.21 app2
```

Снова на app1, включить синхронную репликацию и проверить:

```shell
sudo -u postgres psql -c "ALTER SYSTEM RESET synchronous_standby_names" -c "SELECT pg_reload_conf()"
sudo -u postgres psql -Atc "SELECT application_name, sync_state FROM pg_stat_replication"
# app2|quorum
```

### 2. Приложение на app1 и app2

Бинарник и unit как в основном README, плюс:

```shell
install -m 600 deploy/ha/app/custom_1time.env /etc/custom_1time/env      # пароль, LISTEN_ADDR узла
install -d /etc/systemd/system/custom_1time.service.d
install -m 644 deploy/ha/app/custom_1time.service.d/ha.conf /etc/systemd/system/custom_1time.service.d/
systemctl daemon-reload && systemctl enable --now custom_1time
curl -s http://10.10.0.21:8080/api/health        # {"status":"ok"}
```

Таблица создаётся при первом старте (`DB_MIGRATE=true`). Redis на этих
узлах не нужен.

### 3. Балансировщики lb1 и lb2

```shell
apt install nginx keepalived rsync curl
install -m 644 deploy/ha/sysctl/99-onetime-lb.conf /etc/sysctl.d/ && sysctl --system
install -m 755 deploy/ha/keepalived/check_nginx.sh /etc/keepalived/
install -m 644 deploy/ha/keepalived/keepalived-lb1.conf /etc/keepalived/keepalived.conf   # на lb2: keepalived-lb2.conf
rm -rf /var/www/onetime && cp -r frontend/build /var/www/onetime
sed 's/HOSTNAME/onetime.j0ker.site/g' deploy/ha/nginx/onetime-lb.conf > /etc/nginx/sites-enabled/1time.conf
nginx -t && systemctl reload nginx
systemctl enable --now keepalived
ip -4 addr show | grep 203.0.113.10      # vIP должен быть ровно на одном узле
```

В `keepalived.conf` поменять интерфейс, адреса и `auth_pass` (до 8
символов, одинаковый на обоих). `ip_nonlocal_bind` нужен, чтобы nginx на
резервном узле мог слушать vIP, которого у него пока нет.

### 4. Сертификат

Проверка HTTP-01 приходит на vIP, поэтому выпускать и продлевать
сертификат может только узел, у которого сейчас vIP. Выпустить на нём
`certbot --nginx -d onetime.j0ker.site`, затем на обоих LB:

```shell
install -m 755 deploy/ha/certs/sync-certs.sh /etc/letsencrypt/renewal-hooks/deploy/
install -d /etc/systemd/system/certbot.service.d
install -m 644 deploy/ha/certs/certbot-only-on-vip.conf /etc/systemd/system/certbot.service.d/
systemctl daemon-reload
/etc/letsencrypt/renewal-hooks/deploy/sync-certs.sh     # первая копия на соседа
```

Root каждого LB должен ходить на соседа по ssh-ключу. Вариант без
синхронизации: DNS-01 challenge на обоих узлах.

## Переезд с текущего сервера без потери ссылок

Сейчас сообщения лежат в Redis на одном сервере. Команда
`1time migrate-redis` копирует их в PostgreSQL с теми же id и оставшимся
временем жизни; старые ссылки продолжают открываться.

1. Развернуть схему выше, DNS пока смотрит на старый сервер.
2. На старом сервере остановить приём запросов, чтобы во время копирования
   никто не прочитал сообщение из Redis (иначе оно останется в PostgreSQL):
   `systemctl stop custom_1time`.
3. Скопировать, запуск со старого сервера (нужен доступ к 5432 primary):

   ```shell
   REDISHOST=127.0.0.1:6379 REDISPASS=... \
   DATABASE_URL='postgres://onetime:APP_SECRET@10.10.0.21:5432,10.10.0.22:5432/onetime?target_session_attrs=read-write' \
   /usr/local/bin/go_onetime/1time migrate-redis
   # migrate-redis scanned=N copied=N already_in_postgres=0 skipped=0
   ```

   Команду можно повторять: уже скопированные записи не трогаются.
4. Переключить A-запись onetime.j0ker.site на vIP (TTL записи заранее
   уменьшить до 60 с). Пока DNS не обновился у всех, старый сервер можно
   перевести на `STORE=postgres` с тем же `DATABASE_URL` (и drop-in
   `ha.conf`, чтобы unit пускал к базе), тогда обе точки
   входа работают с одной базой.

Простой для пользователей: время шагов 2 и 3 (секунды).

## Эксплуатация

**Обслуживание сервера приложения** (обновление, перезагрузка):
`systemctl stop custom_1time` на нём. Текущие запросы доработают
(graceful shutdown до 10 с), новые nginx отправит на второй сервер.
Чтобы совсем без ошибок соединения, можно заранее пометить сервер `down`
в `upstream` и сделать `nginx -s reload` на обоих LB.

**Обслуживание балансировщика:** `systemctl stop keepalived` (или nginx)
на нём, vIP уйдёт на соседа за 2–3 с. Открытые в этот момент соединения
оборвутся, браузер переподключится.

**Плановое переключение базы** (обслуживание app1 с primary):

```shell
# app1: остановить primary
systemctl stop postgresql
# app2: повысить реплику
sudo -u postgres psql -c "SELECT pg_promote()"
# пока app1 без реплики, синхронную репликацию отключить, иначе запись встанет
sudo -u postgres psql -c "ALTER SYSTEM SET synchronous_standby_names = ''" -c "SELECT pg_reload_conf()"
```

Приложение на обоих узлах переподключится к app2 само. Вернуть app1
репликой: `deploy/ha/postgresql/init-standby.sh 10.10.0.22 app1`
(или `pg_rewind`, `wal_log_hints` для этого включён), затем на app2
`ALTER SYSTEM RESET synchronous_standby_names`.

**Авария primary:** те же команды на реплике. Ссылки не теряются,
потому что репликация синхронная.

**Авария реплики:** запись на primary ждёт реплику, создание ссылок
зависнет. Снять ожидание: на primary
`ALTER SYSTEM SET synchronous_standby_names = ''; SELECT pg_reload_conf();`.
Когда реплика вернётся, `ALTER SYSTEM RESET synchronous_standby_names`.

## Ограничения и что дальше

- Переключение PostgreSQL ручное (одна команда). Для автоматического
  нужен Patroni с etcd на трёх узлах (например app1, app2 и lb1): он сам
  повышает реплику и снимает синхронность при отказе реплики. Приложение
  менять не придётся, `DATABASE_URL` с двумя хостами уже подходит.
- Rate limit nginx считается на каждом LB отдельно; так как трафик идёт
  через один активный LB, поведение такое же, как на одном сервере.
- Статику фронтенда надо выкладывать на оба LB одинаково.

## Проверено

Стенд: lb1 и lb2 в отдельных сетевых namespace с keepalived и nginx из
этих конфигов (TLS заменён на :80), два экземпляра приложения, PostgreSQL
16 primary + синхронная реплика. Результат 18 из 18:

- vIP поднимается на lb1, 8 запросов делятся 4/4 между app1 и app2;
- 40 ссылок, 20 созданы через app1 и 20 через app2;
- ссылка открывается один раз, неверный ключ не удаляет сообщение;
- остановка app1: ссылки открываются через app2, ни одного 5xx;
- падение nginx на lb1: vIP переезжает на lb2, ссылки открываются,
  чтения снова делятся между app1 и app2; после возврата lb1 vIP остаётся
  на lb2;
- primary PostgreSQL убит (`immediate`), реплика повышена: все 19
  оставшихся ссылок открываются, прочитанные остаются прочитанными, новые
  ссылки создаются.
