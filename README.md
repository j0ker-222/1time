# 1time: одноразовые зашифрованные сообщения

Сервис передаёт пароли и другие секреты одноразовыми ссылками. Сообщение
шифруется в браузере, сервер хранит только шифротекст (в Redis или
PostgreSQL) и удаляет его при первом чтении или по истечении срока
(1, 3, 7 или 30 дней).

Форк [shingrus/1time](https://github.com/shingrus/1time), используется на
onetime.j0ker.site.

## Как устроено

| Компонент | Технологии | Где работает |
|---|---|---|
| Фронтенд | React 19, Vite 8, Bootstrap 5, crypto-js 4.2 | статика в `/var/www/onetime`, отдаёт nginx |
| Бэкенд | Go 1.26, go-redis v9, pgx v5, go-openssl v4 | `127.0.0.1:8080`, systemd `custom_1time` |
| Хранилище | Redis 7+ (`STORE=redis`, по умолчанию) или PostgreSQL 13+ (`STORE=postgres`) | Redis: `127.0.0.1:6379`, только в памяти |
| Входная точка | nginx | 443, TLS, заголовки безопасности, rate limit |

1. Браузер генерирует ключ из 12 символов (`crypto.getRandomValues`),
   шифрует текст (AES-256, формат OpenSSL) и отправляет шифротекст и
   SHA-256 ключа на `POST /api/saveSecret`.
2. Бэкенд сохраняет запись под случайным 128-битным id с TTL.
3. Ссылка имеет вид `/v/#<ключ><id>`: ключ после `#` не уходит на сервер.
4. При открытии браузер шлёт `POST /api/get` с id и хэшем ключа. Бэкенд
   одним Lua-скриптом сверяет хэш, отдаёт запись и удаляет её, поэтому
   параллельные запросы не могут прочитать сообщение дважды.

API для скриптов: [frontend/public/api.md](frontend/public/api.md).

## Сборка

Нужны Go 1.26 (официальный архив с https://go.dev/dl/, пакет Debian
старее) и Node.js 20.19+ или 22.

```shell
make test        # go vet + go test, vitest
make build       # bin/1time
make frontend    # frontend/build
make vulncheck   # govulncheck + npm audit
```

Готовые `1time-linux-amd64` и `frontend-build` также собирает GitHub
Actions (вкладка Actions, артефакты последнего запуска).

Для разработки: `redis-server`, затем `go run .` и `cd frontend && npm run dev`
(Vite проксирует `/api` на `:8080`).

## Установка (Debian)

```shell
apt install nginx redis-server

# Redis
cp configs/redis/1time.conf /etc/redis/1time.conf
PASS=$(openssl rand -hex 32)
sed -i "s/CHANGE_ME_TO_A_LONG_RANDOM_VALUE/$PASS/" /etc/redis/1time.conf
echo 'include /etc/redis/1time.conf' >> /etc/redis/redis.conf
systemctl restart redis-server

# Бэкенд
install -d -m 755 /usr/local/bin/go_onetime /etc/custom_1time
install -m 755 bin/1time /usr/local/bin/go_onetime/1time
install -m 600 configs/systemd/custom_1time.env /etc/custom_1time/env
sed -i "s/CHANGE_ME_TO_A_LONG_RANDOM_VALUE/$PASS/" /etc/custom_1time/env
install -m 644 configs/systemd/custom_1time.service /etc/systemd/system/custom_1time.service
systemctl daemon-reload
systemctl enable --now custom_1time
curl -s http://127.0.0.1:8080/api/health   # {"status":"ok"}

# Фронтенд
rm -rf /var/www/onetime && cp -r frontend/build /var/www/onetime

# nginx (HOSTNAME заменить на имя сайта, сертификат через certbot)
sed 's/HOSTNAME/onetime.j0ker.site/g' configs/nginx/1time.conf > /etc/nginx/sites-enabled/1time.conf
nginx -t && systemctl reload nginx
```

## PostgreSQL и несколько серверов

С `STORE=postgres` сообщения хранятся в PostgreSQL, и несколько копий
бэкенда работают с одной базой: ссылка, созданная через один сервер,
открывается через любой другой. Готовая схема с двумя балансировщиками
на общем vIP (keepalived + nginx), двумя серверами приложения и
синхронной репликацией PostgreSQL, а также порядок переезда с Redis
без потери ссылок: [deploy/ha/README.md](deploy/ha/README.md).

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `STORE` | `redis` | `redis` или `postgres` |
| `DATABASE_URL` | | строка подключения, можно несколько хостов и `target_session_attrs=read-write` |
| `PG_MAX_CONNS` | `10` | размер пула соединений |
| `DB_MIGRATE` | `true` | создавать таблицу при старте |
| `CLEANUP_INTERVAL` | `10m` | как часто удалять просроченные сообщения (`0` выключает) |

`1time migrate-redis` копирует сообщения из Redis (`REDISHOST`,
`REDISPASS`, `REDISDB`) в PostgreSQL (`DATABASE_URL`) с теми же id и
оставшимся сроком жизни. Повторный запуск безопасен.

Тесты PostgreSQL запускаются, если задан `TEST_PG_DSN`:

```shell
TEST_PG_DSN='postgres://postgres@127.0.0.1:5432/onetime_test?sslmode=disable' make test-go
```

## Обновление со старой версии

Формат хранения и шифрования не изменился: ссылки, созданные до
обновления, продолжают открываться.

1. Собрать новую версию (`make build frontend`).
2. Настроить Redis и `/etc/custom_1time/env` как в разделе «Установка».
   После рестарта Redis загрузит старый `dump.rdb` в память; больше он
   на диск не пишет. Файл со старыми шифротекстами можно удалить:
   `rm /var/lib/redis/dump.rdb`.
3. Заменить бинарник и unit, `systemctl daemon-reload && systemctl restart custom_1time`.
   Старый unit (`User=www-data`, без `EnvironmentFile`) больше не нужен.
4. Заменить содержимое `/var/www/onetime` новой сборкой и конфиг nginx.
   Старый service worker в браузерах пользователей удалит себя сам.
5. Старая версия писала шифротексты и хэши ключей в journald. Очистить:
   `journalctl --rotate && journalctl --vacuum-time=1s` (затрагивает весь журнал).

## Что изменилось в версии 2

- Чтение и удаление сообщения атомарны (раньше одну ссылку можно было
  прочитать несколько раз параллельными запросами).
- Ключи и id генерируются криптостойко (`crypto.getRandomValues`,
  `crypto/rand`); id 128-битные случайные вместо счётчика.
- Секреты, шифротексты и хэши больше не пишутся в логи.
- API принимает только `application/json`, ограничивает размер тела,
  проверяет формат id и хэша, у HTTP-сервера есть таймауты и graceful shutdown.
- Один пул соединений с Redis вместо нового клиента на каждый запрос;
  поддержка пароля Redis и unix-сокета.
- Удалены старые серверные страницы `/saveSecret`, `/view/` и шаблоны.
- Фронтенд переписан на React 19 + Vite, Bootstrap подключён локально
  (без CDN), axios заменён на `fetch`; `npm audit`: 0 уязвимостей.
- nginx: HSTS, CSP, X-Frame-Options, Referrer-Policy, rate limit,
  лимит тела; Redis без записи на диск и с лимитом памяти; systemd с
  `DynamicUser` и песочницей.
- Тесты бэкенда и фронтенда, CI с govulncheck и npm audit.

Шифрование осталось AES-CBC с MD5-KDF (формат CryptoJS) ради
совместимости со старыми ссылками; переход на AES-GCM через Web Crypto
запланирован отдельным шагом.
