# 1time: одноразовые зашифрованные сообщения

Сервис передаёт пароли и другие секреты одноразовыми ссылками. Сообщение
шифруется в браузере, сервер хранит только шифротекст в Redis и удаляет
его при первом чтении или по истечении срока (1, 3, 7 или 30 дней).

Форк [shingrus/1time](https://github.com/shingrus/1time), используется на
onetime.j0ker.site.

## Как устроено

| Компонент | Технологии | Где работает |
|---|---|---|
| Фронтенд | React 19, Vite 8, Bootstrap 5, Web Crypto | статика в `/var/www/onetime`, отдаёт nginx |
| Бэкенд | Go 1.26 (stdlib crypto), go-redis v9 | `127.0.0.1:8080`, systemd `custom_1time` |
| Хранилище | Redis 7+ | `127.0.0.1:6379`, только в памяти |
| Входная точка | nginx | 443, TLS, заголовки безопасности, rate limit |

1. Браузер генерирует ключ 128 бит (`crypto.getRandomValues`), выводит из
   него через HKDF id сообщения, ключ шифрования и токен доступа (с
   дополнительным секретом: PBKDF2-SHA256, 600 000 итераций), шифрует текст
   AES-256-GCM и отправляет id, шифротекст и токен на `POST /api/saveSecret`.
2. Бэкенд сохраняет запись под этим id с TTL (`SET NX`, существующая запись
   не перезаписывается).
3. Ссылка имеет вид `/v/#<22 символа>`: это только ключ, после `#` он не
   уходит на сервер, id из него выводится заново.
4. При открытии браузер выводит токен из ключа и шлёт `POST /api/get`.
   Бэкенд одним Lua-скриптом сверяет токен, отдаёт запись и удаляет её,
   поэтому параллельные запросы не могут прочитать сообщение дважды.
5. Браузер расшифровывает текст; GCM проверяет целостность, изменённое
   сообщение не расшифруется.

Формат v3 подробно описан в [api.md](frontend/public/api.md) и реализован
дважды: `internal/otcrypto` (Go) и `frontend/src/lib/cryptoV2.js` (Web
Crypto). Обе реализации и независимый расчёт на Python дают одинаковые
тестовые векторы.

API для скриптов: [frontend/public/api.md](frontend/public/api.md).

## Сборка

Нужны Go 1.26 (официальный архив с https://go.dev/dl/, пакет Debian
старее) и Node.js 22.22+ (LTS 22 или 24).

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

## Формат v3 (короткие ссылки)

- Ссылка сократилась с `/v/#v2.<43 символа>.<32 hex>` до `/v/#<22 символа>`:
  в ней только ключ на 128 бит, id сообщения клиент выводит из ключа через
  HKDF и сам передаёт серверу.
- Криптография та же, что в v2 (HKDF-SHA256, PBKDF2 600 000, AES-256-GCM),
  со своими info-строками, AAD и префиксом `v3:`.
- 128 бит ключа достаточно: перебор по дампу БД (id или токен) нереален.
- Ссылки v2 продолжают открываться.
- Форма отправляется по `Cmd+Enter` (macOS) и `Ctrl+Enter` (Windows, Linux).

## Формат v2 (шифрование)

- AES-CBC с MD5 EVP_BytesToKey (CryptoJS, без MAC) заменён на AES-256-GCM
  через Web Crypto: шифротекст аутентифицирован.
- Ключ ссылки 256 бит; ключ шифрования и токен доступа выводятся из него
  HKDF-SHA256 независимо, токен ничего не говорит о ключе.
- Дополнительный секрет проходит PBKDF2-HMAC-SHA256 с 600 000 итераций
  (вместо одной итерации MD5).
- `/api/unsecSave`, где сервер видел открытый текст, выключен в бэкенде
  (`ENABLE_UNSEC_SAVE=0`) и закрыт в nginx. Для скриптов есть
  `1time send` / `1time read` с шифрованием на клиенте.
- Бэкенд больше не зависит от go-openssl и golang.org/x/crypto.
- Ссылки старого формата (`/v/#<12 символов><id>`) открываются до истечения
  их срока (не больше 30 дней): код для них (`frontend/src/lib/legacy.js`,
  crypto-js) загружается только при открытии такой ссылки. Через 30 дней
  после выкладки v2 его можно удалить.
