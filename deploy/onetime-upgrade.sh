#!/usr/bin/env bash
# onetime-upgrade.sh: обновление onetime.j0ker.site (j0ker-222/1time) до
# версии без известных CVE на Debian-сервере. Запускать от root.
#
# Что делает:
#   1. находит текущую установку (unit, бинарник, webroot, сайт nginx);
#   2. делает резервную копию всего, что меняет;
#   3. ставит Go 1.26 и Node.js 22 в /opt/custom_1time-build (системные
#      пакеты не трогает), если подходящих версий нет в системе;
#   4. скачивает код с GitHub и собирает его от пользователя nobody,
#      прогоняет go vet, go test, тесты фронтенда и npm audit;
#   5. поднимает отдельный Redis custom_1time-redis (пароль, без записи на
#      диск, 256 МБ) и копирует в него текущие сообщения с их TTL;
#      общий Redis сервера не перенастраивается;
#   6. ставит бинарник, unit с песочницей, фронтенд и новый конфиг nginx
#      (server_name, listen и сертификаты берутся из текущего конфига);
#   7. проверяет /api/health и создание/чтение сообщения, при любой ошибке
#      откатывает всё назад;
#   8. после успеха удаляет перенесённые сообщения из общего Redis.
#
# Ветка crypto-v2: шифрование AES-256-GCM (Web Crypto) с HKDF и PBKDF2,
# короткие ссылки (формат v3)
# вместо AES-CBC/MD5, /api/unsecSave выключен в бэкенде и закрыт в nginx.
# Ссылки старого формата продолжают открываться. Повторный запуск поверх
# уже обновлённой версии безопасен: Redis не перезапускается, сообщения
# сохраняются.
#
# Использование:
#   onetime-upgrade.sh [-d домен] [-r ветка] [-u url-репозитория] [-j] [-y]
#   onetime-upgrade.sh -R /var/backups/custom_1time/<дата>    # ручной откат
#
#   -d  домен сайта (по умолчанию onetime.j0ker.site)
#   -r  ветка или тег (по умолчанию crypto-v2)
#   -u  репозиторий (по умолчанию https://github.com/j0ker-222/1time.git)
#   -j  очистить journald от логов старой версии (там шифротексты и хэши
#       ключей); затрагивает весь журнал сервера
#   -y  не спрашивать подтверждение
#   -R  откатить установку из указанной резервной копии

set -Eeuo pipefail
umask 022

DOMAIN="onetime.j0ker.site"
REF="crypto-v2"
REPO="https://github.com/j0ker-222/1time.git"
PURGE_JOURNAL=0
ASSUME_YES=0
ROLLBACK_FROM=""

GO_MIN="1.26"
NODE_MIN="22.22"
NODE_MAJOR="22"

APP_UNIT="custom_1time"
REDIS_UNIT="custom_1time-redis"
APP_DIR="/usr/local/bin/go_onetime"
ETC_DIR="/etc/custom_1time"
REDIS_DATA="/var/lib/custom_1time-redis"
REDIS_PORT="6380"
LISTEN_ADDR="127.0.0.1:8080"
BUILD_ROOT="/opt/custom_1time-build"
BACKUP_ROOT="/var/backups/custom_1time"
SYSTEMD_DIR="/etc/systemd/system"
OLD_REDIS_HOST="127.0.0.1"
OLD_REDIS_PORT="6379"

usage() { sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while getopts ":d:r:u:jyR:h" opt; do
  case "$opt" in
    d) DOMAIN="$OPTARG" ;;
    r) REF="$OPTARG" ;;
    u) REPO="$OPTARG" ;;
    j) PURGE_JOURNAL=1 ;;
    y) ASSUME_YES=1 ;;
    R) ROLLBACK_FROM="$OPTARG" ;;
    h) usage 0 ;;
    *) usage 2 ;;
  esac
done

TS="$(date +%Y%m%d-%H%M%S)"
BACKUP="$BACKUP_ROOT/$TS"
LOG_FILE="$BACKUP_ROOT/upgrade-$TS.log"

c_ok=$'\e[32m'; c_warn=$'\e[33m'; c_err=$'\e[31m'; c_off=$'\e[0m'
[ -t 1 ] || { c_ok=""; c_warn=""; c_err=""; c_off=""; }
log()  { printf '%s[+]%s %s\n' "$c_ok" "$c_off" "$*"; }
warn() { printf '%s[!]%s %s\n' "$c_warn" "$c_off" "$*" >&2; }
# false вместо exit: срабатывает ERR-ловушка, и после начала переключения
# выполняется откат
die()  { printf '%s[x]%s %s\n' "$c_err" "$c_off" "$*" >&2; false; }

# Сравнение версий: ver_ge 1.26.3 1.26 -> истина
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

# Состояние для отката
STAGE="prepare"
OLD_UNIT=""
OLD_UNIT_FILE=""
NGINX_SITE=""
WEBROOT=""
MOVED_IDS_FILE=""

old_redis() {
  if [ -n "${OLD_REDIS_PASS:-}" ]; then
    REDISCLI_AUTH="$OLD_REDIS_PASS" redis-cli -h "$OLD_REDIS_HOST" -p "$OLD_REDIS_PORT" "$@"
  else
    redis-cli -h "$OLD_REDIS_HOST" -p "$OLD_REDIS_PORT" "$@"
  fi
}
new_redis() { REDISCLI_AUTH="$REDIS_PASS" redis-cli -h 127.0.0.1 -p "$REDIS_PORT" "$@"; }

# ---------------------------------------------------------------- откат

restore_from_backup() {
  local b="$1"
  [ -f "$b/manifest" ] || die "в $b нет manifest, это не резервная копия скрипта"
  # shellcheck disable=SC1090,SC1091
  . "$b/manifest"
  warn "Откат из $b"
  systemctl stop "$APP_UNIT" 2>/dev/null || true

  # unit-файлы
  rm -f "$SYSTEMD_DIR/$APP_UNIT.service"
  if [ -n "${M_OLD_UNIT_FILE:-}" ] && [ -f "$b/unit/$(basename "$M_OLD_UNIT_FILE")" ]; then
    cp -a "$b/unit/$(basename "$M_OLD_UNIT_FILE")" "$M_OLD_UNIT_FILE"
  fi
  # бинарник и шаблоны
  if [ -d "$b/app" ]; then
    rm -rf "$APP_DIR"
    cp -a "$b/app" "$APP_DIR"
  fi
  # фронтенд
  if [ -n "${M_WEBROOT:-}" ] && [ -d "$b/webroot" ]; then
    rm -rf "$M_WEBROOT"
    cp -a "$b/webroot" "$M_WEBROOT"
  fi
  # nginx
  if [ -n "${M_NGINX_SITE:-}" ] && [ -f "$b/nginx/site.conf" ]; then
    cp -a "$b/nginx/site.conf" "$M_NGINX_SITE"
  fi
  systemctl daemon-reload
  if [ -n "${M_OLD_UNIT:-}" ]; then
    systemctl enable "$M_OLD_UNIT" >/dev/null 2>&1 || true
    systemctl restart "$M_OLD_UNIT" || warn "не удалось запустить $M_OLD_UNIT"
  fi
  if nginx -t >/dev/null 2>&1; then systemctl reload nginx; else warn "nginx -t не прошёл после отката, проверь вручную"; fi
  # Сообщения в общем Redis не удалялись до успешного завершения, поэтому
  # старая версия видит их как раньше. custom_1time-redis можно остановить.
  systemctl stop "$REDIS_UNIT" 2>/dev/null || true
  systemctl disable "$REDIS_UNIT" >/dev/null 2>&1 || true
  warn "Откат завершён. custom_1time-redis остановлен, его файлы остались: $ETC_DIR, $SYSTEMD_DIR/$REDIS_UNIT.service"
}

on_error() {
  local rc=$? line=${1:-?}
  trap - ERR
  printf '%s[x]%s ошибка (код %s) в строке %s, этап: %s\n' "$c_err" "$c_off" "$rc" "$line" "$STAGE" >&2
  case "$STAGE" in
    prepare|toolchain|build)
      warn "Сервис не менялся, откат не нужен." ;;
    *)
      restore_from_backup "$BACKUP" ;;
  esac
  warn "Лог: $LOG_FILE"
  exit "$rc"
}

[ "$(id -u)" -eq 0 ] || die "запускать от root"

if [ -n "$ROLLBACK_FROM" ]; then
  restore_from_backup "$ROLLBACK_FROM"
  exit 0
fi

mkdir -p "$BACKUP_ROOT"
chmod 700 "$BACKUP_ROOT"
exec > >(tee -a "$LOG_FILE") 2>&1
trap 'on_error $LINENO' ERR

# ---------------------------------------------------------------- 1. поиск

log "Обновление $DOMAIN до $REF ($REPO)"
. /etc/os-release 2>/dev/null || true
log "ОС: ${PRETTY_NAME:-unknown}"

for c in git curl tar xz python3 nginx redis-server redis-cli openssl systemctl sha256sum runuser; do
  command -v "$c" >/dev/null 2>&1 || die "нет команды $c (apt install git curl xz-utils python3 nginx redis-server openssl)"
done

case "$(uname -m)" in
  x86_64) GOARCH=amd64; NODEARCH=x64 ;;
  aarch64) GOARCH=arm64; NODEARCH=arm64 ;;
  *) die "архитектура $(uname -m) не поддерживается" ;;
esac

for u in custom_1time custom_onetime; do
  f="$(systemctl show -P FragmentPath "$u.service" 2>/dev/null || true)"
  if [ -n "$f" ] && [ -f "$f" ]; then OLD_UNIT="$u.service"; OLD_UNIT_FILE="$f"; break; fi
done
[ -n "$OLD_UNIT" ] && log "Текущий unit: $OLD_UNIT ($OLD_UNIT_FILE)" || warn "unit старой версии не найден, будет новая установка"

NGINX_SITE="$(grep -lsE "^\s*server_name\s+([^;]*\s)?${DOMAIN//./\\.}(\s|;)" /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf 2>/dev/null | head -n1 || true)"
[ -n "$NGINX_SITE" ] || die "не нашёл конфиг nginx с server_name $DOMAIN"
NGINX_SITE="$(readlink -f "$NGINX_SITE")"
log "Сайт nginx: $NGINX_SITE"

WEBROOT="$(grep -m1 -oE '^\s*root\s+[^;]+' "$NGINX_SITE" | awk '{print $2}')"
WEBROOT="${WEBROOT:-/var/www/onetime}"
log "Webroot: $WEBROOT"

SSL_CERT="$(grep -m1 -oE '^\s*ssl_certificate\s+[^;]+' "$NGINX_SITE" | awk '{print $2}')"
SSL_KEY="$(grep -m1 -oE '^\s*ssl_certificate_key\s+[^;]+' "$NGINX_SITE" | awk '{print $2}')"
[ -n "$SSL_CERT" ] && [ -n "$SSL_KEY" ] || die "в $NGINX_SITE нет ssl_certificate/ssl_certificate_key"
SSL_INCLUDE="$(grep -oE '^\s*include\s+/etc/letsencrypt/options-ssl-nginx.conf' "$NGINX_SITE" | awk '{print $2}' | head -n1 || true)"
SSL_DHPARAM="$(grep -m1 -oE '^\s*ssl_dhparam\s+[^;]+' "$NGINX_SITE" | awk '{print $2}' || true)"

# Адрес в listen: "listen onetime.j0ker.site:443 ssl;" -> "onetime.j0ker.site:",
# "listen 443 ssl;" -> "" (все адреса). IPv6-строки учитываются отдельно.
listen_prefix() {
  awk -v port="$1" '
    $1 == "listen" {
      a = $2; sub(/;.*/, "", a)
      if (a ~ /^\[/) next
      if (a == port) { print ""; found = 1; exit }
      if (a ~ (":" port "$")) { sub(port "$", "", a); print a; found = 1; exit }
    }
    END { if (!found) exit 1 }' "$NGINX_SITE"
}
LISTEN_HOST="$(listen_prefix 443 || true)"
LISTEN_HOST80="$(listen_prefix 80 || echo "$LISTEN_HOST")"
HAS_V6=0; grep -qE '^\s*listen\s+\[::\]' "$NGINX_SITE" && HAS_V6=1

NGINX_VER="$(nginx -v 2>&1 | sed -E 's#.*/([0-9.]+).*#\1#')"
log "nginx $NGINX_VER, listen '${LISTEN_HOST:-*:}443', IPv6: $HAS_V6"

# Пароль общего Redis (если был задан в старом конфиге)
OLD_REDIS_PASS="$(grep -E '^\s*requirepass\s' /etc/redis/redis.conf 2>/dev/null | awk '{print $2}' | tail -n1 || true)"
OLD_REDIS_PASS="${OLD_REDIS_PASS//\"/}"
if old_redis PING >/dev/null 2>&1; then
  OLD_COUNT="$(old_redis EVAL "return #redis.call('KEYS','messageKey*')" 0 2>/dev/null || echo '?')"
  log "Общий Redis: $OLD_REDIS_HOST:$OLD_REDIS_PORT, сообщений onetime: $OLD_COUNT"
  OLD_REDIS_OK=1
else
  warn "общий Redis $OLD_REDIS_HOST:$OLD_REDIS_PORT недоступен, перенос сообщений пропускается"
  OLD_REDIS_OK=0
fi

if [ "$ASSUME_YES" -ne 1 ]; then
  printf '\nБудут заменены: %s, %s, %s, %s\nПродолжить? [y/N] ' "$APP_DIR" "$WEBROOT" "$NGINX_SITE" "${OLD_UNIT_FILE:-unit}"
  read -r ans </dev/tty
  [ "$ans" = "y" ] || [ "$ans" = "Y" ] || die "отменено"
fi

# ---------------------------------------------------------------- 2. бэкап

log "Резервная копия: $BACKUP"
mkdir -p "$BACKUP"/{unit,nginx,redis}
[ -d "$APP_DIR" ] && cp -a "$APP_DIR" "$BACKUP/app"
[ -d "$WEBROOT" ] && cp -a "$WEBROOT" "$BACKUP/webroot"
cp -a "$NGINX_SITE" "$BACKUP/nginx/site.conf"
[ -n "$OLD_UNIT_FILE" ] && cp -a "$OLD_UNIT_FILE" "$BACKUP/unit/"
[ -f /etc/redis/redis.conf ] && cp -a /etc/redis/redis.conf "$BACKUP/redis/"
[ -d "$ETC_DIR" ] && cp -a "$ETC_DIR" "$BACKUP/etc_custom_1time"
cat > "$BACKUP/manifest" <<EOF
M_OLD_UNIT='$OLD_UNIT'
M_OLD_UNIT_FILE='$OLD_UNIT_FILE'
M_WEBROOT='$WEBROOT'
M_NGINX_SITE='$NGINX_SITE'
EOF
# Права самих файлов не трогаем: при откате они должны вернуться как были
# (www-data запускает бинарник, nginx читает webroot). Закрыт сам каталог.
chmod 700 "$BACKUP"

# ---------------------------------------------------------------- 3. тулчейн

STAGE="toolchain"
TOOLS="$BUILD_ROOT/toolchain"
mkdir -p "$TOOLS"

find_go() {
  local g
  for g in "$(command -v go 2>/dev/null || true)" /usr/local/go/bin/go "$TOOLS/go/bin/go"; do
    [ -n "$g" ] && [ -x "$g" ] || continue
    local v; v="$("$g" env GOVERSION 2>/dev/null | sed 's/^go//')"
    if [ -n "$v" ] && ver_ge "$v" "$GO_MIN"; then echo "$g"; return 0; fi
  done
  return 1
}

if ! GO_BIN="$(find_go)"; then
  log "Скачиваю Go $GO_MIN.x с go.dev"
  read -r GO_FILE GO_SHA < <(curl -fsSL 'https://go.dev/dl/?mode=json' | python3 -c "
import json,sys
want='$GO_MIN'; arch='$GOARCH'
for r in json.load(sys.stdin):
    if r['stable'] and (r['version']=='go'+want or r['version'].startswith('go'+want+'.')):
        for f in r['files']:
            if f['os']=='linux' and f['arch']==arch and f['kind']=='archive':
                print(f['filename'], f['sha256']); sys.exit(0)
sys.exit(1)")
  curl -fsSL -o "$TOOLS/$GO_FILE" "https://go.dev/dl/$GO_FILE"
  echo "$GO_SHA  $TOOLS/$GO_FILE" | sha256sum -c - >/dev/null
  rm -rf "$TOOLS/go" && tar -C "$TOOLS" -xzf "$TOOLS/$GO_FILE" && rm -f "$TOOLS/$GO_FILE"
  GO_BIN="$TOOLS/go/bin/go"
fi
log "Go: $("$GO_BIN" version)"

find_node() {
  local n
  for n in "$(command -v node 2>/dev/null || true)" "$TOOLS/node/bin/node"; do
    [ -n "$n" ] && [ -x "$n" ] || continue
    local v; v="$("$n" -v 2>/dev/null | sed 's/^v//')"
    if [ -n "$v" ] && ver_ge "$v" "$NODE_MIN" && [ -x "$(dirname "$n")/npm" ]; then echo "$n"; return 0; fi
  done
  return 1
}

if ! NODE_BIN="$(find_node)"; then
  log "Скачиваю Node.js $NODE_MAJOR LTS с nodejs.org"
  SUMS="$(curl -fsSL "https://nodejs.org/dist/latest-v$NODE_MAJOR.x/SHASUMS256.txt")"
  read -r NODE_SHA NODE_FILE < <(printf '%s\n' "$SUMS" | grep -E " node-v[0-9.]+-linux-$NODEARCH\.tar\.xz$")
  curl -fsSL -o "$TOOLS/$NODE_FILE" "https://nodejs.org/dist/latest-v$NODE_MAJOR.x/$NODE_FILE"
  echo "$NODE_SHA  $TOOLS/$NODE_FILE" | sha256sum -c - >/dev/null
  rm -rf "$TOOLS/node" && mkdir -p "$TOOLS/node" && tar -C "$TOOLS/node" --strip-components=1 -xJf "$TOOLS/$NODE_FILE" && rm -f "$TOOLS/$NODE_FILE"
  NODE_BIN="$TOOLS/node/bin/node"
fi
log "Node.js: $("$NODE_BIN" -v)"

# ---------------------------------------------------------------- 4. сборка

STAGE="build"
SRC="$BUILD_ROOT/src-$TS"
CACHE="$BUILD_ROOT/cache"
mkdir -p "$CACHE/home"
log "Клонирую $REPO ($REF)"
git clone -q -b "$REF" "$REPO" "$SRC"
COMMIT="$(git -C "$SRC" rev-parse HEAD)"
log "Коммит: $COMMIT"
chown -R nobody:nogroup "$SRC" "$CACHE"

# Сборка без root: код и npm-пакеты из сети не получают права root.
as_builder() {
  runuser -u nobody -- env -i \
    HOME="$CACHE/home" PATH="$(dirname "$GO_BIN"):$(dirname "$NODE_BIN"):/usr/bin:/bin" \
    GOPATH="$CACHE/gopath" GOCACHE="$CACHE/gocache" GOTOOLCHAIN=local CGO_ENABLED=0 \
    npm_config_cache="$CACHE/npm" npm_config_ignore_scripts=true npm_config_fund=false npm_config_update_notifier=false \
    HTTPS_PROXY="${HTTPS_PROXY:-}" https_proxy="${https_proxy:-}" NO_PROXY="${NO_PROXY:-}" no_proxy="${no_proxy:-}" \
    SSL_CERT_FILE="${SSL_CERT_FILE:-}" NODE_EXTRA_CA_CERTS="${NODE_EXTRA_CA_CERTS:-}" GIT_SSL_CAINFO="${GIT_SSL_CAINFO:-}" \
    GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}" GOSUMDB="${GOSUMDB:-sum.golang.org}" \
    GOINSECURE="${GOINSECURE:-}" GOFLAGS="${GOFLAGS:-}" \
    bash -c "cd '$SRC' && $1"
}

log "Go: vet, тесты, сборка"
as_builder "go vet ./... && go test -count=1 ./... && go build -trimpath -ldflags '-s -w' -o bin/1time ."
log "Фронтенд: установка, тесты, сборка"
as_builder "cd frontend && npm ci && npm test && npm run build"
if ! as_builder "cd frontend && npm audit --omit=dev"; then
  warn "npm audit нашёл уязвимости в зависимостях фронтенда, см. вывод выше"
fi
[ -x "$SRC/bin/1time" ] && [ -f "$SRC/frontend/build/index.html" ] || die "сборка не дала bin/1time или build/index.html"

# ---------------------------------------------------------------- 5. Redis

STAGE="redis"
mkdir -p "$ETC_DIR"
chmod 755 "$ETC_DIR"
if [ -f "$ETC_DIR/env" ] && grep -q '^REDISPASS=' "$ETC_DIR/env"; then
  REDIS_PASS="$(grep '^REDISPASS=' "$ETC_DIR/env" | cut -d= -f2-)"
else
  REDIS_PASS="$(openssl rand -hex 32)"
fi

log "Отдельный Redis: $REDIS_UNIT на 127.0.0.1:$REDIS_PORT"
install -d -o redis -g redis -m 750 "$REDIS_DATA"
umask 077
cat > "$ETC_DIR/redis.conf.new" <<EOF
# Redis только для 1time. Создан onetime-upgrade.sh
bind 127.0.0.1 -::1
protected-mode yes
port $REDIS_PORT
requirepass $REDIS_PASS
dir $REDIS_DATA
daemonize no
supervised systemd
logfile ""
# Только память: сообщения не попадают на диск и в бэкапы
save ""
appendonly no
maxmemory 256mb
maxmemory-policy noeviction
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command DEBUG ""
rename-command CONFIG ""
EOF
umask 022
chown root:redis "$ETC_DIR/redis.conf.new"
chmod 640 "$ETC_DIR/redis.conf.new"
# Redis хранит сообщения только в памяти: перезапуск их стирает. Если
# экземпляр уже работает с тем же конфигом (повторный запуск скрипта),
# его не трогаем.
REDIS_RESTART=1
if [ -f "$ETC_DIR/redis.conf" ] && cmp -s "$ETC_DIR/redis.conf.new" "$ETC_DIR/redis.conf" \
   && [ "$(new_redis PING 2>/dev/null || true)" = "PONG" ]; then
  REDIS_RESTART=0
fi
mv "$ETC_DIR/redis.conf.new" "$ETC_DIR/redis.conf"

cat > "$SYSTEMD_DIR/$REDIS_UNIT.service" <<EOF
[Unit]
Description=Redis for 1time (memory only)
After=network.target

[Service]
Type=notify
User=redis
Group=redis
ExecStart=/usr/bin/redis-server $ETC_DIR/redis.conf
Restart=always
RestartSec=2s
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=$REDIS_DATA
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LimitNOFILE=10032

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable "$REDIS_UNIT" >/dev/null 2>&1
if [ "$REDIS_RESTART" -eq 1 ]; then
  systemctl restart "$REDIS_UNIT"
else
  log "$REDIS_UNIT уже работает с этим конфигом, без перезапуска (сообщения сохраняются)"
fi
for _ in $(seq 1 30); do [ "$(new_redis PING 2>/dev/null || true)" = "PONG" ] && break; sleep 0.5; done
[ "$(new_redis PING 2>/dev/null || true)" = "PONG" ] || die "$REDIS_UNIT не отвечает"

# ---------------------------------------------------------------- 6. переключение

STAGE="switch"
if [ -n "$OLD_UNIT" ]; then
  log "Останавливаю $OLD_UNIT"
  systemctl stop "$OLD_UNIT"
fi

# Копия сообщений с сохранением TTL (MIGRATE COPY). Из общего Redis они
# удаляются только в самом конце, после успешных проверок.
MOVED_IDS_FILE="$BACKUP/migrated-keys"
: > "$MOVED_IDS_FILE"
if [ "$OLD_REDIS_OK" -eq 1 ]; then
  log "Копирую сообщения в $REDIS_UNIT"
  old_redis --scan --pattern 'messageKey*' > "$MOVED_IDS_FILE" || true
  total=$(wc -l < "$MOVED_IDS_FILE")
  if [ "$total" -gt 0 ]; then
    xargs -n 100 < "$MOVED_IDS_FILE" | while read -r keys; do
      # shellcheck disable=SC2086
      out="$(old_redis MIGRATE 127.0.0.1 "$REDIS_PORT" "" 0 5000 COPY REPLACE AUTH "$REDIS_PASS" KEYS $keys)"
      case "$out" in OK|NOKEY) ;; *) die "MIGRATE: $out" ;; esac
    done
  fi
  now_total="$(new_redis EVAL "return #redis.call('KEYS','messageKey*')" 0)"
  log "Перенесено из общего Redis: $total, всего сообщений в $REDIS_UNIT: $now_total"
fi

log "Устанавливаю бинарник в $APP_DIR"
rm -rf "$APP_DIR.new"
install -d -m 755 "$APP_DIR.new"
install -m 755 "$SRC/bin/1time" "$APP_DIR.new/1time"
echo "$REF $COMMIT $TS" > "$APP_DIR.new/VERSION"
rm -rf "$APP_DIR"
mv "$APP_DIR.new" "$APP_DIR"

umask 077
cat > "$ETC_DIR/env" <<EOF
LISTEN_ADDR=$LISTEN_ADDR
REDISHOST=127.0.0.1:$REDIS_PORT
REDISPASS=$REDIS_PASS
REDISDB=0
EOF
umask 022
chmod 600 "$ETC_DIR/env"

if [ -n "$OLD_UNIT_FILE" ] && [ "$OLD_UNIT" != "$APP_UNIT.service" ]; then
  systemctl disable "$OLD_UNIT" >/dev/null 2>&1 || true
  rm -f "$OLD_UNIT_FILE"
elif [ -n "$OLD_UNIT_FILE" ] && [ "$OLD_UNIT_FILE" != "$SYSTEMD_DIR/$APP_UNIT.service" ]; then
  # тот же unit, но лежал в /usr/lib/systemd/system: новый кладём в /etc
  rm -f "$OLD_UNIT_FILE"
fi
sed -e "s#^After=.*#After=network.target $REDIS_UNIT.service#" \
    -e "s#^Wants=.*#Requires=$REDIS_UNIT.service#" \
    "$SRC/configs/systemd/custom_1time.service" > "$SYSTEMD_DIR/$APP_UNIT.service"
systemctl daemon-reload
systemctl enable "$APP_UNIT" >/dev/null 2>&1
systemctl restart "$APP_UNIT"

log "Проверка бэкенда"
ok=0
for _ in $(seq 1 30); do
  resp="$(curl -fsS "http://$LISTEN_ADDR/api/health" 2>/dev/null || true)"
  if grep -q '"ok"' <<<"$resp"; then ok=1; break; fi
  sleep 0.5
done
[ "$ok" -eq 1 ] || die "/api/health не отвечает"

# Создать сообщение, прочитать один раз, второй раз получить отказ
if [ -d "$SRC/internal/otcrypto" ]; then
  # Версия с форматом v2/v3: шифрование на клиенте через "1time send/read",
  # /api/unsecSave должен быть выключен.
  smoke="upgrade-smoke-$TS"
  link="$(printf %s "$smoke" | env -u ONETIME_SECRET "$APP_DIR/1time" send -url "http://$LISTEN_ADDR" -days 1)"
  case "$link" in "http://$LISTEN_ADDR/v/#"?*) ;; *) die "1time send вернул не ссылку: $link" ;; esac
  got="$(env -u ONETIME_SECRET "$APP_DIR/1time" read "$link")" || die "1time read не смог прочитать сообщение"
  [ "$got" = "$smoke" ] || die "прочитано не то сообщение: $got"
  if env -u ONETIME_SECRET "$APP_DIR/1time" read "$link" >/dev/null 2>&1; then die "повторное чтение не запрещено"; fi
  code="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{"secretMessage":"x"}' "http://$LISTEN_ADDR/api/unsecSave")"
  [ "$code" = "404" ] || die "/api/unsecSave должен быть выключен в бэкенде, ответ $code"
  log "Шифрование на клиенте (1time send/read) работает, /api/unsecSave выключен"
else
  link="$(curl -fsS -X POST -H 'Content-Type: application/json' -d '{"secretMessage":"upgrade-smoke","duration":60}' "http://$LISTEN_ADDR/api/unsecSave" | python3 -c 'import sys,json;print(json.load(sys.stdin)["newLink"])')"
  frag="${link#/v/#}"; key="${frag:0:12}"; mid="${frag:12}"
  hash="$(printf %s "$key" | sha256sum | cut -d' ' -f1)"
  r1="$(curl -fsS -X POST -H 'Content-Type: application/json' -d "{\"id\":\"$mid\",\"hashedKey\":\"$hash\"}" "http://$LISTEN_ADDR/api/get")"
  r2="$(curl -fsS -X POST -H 'Content-Type: application/json' -d "{\"id\":\"$mid\",\"hashedKey\":\"$hash\"}" "http://$LISTEN_ADDR/api/get")"
  grep -q '"status":"ok"' <<<"$r1" || die "тест чтения не прошёл: $r1"
  grep -q '"no message"' <<<"$r2" || die "повторное чтение не запрещено: $r2"
fi
log "Сообщение создаётся и читается ровно один раз"

log "Фронтенд в $WEBROOT"
rm -rf "$WEBROOT.new"
cp -a "$SRC/frontend/build" "$WEBROOT.new"
chown -R root:root "$WEBROOT.new"
find "$WEBROOT.new" -type d -exec chmod 755 {} + && find "$WEBROOT.new" -type f -exec chmod 644 {} +
rm -rf "$WEBROOT"
mv "$WEBROOT.new" "$WEBROOT"

log "Конфиг nginx"
if ver_ge "$NGINX_VER" "1.25.1"; then H2_LISTEN=""; H2_DIRECTIVE="    http2 on;"; else H2_LISTEN=" http2"; H2_DIRECTIVE=""; fi
V6_80=""; V6_443=""
if [ "$HAS_V6" -eq 1 ]; then
  V6_80="    listen [::]:80;"
  V6_443="    listen [::]:443 ssl$H2_LISTEN;"
fi
if [ -n "$SSL_INCLUDE" ]; then
  SSL_TUNING="    include $SSL_INCLUDE;"
else
  SSL_TUNING="    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:onetime_ssl:10m;
    ssl_session_tickets off;"
fi
[ -n "$SSL_DHPARAM" ] && SSL_TUNING="$SSL_TUNING
    ssl_dhparam $SSL_DHPARAM;"

CSP="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; manifest-src 'self'; worker-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
SEC_HEADERS="add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;
        add_header X-Content-Type-Options \"nosniff\" always;"
ALL_HEADERS="$SEC_HEADERS
        add_header Content-Security-Policy \"$CSP\" always;
        add_header X-Frame-Options \"DENY\" always;
        add_header Referrer-Policy \"no-referrer\" always;
        add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;
        add_header Cross-Origin-Opener-Policy \"same-origin\" always;"

cat > "$NGINX_SITE.new" <<EOF
# $DOMAIN: 1time. Создан onetime-upgrade.sh $TS ($REF $COMMIT)
# Предыдущая версия: $BACKUP/nginx/site.conf

limit_req_zone \$binary_remote_addr zone=onetime_api:10m rate=10r/s;

upstream onetime_backend {
    server $LISTEN_ADDR;
    keepalive 16;
}

server {
    listen ${LISTEN_HOST80}80;
$V6_80
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}

server {
    listen ${LISTEN_HOST}443 ssl$H2_LISTEN;
$V6_443
$H2_DIRECTIVE
    server_name $DOMAIN;

    ssl_certificate     $SSL_CERT;
    ssl_certificate_key $SSL_KEY;
$SSL_TUNING

    root $WEBROOT;
    index index.html;
    server_tokens off;
    client_max_body_size 1m;

    access_log /var/log/nginx/onetime_access.log;
    error_log  /var/log/nginx/onetime_error.log;

    rewrite ^/ico.png\$ /favicon-1024.png last;

    # Сервер увидел бы здесь открытый текст: закрыто (скрипты используют
    # "1time send" с шифрованием на клиенте)
    location = /api/unsecSave {
        return 404;
    }

    location /api/ {
        $SEC_HEADERS
        limit_req zone=onetime_api burst=20 nodelay;
        limit_req_status 429;
        proxy_pass http://onetime_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 15s;
    }

    location /assets/ {
        add_header Cache-Control "public, max-age=31536000, immutable" always;
        $SEC_HEADERS
        try_files \$uri =404;
    }

    # Удаляет service worker старой сборки из браузеров
    location = /service-worker.js {
        add_header Cache-Control "no-cache" always;
        $SEC_HEADERS
        try_files \$uri =404;
    }

    location / {
        add_header Cache-Control "no-cache" always;
        $ALL_HEADERS
        try_files \$uri /index.html;
    }
}
EOF
sed -i '/^$/N;/^\n$/D' "$NGINX_SITE.new"
cp "$NGINX_SITE.new" "$BACKUP/nginx/site.generated.conf"
mv "$NGINX_SITE.new" "$NGINX_SITE"
nginx -t
systemctl reload nginx

log "Проверка через nginx"
HOST_IP="$(getent ahostsv4 "$DOMAIN" | awk 'NR==1{print $1}')"
ncurl() { curl -fsS ${HOST_IP:+--resolve "$DOMAIN:443:$HOST_IP"} "$@"; }
# reload в nginx асинхронный: старые воркеры ещё какое-то время отвечают
# по старому конфигу. Ждём, пока на /api/ появится заголовок нового конфига.
ok=0
for _ in $(seq 1 20); do
  hdrs="$(ncurl -D - -o /dev/null -X GET "https://$DOMAIN/api/health" 2>/dev/null || true)"
  if grep -qi '^strict-transport-security:' <<<"$hdrs"; then ok=1; break; fi
  sleep 1
done
[ "$ok" -eq 1 ] || { printf '%s\n' "$hdrs" >&2; die "nginx не перешёл на новый конфиг за 20 с"; }
resp="$(ncurl "https://$DOMAIN/api/health" 2>/dev/null || true)"
grep -q '"ok"' <<<"$resp" || die "https://$DOMAIN/api/health не отвечает: $resp"
hdrs="$(ncurl -I "https://$DOMAIN/v/")"
for h in content-security-policy strict-transport-security x-frame-options x-content-type-options referrer-policy; do
  grep -qi "^$h:" <<<"$hdrs" || { printf '%s\n' "$hdrs" >&2; die "нет заголовка $h"; }
done
page="$(ncurl "https://$DOMAIN/")"
grep -q '/assets/' <<<"$page" || die "главная страница не из новой сборки"
code="$(curl -s -o /dev/null -w '%{http_code}' ${HOST_IP:+--resolve "$DOMAIN:443:$HOST_IP"} -X POST -H 'Content-Type: application/json' -d '{"secretMessage":"x"}' "https://$DOMAIN/api/unsecSave")"
[ "$code" = "404" ] || die "/api/unsecSave должен быть закрыт в nginx, ответ $code"
log "Сайт отвечает по https с заголовками безопасности, /api/unsecSave закрыт"

# ---------------------------------------------------------------- 7. уборка

STAGE="done"
trap - ERR

if [ "$OLD_REDIS_OK" -eq 1 ] && [ -s "$MOVED_IDS_FILE" ]; then
  log "Удаляю перенесённые сообщения из общего Redis"
  xargs -n 100 < "$MOVED_IDS_FILE" | while read -r keys; do
    # shellcheck disable=SC2086
    old_redis UNLINK $keys >/dev/null
  done
  old_redis DEL nextIncrementalKey >/dev/null || true
  # Перезаписать dump.rdb без старых шифротекстов (если снапшоты включены)
  old_redis BGSAVE >/dev/null 2>&1 || true
fi
rm -f "$MOVED_IDS_FILE"

if [ "$PURGE_JOURNAL" -eq 1 ]; then
  log "Чищу journald (старая версия писала туда шифротексты и хэши ключей)"
  journalctl --rotate >/dev/null 2>&1 || true
  journalctl --vacuum-time=1s >/dev/null 2>&1 || true
else
  OLD_LINES="$(journalctl -q -u "${OLD_UNIT:-custom_onetime.service}" 2>/dev/null | grep -c 'paylaod\|Got from storage' || true)"
  [ "${OLD_LINES:-0}" -gt 0 ] && warn "в journald $OLD_LINES строк старой версии с шифротекстами: перезапусти с -j или почисти вручную"
fi

rm -rf "$SRC"
find "$BUILD_ROOT" -maxdepth 1 -name 'src-*' -mtime +7 -exec rm -rf {} + 2>/dev/null || true

log "Готово: $REF $COMMIT"
log "  бэкенд:  systemctl status $APP_UNIT"
log "  redis:   systemctl status $REDIS_UNIT (пароль в $ETC_DIR/env)"
log "  бэкап:   $BACKUP   (откат: $0 -R $BACKUP)"
log "  лог:     $LOG_FILE"
