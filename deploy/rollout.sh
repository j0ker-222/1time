#!/usr/bin/env bash
# rollout.sh: раскатка onetime на сервер одной командой.
#
#   git clone -b crypto-v2 --depth 1 https://github.com/j0ker-222/1time.git 1time-build
#   sudo bash 1time-build/deploy/rollout.sh
#
# Что делает:
#   1. если памяти мало (на сервере 1 ГБ), временно подключает swap 2 ГБ
#      (/swapfile-build), иначе компилятор Go убивает OOM killer;
#   2. запускает deploy/onetime-upgrade.sh из этой же копии репозитория со
#      сборкой в один поток (GOFLAGS=-p=1) и веткой, на которой стоит копия;
#   3. после работы отключает и удаляет swap, если сам его создавал.
#
# Ключи:
#   -d домен    по умолчанию onetime.j0ker.site
#   -y          не спрашивать подтверждение
#   -j          очистить journald от логов самой первой версии
#   -k          оставить swap после раскатки (и прописать в /etc/fstab)
#   -R каталог  откат из резервной копии (без сборки и swap)

set -Eeuo pipefail

DOMAIN="onetime.j0ker.site"
ASSUME_YES=0
PURGE_JOURNAL=0
KEEP_SWAP=0
ROLLBACK_FROM=""

SWAPFILE="/swapfile-build"
SWAP_SIZE_GB=2
MIN_MEM_MB=2048        # RAM + swap, при которых свой swap не нужен
MIN_FREE_DISK_MB=4096  # swap + сборка + бэкап

while getopts ":d:yjkR:h" opt; do
  case "$opt" in
    d) DOMAIN="$OPTARG" ;;
    y) ASSUME_YES=1 ;;
    j) PURGE_JOURNAL=1 ;;
    k) KEEP_SWAP=1 ;;
    R) ROLLBACK_FROM="$OPTARG" ;;
    h) sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
  esac
done

log()  { printf '\e[32m[rollout]\e[0m %s\n' "$*"; }
warn() { printf '\e[33m[rollout]\e[0m %s\n' "$*" >&2; }
die()  { printf '\e[31m[rollout]\e[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "запускать через sudo"

HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
UPGRADE="$HERE/onetime-upgrade.sh"
[ -f "$UPGRADE" ] || die "нет $UPGRADE рядом с rollout.sh"

if [ -n "$ROLLBACK_FROM" ]; then
  exec bash "$UPGRADE" -R "$ROLLBACK_FROM"
fi

REPO_DIR="$(dirname "$HERE")"
BRANCH="$(git -C "$REPO_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
REPO_URL="$(git -C "$REPO_DIR" remote get-url origin 2>/dev/null || true)"
COMMIT="$(git -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null || true)"
[ -n "$BRANCH" ] && [ "$BRANCH" != "HEAD" ] || die "не удалось определить ветку копии $REPO_DIR (клонируй с -b <ветка>)"
[ -n "$REPO_URL" ] || REPO_URL="https://github.com/j0ker-222/1time.git"
log "Раскатка $DOMAIN: ветка $BRANCH (сейчас $COMMIT), $REPO_URL"

# ---------------------------------------------------------------- swap

SWAP_CREATED=0
cleanup_swap() {
  if [ "$SWAP_CREATED" -eq 1 ] && [ "$KEEP_SWAP" -ne 1 ]; then
    log "Отключаю временный swap $SWAPFILE"
    swapoff "$SWAPFILE" 2>/dev/null || true
    rm -f "$SWAPFILE"
  fi
}
trap cleanup_swap EXIT

mem_mb="$(awk '/^MemTotal:/{print int($2/1024)}' /proc/meminfo)"
swap_mb="$(awk '/^SwapTotal:/{print int($2/1024)}' /proc/meminfo)"
log "Память: RAM ${mem_mb} МБ, swap ${swap_mb} МБ"

if [ $((mem_mb + swap_mb)) -lt "$MIN_MEM_MB" ]; then
  if swapon --show=NAME --noheadings 2>/dev/null | grep -qx "$SWAPFILE"; then
    log "$SWAPFILE уже подключён"
  else
    free_mb="$(df -Pm / | awk 'NR==2{print $4}')"
    [ "$free_mb" -ge "$MIN_FREE_DISK_MB" ] || die "на / свободно ${free_mb} МБ, нужно хотя бы ${MIN_FREE_DISK_MB} МБ"
    log "Подключаю временный swap ${SWAP_SIZE_GB} ГБ: $SWAPFILE"
    rm -f "$SWAPFILE"
    if ! fallocate -l "${SWAP_SIZE_GB}G" "$SWAPFILE" 2>/dev/null; then
      dd if=/dev/zero of="$SWAPFILE" bs=1M count=$((SWAP_SIZE_GB * 1024)) status=none
    fi
    chmod 600 "$SWAPFILE"
    mkswap "$SWAPFILE" >/dev/null
    if swapon "$SWAPFILE"; then
      SWAP_CREATED=1
    else
      rm -f "$SWAPFILE"
      warn "swapon не сработал; сборка может не поместиться в память (сайт при этом не пострадает)"
    fi
  fi
  free -h | sed 's/^/           /'
fi

# ---------------------------------------------------------------- раскатка

args=(-d "$DOMAIN" -r "$BRANCH" -u "$REPO_URL")
[ "$ASSUME_YES" -eq 1 ] && args+=(-y)
[ "$PURGE_JOURNAL" -eq 1 ] && args+=(-j)

log "Запускаю onetime-upgrade.sh ${args[*]} (сборка в один поток)"
rc=0
env GOFLAGS=-p=1 bash "$UPGRADE" "${args[@]}" || rc=$?

if [ "$rc" -eq 0 ] && [ "$KEEP_SWAP" -eq 1 ] && [ "$SWAP_CREATED" -eq 1 ]; then
  grep -q "^$SWAPFILE " /etc/fstab || echo "$SWAPFILE none swap sw 0 0" >> /etc/fstab
  log "swap $SWAPFILE оставлен и прописан в /etc/fstab"
fi

if [ "$rc" -eq 0 ]; then
  log "Готово. Проверка: curl -s https://$DOMAIN/api/health"
else
  warn "onetime-upgrade.sh завершился с кодом $rc (при ошибке после переключения он сам откатил версию)"
fi
exit "$rc"
