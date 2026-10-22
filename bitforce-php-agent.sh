#!/usr/bin/env bash
# =============================================================================
#  BitForce PHP Agent v2.0 - Diagnóstico y remediación de PHP2Shell
#  CVE-2026-109618 / CVE-2026-109619 (afecta PHP 5.4 a 8.5.11)
#  https://bitforce.pe
#
#  DISTRIBUCIONES: Debian, Ubuntu, RHEL, AlmaLinux, Rocky, CentOS, Oracle
#  Linux, Amazon Linux, Fedora, openSUSE/SLES y Alpine (requiere: apk add bash).
#  DETECTA: paneles (cPanel, Plesk, DirectAdmin, CWP, aaPanel, CyberPanel,
#  CloudPanel, HestiaCP, Virtualmin, ISPConfig, CloudLinux), Apache (mod_php
#  y PHP-FPM), Nginx, LiteSpeed/OpenLiteSpeed, Caddy y contenedores Docker.
#
#  MODOS
#    diagnose  (por defecto) Solo lectura. Inventario de PHP, estado del
#              parche, qué versión usa cada sitio e indicadores de compromiso.
#    fix       Actualiza PHP en la MISMA rama: respaldo, prueba de
#              configuración, reinicio de servicios y chequeo HTTP antes/después.
#    plan      Solo lectura. Plan de cambio de rama (--to X.Y): análisis de
#              compatibilidad del código, composer, extensiones y pasos.
#    stage     Instala la rama destino EN PARALELO sin cambiar ningún sitio:
#              mismas extensiones, ajustes de php.ini y pools; valida el código.
#    switch    Pasa sitios de la rama origen a la destino con respaldo, prueba
#              de configuración y reversión automática si un sitio falla.
#    rollback  Revierte el último fix o switch (o el indicado con --backup).
#
#  USO
#    sudo bash bitforce-php-agent.sh [modo] [opciones]
#
#  OPCIONES
#    --to X.Y          Rama destino (plan, stage, switch)
#    --from X.Y        Rama origen (plan, stage, switch); por defecto se detecta
#    --site NOMBRE     Sitio a cambiar en switch (dominio o archivo; repetible)
#    --all-sites       switch: todos los sitios que usan la rama origen
#    --cli             switch: cambia también el "php" de consola (Debian/Ubuntu)
#    --app DIR         Carpeta de la aplicación para plan/stage (repetible)
#    --upstream-repo   Permite agregar el repo upstream (Sury, PPA de Ondřej o
#                      Remi) si el repo de la distro no trae la versión necesaria
#    -w, --webroot DIR Raíz web adicional para indicadores (repetible)
#    -d, --days N      Archivos PHP modificados en los últimos N días (def. 5)
#    --since FECHA     Revisar logs desde FECHA AAAA-MM-DD (def. 2026-10-19)
#    --no-ioc          Omite la búsqueda de indicadores de compromiso
#    --backup ID       Respaldo a usar en rollback (por defecto el último)
#    -o, --out DIR     Carpeta de reportes (def. /var/tmp/bitforce)
#    -y, --yes         No pedir confirmación (ejecución desatendida)
#    -q, --no-color    Sin colores
#    -h, --help        Esta ayuda
#
#  CÓDIGOS DE SALIDA
#    0 OK | 1 requiere acción | 2 indicadores sospechosos | 3 error
# =============================================================================

if [ -z "${BASH_VERSION:-}" ]; then
  echo "Ejecuta con bash: bash $0   (en Alpine instala bash: apk add bash)"; exit 3
fi
if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then echo "Se requiere bash 4 o superior."; exit 3; fi

export LC_ALL=C
umask 022
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
shopt -s nullglob

AGENT_VERSION="2.0.0"
CVE_RE='CVE-2026-10961[89]'
declare -A FIXED=([8.2]=8.2.35 [8.3]=8.3.36 [8.4]=8.4.27 [8.5]=8.5.12)
declare -A EOL=([5.4]=2015-09-03 [5.5]=2016-07-21 [5.6]=2018-12-31 [7.0]=2019-01-10
  [7.1]=2019-12-01 [7.2]=2020-11-30 [7.3]=2021-12-06 [7.4]=2022-11-28 [8.0]=2023-11-26
  [8.1]=2025-12-31 [8.2]=2026-12-31 [8.3]=2027-12-31 [8.4]=2028-12-31 [8.5]=2029-12-31)
RECOMMENDED_TARGET="8.3"
BACKUP_ROOT="/var/backups/bitforce-php"
ACTION_LOG="/var/log/bitforce-php-agent.log"

# ----------------------------------------------------------------- argumentos
MODE="diagnose"
case "${1:-}" in diagnose|fix|plan|stage|switch|rollback|help) MODE=$1; shift ;; esac
TO=""; FROM=""; SITES_SEL=(); ALL_SITES=0; SWITCH_CLI=0; APPS=(); UPSTREAM=0
WEBROOTS=(); DAYS=5; SINCE="2026-10-19"; NO_IOC=0; BACKUP_ID=""
OUT_DIR="/var/tmp/bitforce"; ASSUME_YES=0; USE_COLOR=1
while [ $# -gt 0 ]; do
  case "$1" in
    --to) TO=${2:-}; shift ;;
    --from) FROM=${2:-}; shift ;;
    --site) SITES_SEL+=("${2:-}"); shift ;;
    --all-sites) ALL_SITES=1 ;;
    --cli) SWITCH_CLI=1 ;;
    --app) APPS+=("${2:-}"); shift ;;
    --upstream-repo) UPSTREAM=1 ;;
    -w|--webroot) WEBROOTS+=("${2:-}"); shift ;;
    -d|--days) DAYS=${2:-5}; shift ;;
    --since) SINCE=${2:-}; shift ;;
    --no-ioc) NO_IOC=1 ;;
    --backup) BACKUP_ID=${2:-}; shift ;;
    -o|--out) OUT_DIR=${2:-}; shift ;;
    -y|--yes) ASSUME_YES=1 ;;
    -q|--no-color) USE_COLOR=0 ;;
    -h|--help|help) MODE=help ;;
    *) echo "Opción desconocida: $1 (usa --help)" >&2; exit 3 ;;
  esac
  shift
done
if [ "$MODE" = help ]; then
  awk 'NR>2 && /^# =+$/ {exit} NR>2 {sub(/^# ?/,""); print}' "$0"; exit 0
fi
for v in "$TO" "$FROM"; do
  if [ -n "$v" ] && ! [[ $v =~ ^[0-9]+\.[0-9]+$ ]]; then echo "Rama inválida: $v (formato X.Y, ej. 8.3)" >&2; exit 3; fi
done
[[ $DAYS =~ ^[0-9]+$ ]] || DAYS=5

# ------------------------------------------------------------------- salida
mkdir -p "$OUT_DIR" 2>/dev/null; [ -w "$OUT_DIR" ] || OUT_DIR=/tmp
HOST=$(hostname -f 2>/dev/null || hostname 2>/dev/null || cat /proc/sys/kernel/hostname)
HOST=${HOST//[^A-Za-z0-9._-]/_}
STAMP=$(date +%Y%m%d-%H%M%S)
BASE="$OUT_DIR/bitforce-${HOST}-${STAMP}-${MODE}"
TXT="$BASE.txt"; JSON="$BASE.json"
[ -t 1 ] || USE_COLOR=0
if [ "$USE_COLOR" -eq 1 ]; then
  R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; B=$'\e[1m'; N=$'\e[0m'
  exec > >(tee >(sed -r 's/\x1b\[[0-9;]*m//g' > "$TXT")) 2>&1
else
  R=""; G=""; Y=""; C=""; B=""; N=""
  exec > >(tee "$TXT") 2>&1
fi

NEEDS_ACTION=0; SUSPICIOUS=0
SUMMARY=(); IOC_FINDINGS=(); ACTIONS=(); RECS=()

section() { printf '\n%s== %s ==%s\n' "$B" "$1" "$N"; }
subhead() { printf '\n  %s%s%s\n' "$B" "$1" "$N"; }
ok()   { printf '  %s[OK]%s     %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s[AVISO]%s  %s\n' "$Y" "$N" "$*"; }
bad()  { printf '  %s[FALLA]%s  %s\n' "$R" "$N" "$*"; }
info() { printf '           %s\n' "$*"; }
cmdl() { printf '           %s$ %s%s\n' "$C" "$*" "$N"; }
have() { command -v "$1" >/dev/null 2>&1; }
trimw() { sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s/[[:space:]]+/ /g' <<< "$1"; }
uniqw() { tr -s ' \t' '\n\n' <<< "$1" | grep -v '^$' | sort -u | tr '\n' ' ' | sed 's/ $//'; }
TAB=$'\t'
alog() { echo "[$(date '+%F %T')] [$MODE] $*" >> "$ACTION_LOG" 2>/dev/null; }

run_cmd() {   # ejecuta, muestra las últimas líneas y guarda todo en el log
  local tmp rc; tmp=$(mktemp 2>/dev/null || echo "/tmp/bf.$$.$RANDOM")
  printf '  %s$ %s%s\n' "$C" "$*" "$N"; alog "\$ $*"
  "$@" >"$tmp" 2>&1; rc=$?
  cat "$tmp" >> "$ACTION_LOG" 2>/dev/null
  tail -n 8 "$tmp" | sed 's/^/      /'
  rm -f "$tmp"; ACTIONS+=("$* (rc=$rc)"); return $rc
}
run_sh() { run_cmd bash -c "$1"; }

confirm() {
  [ "$ASSUME_YES" -eq 1 ] && return 0
  if { : < /dev/tty; } 2>/dev/null; then
    local ans; printf '\n  %s%s [s/N]: %s' "$B" "$1" "$N"; read -r ans < /dev/tty
    [[ $ans =~ ^[sSyY] ]]
  else
    warn "No hay terminal interactiva. Repite con --yes para confirmar, o usa: ssh -t ..."
    return 1
  fi
}

LOCKDIR=/run/bitforce-php-agent.lock
cleanup() { [ -n "${LOCK_HELD:-}" ] && rmdir "$LOCKDIR" 2>/dev/null; }
trap cleanup EXIT
take_lock() {
  [ -d /run ] || LOCKDIR=/tmp/bitforce-php-agent.lock
  if mkdir "$LOCKDIR" 2>/dev/null; then LOCK_HELD=1
  else bad "Otra ejecución del agente está en curso ($LOCKDIR)."; finish 3; fi
}
need_root() { [ "$(id -u)" -eq 0 ] || { bad "El modo '$MODE' requiere root (sudo)."; finish 3; }; }

# --------------------------------------------------------------- versiones
ver_ge() {   # 0 si $1 >= $2
  local IFS=. i x y; local -a a b; read -ra a <<< "$1"; read -ra b <<< "$2"
  for ((i=0; i<${#a[@]} || i<${#b[@]}; i++)); do
    x=${a[i]:-0}; y=${b[i]:-0}; x=${x%%[!0-9]*}; y=${y%%[!0-9]*}; x=${x:-0}; y=${y:-0}
    ((10#$x > 10#$y)) && return 0; ((10#$x < 10#$y)) && return 1
  done; return 0
}
ver_lt() { ! ver_ge "$1" "$2"; }
ver_gt() { ver_ge "$1" "$2" && [ "$1" != "$2" ] && ! ver_ge "$2" "$1"; }
branch_of() { [[ $1 =~ ^([0-9]+)\.([0-9]+) ]] && echo "${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"; }
xy_of() { echo "${1/./}"; }
upstream_of() { local v="${1#*:}"; echo "${v%%[-+~]*}"; }
guess_branch() {   # extrae la rama de un texto: php8.3, php83, ea-php82, lsphp74...
  local t=$1
  if [[ $t =~ ([5-8])\.([0-9]) ]]; then echo "${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"; return; fi
  if [[ $t =~ php-?(fpm)?([5-8])([0-9]) ]]; then echo "${BASH_REMATCH[2]}.${BASH_REMATCH[3]}"; return; fi
}
bump_last() { local p=${1%.*} l=${1##*.}; [ "$p" = "$1" ] && echo $((l+1)) || echo "$p.$((l+1))"; }
php_version_of() { timeout 8 "$1" -v 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1; }

# ------------------------------------------------------------------ sistema
detect_os() {
  local OSR_ID="" OSR_ID_LIKE="" OSR_VERSION_ID="" OSR_PRETTY_NAME="" OSR_VERSION_CODENAME="" OSR_UBUNTU_CODENAME=""
  if [ -r /etc/os-release ]; then
    eval "$(sed -nE 's/^(ID|ID_LIKE|VERSION_ID|PRETTY_NAME|VERSION_CODENAME|UBUNTU_CODENAME)=(.*)$/OSR_\1=\2/p' /etc/os-release)"
  fi
  OS_ID=${OSR_ID:-unknown}; OS_LIKE=${OSR_ID_LIKE:-}; OS_VER=${OSR_VERSION_ID:-}
  OS_NAME=${OSR_PRETTY_NAME:-$(uname -sr)}; OS_CODENAME=${OSR_UBUNTU_CODENAME:-${OSR_VERSION_CODENAME:-}}
  OS_MAJOR=${OS_VER%%.*}
  case " $OS_ID $OS_LIKE " in
    *" debian "*|*" ubuntu "*) FAMILY=debian; PKGTOOL=dpkg ;;
    *" rhel "*|*" fedora "*|*" centos "*|*" amzn "*|*" cloudlinux "*|*" almalinux "*|*" rocky "*|*" ol "*) FAMILY=rhel; PKGTOOL=rpm ;;
    *suse*|*" sles "*) FAMILY=suse; PKGTOOL=rpm ;;
    *" alpine "*) FAMILY=alpine; PKGTOOL=apk ;;
    *) FAMILY=unknown; PKGTOOL=none
       have dpkg && { FAMILY=debian; PKGTOOL=dpkg; }
       have rpm && [ "$FAMILY" = unknown ] && { FAMILY=rhel; PKGTOOL=rpm; } ;;
  esac
  DNF=dnf; have dnf || DNF=yum
  HAS_SYSTEMD=0; [ -d /run/systemd/system ] && have systemctl && HAS_SYSTEMD=1
  case $FAMILY in debian|suse) APACHE_SVC=apache2 ;; *) APACHE_SVC=httpd ;; esac
}

detect_panel() {
  PANEL=""; PANEL_NAME=""; PANEL_OWN=0; CLOUDLINUX=0
  if [ -d /usr/local/cpanel ]; then PANEL=cpanel; PANEL_NAME="cPanel/WHM (EasyApache 4)"
  elif [ -d /usr/local/psa ]; then PANEL=plesk; PANEL_NAME="Plesk"; PANEL_OWN=1
  elif [ -d /usr/local/directadmin ]; then PANEL=directadmin; PANEL_NAME="DirectAdmin"; PANEL_OWN=1
  elif [ -d /usr/local/cwpsrv ]; then PANEL=cwp; PANEL_NAME="CentOS Web Panel"; PANEL_OWN=1
  elif [ -d /www/server/panel ]; then PANEL=aapanel; PANEL_NAME="aaPanel"; PANEL_OWN=1
  elif [ -d /usr/local/CyberCP ]; then PANEL=cyberpanel; PANEL_NAME="CyberPanel"
  elif have clpctl || [ -d /home/clp ]; then PANEL=cloudpanel; PANEL_NAME="CloudPanel"
  elif [ -d /usr/local/hestia ]; then PANEL=hestia; PANEL_NAME="HestiaCP"
  elif [ -d /usr/local/vesta ]; then PANEL=vesta; PANEL_NAME="VestaCP"
  elif [ -d /usr/local/ispconfig ]; then PANEL=ispconfig; PANEL_NAME="ISPConfig"
  elif [ -d /etc/webmin/virtual-server ]; then PANEL=virtualmin; PANEL_NAME="Virtualmin"
  fi
  { grep -qi cloudlinux /etc/os-release 2>/dev/null || [ -d /opt/alt ]; } && CLOUDLINUX=1
}

panel_howto() {
  case $PANEL in
    cpanel) info "WHM > EasyApache 4, o por consola:"
            cmdl "$DNF -y upgrade 'ea-php*' && /scripts/restartsrv_apache_php_fpm && /scripts/restartsrv_httpd" ;;
    plesk) info "Herramientas y configuración > Actualizaciones, o por consola:"
           cmdl "plesk installer --select-product-id plesk --select-release-current --upgrade-installed-components" ;;
    directadmin) cmdl "cd /usr/local/directadmin/custombuild && ./build update && ./build php" ;;
    cwp) info "CWP > PHP Settings > PHP Version Switcher / PHP-FPM Selector: recompilar a la versión corregida." ;;
    aapanel) info "aaPanel > App Store > PHP X.Y > Update (recompila PHP con la versión corregida)." ;;
  esac
}

scan_procs() {
  P_PID=(); P_COMM=(); P_UID=()
  local d comm k v
  for d in /proc/[0-9]*; do
    read -r comm 2>/dev/null < "$d/comm" || continue
    v=""
    while read -r k v _; do [ "$k" = "Uid:" ] && break; v=""; done 2>/dev/null < "$d/status"
    P_PID+=("${d#/proc/}"); P_COMM+=("$comm"); P_UID+=("$v")
  done
}
proc_exe() { readlink "/proc/$1/exe" 2>/dev/null; }
proc_cmd() { tr '\0' ' ' 2>/dev/null < "/proc/$1/cmdline"; }

listen_ports() {
  local f sl l rem st
  for f in /proc/net/tcp /proc/net/tcp6; do
    [ -r "$f" ] || continue
    while read -r sl l rem st _; do
      [ "$st" = 0A ] && echo $((16#${l##*:}))
    done < <(tail -n +2 "$f")
  done | sort -un
}

# ------------------------------------------------------------- paquetes
pkg_info() {   # define PI_NAME PI_VER PI_UP PI_VENDOR para un archivo
  PI_NAME=""; PI_VER=""; PI_UP=""; PI_VENDOR=""
  local f=$1 out
  case $PKGTOOL in
    dpkg) out=$(dpkg -S "$f" 2>/dev/null | grep -v '^diversion' | head -1)
          [ -n "$out" ] || return 1
          PI_NAME=${out%%:*}; PI_VER=$(dpkg-query -W -f='${Version}' "$PI_NAME" 2>/dev/null) ;;
    rpm)  out=$(rpm -qf --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n' "$f" 2>/dev/null | head -1)
          case $out in ""|*"not owned"*|*"no pertenece"*) return 1 ;; esac
          IFS=$'\t' read -r PI_NAME PI_VER PI_VENDOR <<< "$out" ;;
    apk)  out=$(apk info --who-owns "$f" 2>/dev/null | head -1)
          case $out in *"is owned by"*) out=${out##* }
            PI_NAME=$(echo "$out" | sed -E 's/-[0-9][^-]*-r[0-9]+$//'); PI_VER=${out#"$PI_NAME"-} ;;
          *) return 1 ;; esac ;;
    *) return 1 ;;
  esac
  PI_UP=$(upstream_of "$PI_VER"); return 0
}
apt_origin() { apt-cache policy "$1" 2>/dev/null | grep -oE 'https?://[^ ]+' | head -1; }

installed_pkgs_matching() {   # lista de paquetes instalados que cumplen la regex
  case $PKGTOOL in
    dpkg) dpkg-query -W -f='${Package} ${db:Status-Abbrev}\n' 2>/dev/null | awk '$2 ~ /^ii/ {print $1}' | grep -E "$1" ;;
    rpm)  rpm -qa --qf '%{NAME}\n' 2>/dev/null | grep -E "$1" | sort -u ;;
    apk)  apk info 2>/dev/null | grep -E "$1" ;;
  esac
}

# ----------------------------------------------------- instalaciones de PHP
reset_installs() {
  INST_KEYS=()
  unset I_VER I_BR I_PREFIX I_BINS I_KINDS I_CLI I_FPM I_LSPHP I_MOD I_PKG I_PKGVER I_VENDOR \
        I_SRC I_STATUS I_WHY I_SVCS I_STALE I_SOCKS I_CONF I_RUN SOCK2KEY
  declare -gA I_VER=() I_BR=() I_PREFIX=() I_BINS=() I_KINDS=() I_CLI=() I_FPM=() I_LSPHP=() \
              I_MOD=() I_PKG=() I_PKGVER=() I_VENDOR=() I_SRC=() I_STATUS=() I_WHY=() \
              I_SVCS=() I_STALE=() I_SOCKS=() I_CONF=() I_RUN=() SOCK2KEY=()
}

new_key() {   # $1 clave $2 versión $3 prefijo
  if [ -z "${I_VER[$1]:-}" ]; then
    INST_KEYS+=("$1"); I_VER[$1]=$2; I_BR[$1]=$(branch_of "$2"); I_PREFIX[$1]=$3
  fi
}
add_bin() {   # $1 ruta $2 tipo (cli|fpm|lsphp)
  local real ver br prefix key k
  real=$(readlink -f "$1" 2>/dev/null); [ -n "$real" ] || real=$1
  [ -f "$real" ] && [ -x "$real" ] || return 1
  for k in "${INST_KEYS[@]}"; do case " ${I_BINS[$k]} " in *" $real "*) LAST_KEY=$k; return 0 ;; esac; done
  ver=$(php_version_of "$real"); [ -n "$ver" ] || return 1
  br=$(branch_of "$ver"); prefix=$(dirname "$(dirname "$real")")
  key="$prefix|$br"
  if [ "$real" = /usr/bin/php ] || [ "$real" = /usr/local/bin/php ]; then   # envoltorio genérico
    for k in "${INST_KEYS[@]}"; do [ "${I_VER[$k]}" = "$ver" ] && { key=$k; break; }; done
  fi
  new_key "$key" "$ver" "$prefix"
  I_BINS[$key]="${I_BINS[$key]:+${I_BINS[$key]} }$real"; I_KINDS[$key]="${I_KINDS[$key]:+${I_KINDS[$key]} }$2"
  case $2 in
    cli) [ -z "${I_CLI[$key]:-}" ] && I_CLI[$key]=$real ;;
    fpm) I_FPM[$key]=$real ;;
    lsphp) I_LSPHP[$key]=$real ;;
  esac
  LAST_KEY=$key
}
add_mod() {   # módulo de Apache (mod_php)
  local real prefix ver br key k
  real=$(readlink -f "$1" 2>/dev/null); [ -f "$real" ] || return 1
  prefix=${real%%/lib*}; [ -n "$prefix" ] || prefix=/usr
  pkg_info "$real"; ver=$PI_UP
  br=$(branch_of "$ver"); [ -n "$br" ] || br=$(guess_branch "$(basename "$real")")
  key=""
  for k in "${INST_KEYS[@]}"; do
    [ "${I_PREFIX[$k]}" = "$prefix" ] || continue
    if [ -z "$br" ] || [ "${I_BR[$k]}" = "$br" ]; then key=$k; break; fi
  done
  if [ -z "$key" ]; then [ -n "$ver" ] || return 1; key="$prefix|$br"; new_key "$key" "$ver" "$prefix"; fi
  I_MOD[$key]=$real; I_KINDS[$key]="${I_KINDS[$key]:+${I_KINDS[$key]} }apache-mod"
  case " ${I_BINS[$key]} " in *" $real "*) ;; *) I_BINS[$key]="${I_BINS[$key]:+${I_BINS[$key]} }$real" ;; esac
}

discover_installs() {
  reset_installs
  local c i e
  for c in /usr/bin/php[0-9]* /usr/local/bin/php[0-9]* /opt/remi/php*/root/usr/bin/php \
           /opt/cpanel/ea-php*/root/usr/bin/php /opt/alt/php*/usr/bin/php /opt/plesk/php/*/bin/php \
           /usr/local/lsws/lsphp*/bin/php /www/server/php/*/bin/php /usr/local/php*/bin/php /opt/php*/bin/php; do
    case $c in *-config*|*ize*|*dbg*|*cgi*) continue ;; esac
    add_bin "$c" cli
  done
  for c in /usr/sbin/php-fpm* /usr/local/sbin/php-fpm* /opt/remi/php*/root/usr/sbin/php-fpm \
           /opt/cpanel/ea-php*/root/usr/sbin/php-fpm /opt/alt/php*/usr/sbin/php-fpm /opt/plesk/php/*/sbin/php-fpm \
           /www/server/php/*/sbin/php-fpm /usr/local/php*/sbin/php-fpm /opt/php*/sbin/php-fpm; do
    add_bin "$c" fpm
  done
  for c in /usr/local/lsws/lsphp*/bin/lsphp /usr/bin/lsphp*; do add_bin "$c" lsphp; done
  for i in "${!P_PID[@]}"; do   # binarios en ejecución (incluye compilados a mano)
    case ${P_COMM[$i]} in
      php-fpm*|php[0-9]*|php|lsphp*)
        e=$(proc_exe "${P_PID[$i]}"); e=${e% (deleted)}; [ -n "$e" ] || continue
        case ${P_COMM[$i]} in php-fpm*) add_bin "$e" fpm ;; lsphp*) add_bin "$e" lsphp ;; *) add_bin "$e" cli ;; esac ;;
    esac
  done
  for c in /usr/bin/php /usr/local/bin/php; do add_bin "$c" cli; done
  for c in /usr/lib/apache2/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so /usr/lib/httpd/modules/libphp*.so \
           /usr/lib64/apache2*/mod_php*.so /usr/lib/apache2*/mod_php*.so /usr/libexec/apache2/libphp*.so; do
    add_mod "$c"
  done
}

has_cve_changelog() {
  local n=${I_PKG[$1]:-} br=${I_BR[$1]} f
  [ -n "$n" ] || return 1
  case $PKGTOOL in
    dpkg) for f in "/usr/share/doc/$n/changelog.Debian.gz" "/usr/share/doc/php$br-common/changelog.Debian.gz"; do
            [ -r "$f" ] && gzip -dc "$f" 2>/dev/null | grep -qE "$CVE_RE" && return 0
          done ;;
    rpm) rpm -q --changelog "$n" 2>/dev/null | grep -qE "$CVE_RE" && return 0 ;;
  esac
  return 1
}

classify_src() {
  local k=$1 p=${I_PREFIX[$1]} n=${I_PKG[$1]:-} o
  case $p in
    /opt/cpanel/*) echo cpanel; return ;; /opt/plesk/*) echo plesk; return ;;
    /opt/alt/*) echo cloudlinux; return ;; /usr/local/lsws/*) echo litespeed; return ;;
    /www/server/*) echo aapanel; return ;; /opt/remi/*) echo remi-scl; return ;;
  esac
  if [ -z "$n" ]; then
    case $PANEL in directadmin|cwp) echo "$PANEL" ;; *) echo manual ;; esac; return
  fi
  case $n in ea-*) echo cpanel; return ;; alt-php*) echo cloudlinux; return ;;
             plesk-php*) echo plesk; return ;; lsphp*) echo litespeed; return ;; esac
  case $PKGTOOL in
    dpkg) o=$(apt_origin "$n")
          case $o in *sury*) echo sury ;; *ondrej*|*launchpad*) echo ondrej-ppa ;;
                     *esm.ubuntu*) echo ubuntu-esm ;; "") echo local ;; *) echo distro ;; esac ;;
    rpm) case "${I_PKGVER[$k]} ${I_VENDOR[$k]:-}" in *remi*|*Remi*) echo remi ;; *) echo distro ;; esac ;;
    *) echo distro ;;
  esac
}

evaluate_installs() {
  local k first v br fixed
  for k in "${INST_KEYS[@]}"; do
    read -r first _ <<< "${I_BINS[$k]}"
    if pkg_info "$first"; then I_PKG[$k]=$PI_NAME; I_PKGVER[$k]=$PI_VER; I_VENDOR[$k]=$PI_VENDOR; fi
    I_SRC[$k]=$(classify_src "$k")
    v=${I_VER[$k]}; br=${I_BR[$k]}; fixed=${FIXED[$br]:-}
    if ver_ge "$br" 8.6; then I_STATUS[$k]=PATCHED; I_WHY[$k]="rama posterior a 8.5"
    elif [ -n "$fixed" ] && ver_ge "$v" "$fixed"; then I_STATUS[$k]=PATCHED; I_WHY[$k]="versión $v ≥ $fixed"
    elif has_cve_changelog "$k"; then I_STATUS[$k]=PATCHED; I_WHY[$k]="backport de la distro: el changelog menciona el CVE"
    elif [ -n "$fixed" ]; then I_STATUS[$k]=VULNERABLE; I_WHY[$k]="versión $v < $fixed"
    else I_STATUS[$k]=UNSUPPORTED; I_WHY[$k]="rama $br sin soporte upstream desde ${EOL[$br]:-hace años}"
    fi
    I_STALE[$k]=0
  done
}

map_running() {   # procesos por instalación y reinicio pendiente
  local i e k stale
  for i in "${!P_PID[@]}"; do
    case ${P_COMM[$i]} in php-fpm*|php[0-9]*|php|lsphp*|apache2|httpd) ;; *) continue ;; esac
    e=$(proc_exe "${P_PID[$i]}"); [ -n "$e" ] || continue
    stale=0; [[ $e == *" (deleted)" ]] && stale=1; e=${e% (deleted)}
    for k in "${INST_KEYS[@]}"; do
      case ${P_COMM[$i]} in
        apache2|httpd)
          [ -n "${I_MOD[$k]:-}" ] || continue
          grep -q "${I_MOD[$k]}" "/proc/${P_PID[$i]}/maps" 2>/dev/null || continue
          grep -E "libphp|mod_php" "/proc/${P_PID[$i]}/maps" 2>/dev/null | grep -q '(deleted)' && stale=1 ;;
        *) case " ${I_BINS[$k]} " in *" $(readlink -f "$e" 2>/dev/null || echo "$e") "*) ;; *) continue ;; esac ;;
      esac
      I_RUN[$k]="${I_RUN[$k]:-} ${P_PID[$i]}"
      [ $stale -eq 1 ] && I_STALE[$k]=1
    done
  done
}

map_services() {
  local u path real k br
  if [ "$HAS_SYSTEMD" -eq 1 ]; then
    while read -r u _; do
      [[ $u == *.service ]] || continue
      path=$(systemctl show -p ExecStart "$u" 2>/dev/null | grep -oE 'path=[^ ;]+' | head -1); path=${path#path=}
      [ -n "$path" ] || continue
      real=$(readlink -f "$path" 2>/dev/null || echo "$path")
      for k in "${INST_KEYS[@]}"; do
        case " ${I_BINS[$k]} " in *" $real "*) I_SVCS[$k]="${I_SVCS[$k]:+${I_SVCS[$k]} }${u%.service}" ;; esac
      done
    done < <(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null | grep -Ei 'php|fpm')
  else
    for path in /etc/init.d/*php*fpm* /etc/init.d/*fpm*php* /etc/init.d/php-fpm*; do
      u=$(basename "$path"); br=$(guess_branch "$u")
      for k in "${INST_KEYS[@]}"; do
        [ -n "${I_FPM[$k]:-}" ] || continue
        if [ -z "$br" ] || [ "${I_BR[$k]}" = "$br" ]; then
          case " ${I_SVCS[$k]:-} " in *" $u "*) ;; *) I_SVCS[$k]="${I_SVCS[$k]:+${I_SVCS[$k]} }$u" ;; esac
        fi
      done
    done
  fi
}

norm_listen() {
  local v=${1#unix:}
  v=${v#proxy:}; v=${v#unix:}; v=${v%%|*}
  case $v in
    fcgi://*) v=${v#fcgi://}; v=${v%%/*}; echo ":${v##*:}" ;;
    /*) readlink -f "$v" 2>/dev/null || echo "$v" ;;
    *:*) echo ":${v##*:}" ;;
    [0-9]*) echo ":$v" ;;
    *) echo "$v" ;;
  esac
}
fpm_conf_for() {
  local k=$1 br=${I_BR[$1]} xy p=${I_PREFIX[$1]} c
  xy=$(xy_of "$br")
  for c in "/etc/php/$br/fpm/php-fpm.conf" "/etc/opt/remi/php$xy/php-fpm.conf" "/etc/php$xy/php-fpm.conf" \
           "${p%/usr}/etc/php-fpm.conf" "$p/etc/php-fpm.conf" "/etc/php${br%%.*}/fpm/php-fpm.conf" \
           /etc/php-fpm.conf /usr/local/etc/php-fpm.conf; do
    [ -f "$c" ] && { echo "$c"; return; }
  done
}
fpm_pool_files() {
  local conf=$1 dir pat f
  dir=$(dirname "$conf"); echo "$conf"
  while read -r pat; do
    case $pat in /*) ;; *) pat="$dir/$pat" ;; esac
    for f in $pat; do [ -f "$f" ] && echo "$f"; done
  done < <(grep -hE '^[[:space:]]*include[[:space:]]*=' "$conf" 2>/dev/null | sed -E 's/^[^=]*=[[:space:]]*//; s/[[:space:]]*$//; s/"//g')
}
fpm_listens() {   # imprime: archivo<TAB>pool<TAB>listen<TAB>usuario
  local f
  while read -r f; do
    awk -v f="$f" '
      /^[ \t]*\[[^]]+\]/ { if (pool!="" && pool!="global" && l!="") print f "\t" pool "\t" l "\t" u
                           pool=$0; gsub(/[][ \t]/,"",pool); l=""; u=""; next }
      /^[ \t]*listen[ \t]*=/ { l=$0; sub(/^[^=]*=[ \t]*/,"",l); gsub(/[" \t]/,"",l) }
      /^[ \t]*user[ \t]*=/ { u=$0; sub(/^[^=]*=[ \t]*/,"",u); gsub(/[" \t]/,"",u) }
      END { if (pool!="" && pool!="global" && l!="") print f "\t" pool "\t" l "\t" u }' "$f" 2>/dev/null \
    | while IFS=$'\t' read -r ff pool l u; do printf '%s\t%s\t%s\t%s\n' "$ff" "$pool" "${l//\$pool/$pool}" "$u"; done
  done < <(fpm_pool_files "$1")
}
map_fpm_sockets() {
  local i cmd conf e k ff pool l u
  POOL_USERS=""
  for i in "${!P_PID[@]}"; do
    [[ ${P_COMM[$i]} == php-fpm* ]] || continue
    cmd=$(proc_cmd "${P_PID[$i]}"); [[ $cmd == *"master process"* ]] || continue
    conf=$(sed -nE 's/.*master process \(([^)]*)\).*/\1/p' <<< "$cmd")
    e=$(proc_exe "${P_PID[$i]}"); e=${e% (deleted)}; e=$(readlink -f "$e" 2>/dev/null || echo "$e")
    for k in "${INST_KEYS[@]}"; do case " ${I_BINS[$k]} " in *" $e "*) [ -n "$conf" ] && I_CONF[$k]=$conf ;; esac; done
  done
  for k in "${INST_KEYS[@]}"; do
    [ -n "${I_FPM[$k]:-}" ] || continue
    [ -n "${I_CONF[$k]:-}" ] || I_CONF[$k]=$(fpm_conf_for "$k")
    [ -n "${I_CONF[$k]}" ] || continue
    while IFS=$'\t' read -r ff pool l u; do
      I_SOCKS[$k]="${I_SOCKS[$k]:+${I_SOCKS[$k]} }$l"
      SOCK2KEY[$(norm_listen "$l")]=$k
      [ -n "$u" ] && POOL_USERS="$POOL_USERS $u"
    done < <(fpm_listens "${I_CONF[$k]}")
  done
}

key_for_branch() {   # instalación de una rama (prefiere la que tiene FPM)
  local k best=""
  for k in "${INST_KEYS[@]}"; do
    [ "${I_BR[$k]}" = "$1" ] || continue
    [ -n "${I_FPM[$k]:-}" ] && { echo "$k"; return; }
    [ -z "$best" ] && best=$k
  done
  echo "$best"
}

# ------------------------------------------------------- servidores web
detect_web() {
  WEB=(); local i
  NGINX_BIN=$(command -v nginx 2>/dev/null)
  APACHE_CTL=""; for i in apache2ctl apachectl; do have $i && { APACHE_CTL=$(command -v $i); break; }; done
  [ -z "$APACHE_CTL" ] && have httpd && APACHE_CTL=$(command -v httpd)
  declare -gA WEB_RUN=()
  for i in "${!P_COMM[@]}"; do
    case ${P_COMM[$i]} in
      nginx) WEB_RUN[nginx]=1 ;; apache2|httpd) WEB_RUN[apache]=1 ;;
      litespeed|lshttpd|openlitespeed) WEB_RUN[litespeed]=1 ;; caddy) WEB_RUN[caddy]=1 ;; lighttpd) WEB_RUN[lighttpd]=1 ;;
    esac
  done
  [ -n "$NGINX_BIN" ] && WEB+=(nginx)
  [ -n "$APACHE_CTL" ] && WEB+=(apache)
  [ -d /usr/local/lsws ] && WEB+=(litespeed)
  have caddy && WEB+=(caddy)
  have lighttpd && WEB+=(lighttpd)
}

parse_sites() {   # SITE_*: servidor, archivo, nombres, raíz, handler crudo
  SITE_SRV=(); SITE_FILE=(); SITE_NAMES=(); SITE_ROOTS=(); SITE_HRAW=(); SITE_KEY=(); SITE_HOW=(); SITE_PORTS=()
  declare -gA NG_UP=() NG_UPFILE=()
  APACHE_MODS=""; APACHE_GLOBAL_H=""; APACHE_GLOBAL_FILE=""; APACHE_MODPHP=0
  local t f names roots pass name addr hs mods lports
  if [ -n "$NGINX_BIN" ]; then
    while IFS=$'\t' read -r t f names roots pass lports; do
      case $t in
        UP) NG_UP[$f]=$names; NG_UPFILE[$f]=$roots ;;
        SITE) [ "$names" = "-" ] && names=""; [ "$roots" = "-" ] && roots=""; [ "$pass" = "-" ] && pass=""
              SITE_SRV+=(nginx); SITE_FILE+=("$f"); SITE_NAMES+=("$(uniqw "$names")")
              SITE_ROOTS+=("$(uniqw "$roots")"); SITE_HRAW+=("$(trimw "$pass")"); [ "$lports" = "-" ] && lports=""; SITE_PORTS+=("$(uniqw "$lports")") ;;
      esac
    done < <(timeout 30 "$NGINX_BIN" -T 2>/dev/null | awk '
      /^# configuration file / { f=$4; sub(/:$/,"",f); next }
      { l=$0; sub(/#.*/,"",l); gsub(/;/," ; ",l) }
      l ~ /^[ \t]*upstream[ \t]/ { split(l,a," "); up=a[2]; sub(/{.*/,"",up); next }
      up!="" && l ~ /^[ \t]*server[ \t]/ { split(l,a," "); print "UP\t" up "\t" a[2] "\t" f }
      up!="" && l ~ /}/ { up=""; next }
      l ~ /^[ \t]*server_name[ \t]/ { n=l; sub(/^[ \t]*server_name[ \t]+/,"",n); sub(/[ \t]*;.*/,"",n); names[f]=names[f] " " n; seen[f]=1 }
      l ~ /^[ \t]*root[ \t]/ { r=l; sub(/^[ \t]*root[ \t]+/,"",r); sub(/[ \t]*;.*/,"",r); if (index(roots[f], r)==0) roots[f]=roots[f] " " r }
      l ~ /^[ \t]*listen[ \t]/ { split(l,a," "); pt=a[2]; sub(/.*:/,"",pt); if (pt ~ /^[0-9]+$/) { if (l ~ /[ \t]ssl/ || pt=="443") pt=pt "s"; if (index(ports[f]," " pt)==0) ports[f]=ports[f] " " pt } }
      l ~ /fastcgi_pass[ \t]/ { p=l; sub(/.*fastcgi_pass[ \t]+/,"",p); sub(/[ \t]*;.*/,"",p); if (index(pass[f], p)==0) pass[f]=pass[f] " " p; seen[f]=1 }
      END { for (k in seen) print "SITE\t" k "\t" (names[k]==""?"-":names[k]) "\t" (roots[k]==""?"-":roots[k]) "\t" (pass[k]==""?"-":pass[k]) "\t" (ports[k]==""?"-":ports[k]) }')
  fi
  if [ -n "$APACHE_CTL" ]; then
    APACHE_MODS=$(timeout 20 "$APACHE_CTL" -M 2>/dev/null | awk '{print $1}' | tr '\n' ' ')
    [[ " $APACHE_MODS " =~ \ php[0-9]*_module\  ]] && APACHE_MODPHP=1
    while read -r f; do
      [ -f "$f" ] || continue
      IFS=$'\t' read -r names roots hs mods lports < <(awk '
        { l=$0; sub(/^[ \t]+/,"",l); if (l ~ /^#/) next; ll=tolower(l) }
        ll ~ /^servername[ \t]/ { split(l,a,/[ \t]+/); n=n " " a[2] }
        ll ~ /^serveralias[ \t]/ { c=split(l,a,/[ \t]+/); for(i=2;i<=c;i++) n=n " " a[i] }
        ll ~ /^documentroot[ \t]/ { r=l; sub(/^[^ \t]+[ \t]+/,"",r); gsub(/"/,"",r); if (index(rs,r)==0) rs=rs " " r }
        ll ~ /sethandler[ \t].*proxy:/ { h=l; sub(/.*proxy:/,"proxy:",h); gsub(/"/,"",h); sub(/[ \t].*/,"",h); if (index(hs,h)==0) hs=hs " " h }
        ll ~ /proxypassmatch.*fcgi:\/\// { h=l; sub(/.*fcgi:\/\//,"fcgi://",h); sub(/[ \t].*/,"",h); if (index(hs,h)==0) hs=hs " " h }
        ll ~ /^loadmodule[ \t]+php/ { split(l,a,/[ \t]+/); m=m " " a[3] }
        ll ~ /^<virtualhost[ \t]/ { v=l; gsub(/[<>]/,"",v); c=split(v,a,/[ \t]+/); for(i=2;i<=c;i++){ pt=a[i]; sub(/.*:/,"",pt); if (pt ~ /^[0-9]+$/) cur=cur " " pt } }
        ll ~ /^sslengine[ \t]+on/ { ssl=1 }
        END { if (cur!="") { c=split(cur,a," "); for(i=1;i<=c;i++){ x=a[i]; if (ssl || x=="443") x=x "s"; if (index(ps," " x)==0) ps=ps " " x } }
              printf "%s\t%s\t%s\t%s\t%s\n", (n==""?"-":n), (rs==""?"-":rs), (hs==""?"-":hs), (m==""?"-":m), (ps==""?"-":ps) }' "$f")
      [ "$names" = "-" ] && names=""; [ "$roots" = "-" ] && roots=""; [ "$hs" = "-" ] && hs=""; [ "$mods" = "-" ] && mods=""; [ "$lports" = "-" ] && lports=""
      if [ -z "$names" ] && [ -n "$hs" ]; then APACHE_GLOBAL_H=$(trimw "$hs"); APACHE_GLOBAL_FILE=$f; continue; fi
      [ -n "$names" ] || continue
      SITE_SRV+=(apache); SITE_FILE+=("$f"); SITE_NAMES+=("$(uniqw "$names")")
      SITE_ROOTS+=("$(uniqw "$roots")"); SITE_HRAW+=("$(trimw "$hs")"); SITE_PORTS+=("$(uniqw "$lports")")
    done < <(timeout 20 "$APACHE_CTL" -t -D DUMP_INCLUDES 2>/dev/null | sed -nE 's/^[[:space:]]*\([0-9*]+\)[[:space:]]+(\/[^[:space:]]+).*/\1/p' | sort -u)
  fi
  if [ -d /usr/local/lsws ]; then
    local lsh; lsh=$(grep -hoE 'lsphp[0-9]+' /usr/local/lsws/conf/httpd_config.* 2>/dev/null | sort -u | tr '\n' ' ')
    SITE_SRV+=(litespeed); SITE_FILE+=("/usr/local/lsws/conf"); SITE_NAMES+=("(sitios de LiteSpeed)")
    SITE_ROOTS+=(""); SITE_HRAW+=("$lsh"); SITE_PORTS+=("")
  fi
  for f in /etc/caddy/Caddyfile /etc/caddy/*.caddy /etc/caddy/conf.d/*; do
    [ -f "$f" ] || continue
    hs=$(grep -hE '^[[:space:]]*php_fastcgi' "$f" | awk '{print $2}' | tr '\n' ' '); hs=$(trimw "$hs")
    [ -n "$hs" ] || continue
    SITE_SRV+=(caddy); SITE_FILE+=("$f"); SITE_NAMES+=("$(uniqw "$(grep -hE '^[^[:space:]#].*\{' "$f" | sed 's/{.*//' | tr ',\n' '  ')")")
    SITE_ROOTS+=("$(uniqw "$(grep -hE '^[[:space:]]*root' "$f" | awk '{print $NF}' | tr '\n' ' ')")"); SITE_HRAW+=("$hs"); SITE_PORTS+=("")
  done
}

resolve_handler() {   # $1 handler crudo -> clave de instalación (o vacío)
  local h=$1 n br
  [ -n "${NG_UP[$h]:-}" ] && h=${NG_UP[$h]}
  n=$(norm_listen "$h")
  [ -n "${SOCK2KEY[$n]:-}" ] && { echo "${SOCK2KEY[$n]}"; return; }
  br=$(guess_branch "$h"); [ -n "$br" ] && key_for_branch "$br"
}
resolve_sites() {
  local i h k how mk
  mk=""; for k in "${INST_KEYS[@]}"; do [ -n "${I_MOD[$k]:-}" ] && mk=$k; done
  for i in "${!SITE_SRV[@]}"; do
    h=${SITE_HRAW[$i]%% *}; k=""; how=""
    case ${SITE_SRV[$i]} in
      nginx) if [ -n "$h" ]; then k=$(resolve_handler "$h"); how="PHP-FPM ($h)"; else how="sin PHP (estático/proxy)"; fi ;;
      apache) if [ -n "$h" ]; then k=$(resolve_handler "$h"); how="PHP-FPM ($h)"
              elif [ -n "$APACHE_GLOBAL_H" ]; then k=$(resolve_handler "${APACHE_GLOBAL_H%% *}"); how="PHP-FPM global (${APACHE_GLOBAL_H%% *})"
              elif [ "$APACHE_MODPHP" -eq 1 ] && [ -n "$mk" ]; then k=$mk; how="mod_php"
              else how="sin handler PHP detectado"; fi ;;
      litespeed) k=$(key_for_branch "$(guess_branch "$h")"); how="LSAPI (${h:-lsphp})" ;;
      caddy) k=$(resolve_handler "$h"); how="PHP-FPM ($h)" ;;
    esac
    SITE_KEY[$i]=$k; SITE_HOW[$i]=$how
  done
}

full_discovery() {
  scan_procs; discover_installs; evaluate_installs; map_running; map_services
  map_fpm_sockets; detect_web; parse_sites; resolve_sites
}

status_label() {
  case $1 in PATCHED) printf '%sPARCHADO%s' "$G" "$N" ;; VULNERABLE) printf '%sVULNERABLE%s' "$R" "$N" ;;
             UNSUPPORTED) printf '%sSIN SOPORTE (vulnerable)%s' "$R" "$N" ;; *) printf 'DESCONOCIDO' ;; esac
}
src_label() {
  case $1 in
    distro) echo "repositorio oficial de la distro" ;; sury) echo "repo Sury (packages.sury.org)" ;;
    ondrej-ppa) echo "PPA de Ondřej Surý" ;; ubuntu-esm) echo "Ubuntu ESM/Pro" ;; local) echo "paquete sin repositorio activo" ;;
    remi) echo "repo Remi (modular)" ;; remi-scl) echo "repo Remi (SCL, en paralelo)" ;; cpanel) echo "cPanel EasyApache (ea-php)" ;;
    plesk) echo "Plesk" ;; cloudlinux) echo "CloudLinux alt-php" ;; litespeed) echo "LiteSpeed lsphp" ;;
    aapanel) echo "aaPanel (compilado)" ;; directadmin) echo "DirectAdmin CustomBuild" ;; cwp) echo "CWP (compilado)" ;;
    manual) echo "compilado o instalado a mano" ;; *) echo "$1" ;;
  esac
}

# ----------------------------------------------------------- chequeo HTTP
declare -A HEALTH_BEFORE=() HEALTH_AFTER=()
health_targets() {   # "nombre puerto[s]" por sitio PHP (máximo 20)
  local i n p c=0 sel="${1:-}"; local -a nn pp
  for i in "${!SITE_SRV[@]}"; do
    [ -n "${SITE_KEY[$i]:-}" ] || continue
    [ -n "$sel" ] && [[ " $sel " != *" $i "* ]] && continue
    read -ra nn <<< "${SITE_NAMES[$i]}"
    for n in "${nn[@]}"; do
      case $n in _|localhost|"*"*|"~"*|*'$'*|"("*|default*) continue ;; esac
      [[ $n == *.* ]] || continue
      read -ra pp <<< "${SITE_PORTS[$i]:-}"
      [ ${#pp[@]} -gt 0 ] || { pp=(80); [[ " $PORTS " == *" 443 "* ]] && pp+=(443s); }
      for p in "${pp[@]}"; do [[ " $PORTS " == *" ${p%s} "* ]] && echo "$n $p"; done
      c=$((c+1)); break
    done
    [ $c -ge 20 ] && break
  done | sort -u
}
http_code() {   # $1 dominio $2 puerto (sufijo s = https)
  local port=${2%s} sch=http; [[ $2 == *s ]] && sch=https
  curl -sk -o /dev/null -m 10 -w '%{http_code}' --resolve "$1:$port:127.0.0.1" "$sch://$1:$port/" 2>/dev/null || echo 000
}
health_snapshot() {   # $1 = before|after  [$2 = índices de sitios]
  have curl || return 0
  local n p
  while read -r n p; do
    [ -n "$n" ] || continue
    if [ "$1" = before ]; then HEALTH_BEFORE["$n:$p"]=$(http_code "$n" "$p"); else HEALTH_AFTER["$n:$p"]=$(http_code "$n" "$p"); fi
  done < <(health_targets "${2:-}")
}
code_ok() { [[ $1 =~ ^(2..|3..|401|403|404)$ ]]; }
health_compare() {   # imprime resultado; devuelve 1 si hay regresión
  have curl || { info "curl no está instalado: se omite el chequeo HTTP."; return 0; }
  local t b a reg=0
  [ ${#HEALTH_BEFORE[@]} -eq 0 ] && { info "No hay dominios para el chequeo HTTP."; return 0; }
  for t in $(printf '%s\n' "${!HEALTH_BEFORE[@]}" | sort); do
    b=${HEALTH_BEFORE[$t]}; a=${HEALTH_AFTER[$t]:-000}
    if code_ok "$b" && ! code_ok "$a"; then bad "$t: antes $b, ahora $a"; reg=1
    else ok "$t: antes $b, ahora $a"; fi
  done
  return $reg
}

# ----------------------------------------------------------- respaldo
make_backup() {   # $1 tipo
  BK_ID="$STAMP-$1"; BK_DIR="$BACKUP_ROOT/$BK_ID"
  mkdir -p "$BK_DIR/files" || { bad "No se pudo crear $BK_DIR"; finish 3; }
  chmod 700 "$BACKUP_ROOT" "$BK_DIR"
  local p paths=()
  for p in /etc/php /etc/php.ini /etc/php.d /etc/php-fpm.conf /etc/php-fpm.d /etc/opt/remi /etc/php[0-9]* \
           /etc/apache2 /etc/httpd /etc/nginx /etc/caddy /usr/local/lsws/conf /opt/cpanel/ea-php*/root/etc; do
    [ -e "$p" ] && paths+=("$p")
  done
  [ ${#paths[@]} -gt 0 ] && tar czf "$BK_DIR/etc.tgz" "${paths[@]}" 2>/dev/null
  case $PKGTOOL in
    dpkg) dpkg-query -W -f='${Package}=${Version}\n' 2>/dev/null | grep -E '^(php|libapache2-mod-php|lsphp)' > "$BK_DIR/packages.txt" ;;
    rpm) rpm -qa --qf '%{NAME}=%{VERSION}-%{RELEASE}\n' 2>/dev/null | grep -E '^(php|ea-php|alt-php|lsphp|plesk-php|apache2-mod_php)' > "$BK_DIR/packages.txt" ;;
    apk) apk info -v 2>/dev/null | grep -E '^php' > "$BK_DIR/packages.txt" ;;
  esac
  printf 'MODE\t%s\nDATE\t%s\nHOST\t%s\n' "$1" "$(date '+%F %T')" "$HOST" > "$BK_DIR/manifest"
  ok "Respaldo creado: $BK_DIR"
  alog "respaldo $BK_DIR"
}
backup_file() {   # copia un archivo al respaldo y lo registra
  local f dest; f=$(readlink -f "$1" 2>/dev/null || echo "$1"); dest="$BK_DIR/files$f"
  grep -qF "FILE${TAB}$f${TAB}" "$BK_DIR/manifest" 2>/dev/null && return 0
  mkdir -p "$(dirname "$dest")" && cp -p "$f" "$dest" && printf 'FILE\t%s\t%s\n' "$f" "$dest" >> "$BK_DIR/manifest"
}

# ----------------------------------------------------- servicios
svc_restart() {
  local u=${1%.service} verb=${2:-restart}
  if [ "$HAS_SYSTEMD" -eq 1 ]; then run_cmd systemctl "$verb" "$u"
  elif have rc-service; then run_cmd rc-service "$u" "$verb"
  elif [ -x "/etc/init.d/$u" ]; then run_cmd "/etc/init.d/$u" "$verb"
  elif have service; then run_cmd service "$u" "$verb"
  else return 1; fi
}
fpm_master_pid() {
  local i e
  for i in "${!P_PID[@]}"; do
    [[ ${P_COMM[$i]} == php-fpm* ]] || continue
    [[ $(proc_cmd "${P_PID[$i]}") == *"master process"* ]] || continue
    e=$(proc_exe "${P_PID[$i]}"); e=${e% (deleted)}
    case " ${I_BINS[$1]} " in *" $(readlink -f "$e" 2>/dev/null || echo "$e") "*) echo "${P_PID[$i]}"; return ;; esac
  done
}
apache_test() { timeout 30 "$APACHE_CTL" -t >/dev/null 2>&1; }
nginx_test() { timeout 30 "$NGINX_BIN" -t >/dev/null 2>&1; }
apache_reload() {
  if [ "$PANEL" = cpanel ] && [ -x /scripts/restartsrv_httpd ]; then run_cmd /scripts/restartsrv_httpd
  else svc_restart "$APACHE_SVC" "${1:-restart}" || run_cmd "$APACHE_CTL" -k graceful; fi
}
nginx_reload() { svc_restart nginx reload || run_cmd "$NGINX_BIN" -s reload; }

restart_php() {   # reinicia FPM/Apache/LiteSpeed de las instalaciones indicadas
  local k u pid done_u=" " ap=0 ls=0
  for k in "$@"; do
    if [ -n "${I_FPM[$k]:-}" ]; then
      if ! timeout 20 "${I_FPM[$k]}" -t >/dev/null 2>&1; then
        bad "La configuración de PHP-FPM ${I_BR[$k]} tiene errores: no se reinicia."
        timeout 20 "${I_FPM[$k]}" -t 2>&1 | tail -3 | sed 's/^/           /'; continue
      fi
      if [ -n "${I_SVCS[$k]:-}" ]; then
        for u in ${I_SVCS[$k]}; do
          [[ $done_u == *" $u "* ]] && continue; done_u="$done_u$u "
          svc_restart "$u" && ok "Servicio $u reiniciado" || bad "No se pudo reiniciar $u"
        done
      else
        pid=$(fpm_master_pid "$k")
        if [ -n "$pid" ]; then run_cmd kill -USR2 "$pid" && ok "PHP-FPM ${I_BR[$k]} recargado (USR2)"; fi
      fi
    fi
    [ -n "${I_MOD[$k]:-}" ] && ap=1
    [ "${I_SRC[$k]}" = litespeed ] && ls=1
  done
  if [ $ap -eq 1 ] && [ -n "$APACHE_CTL" ] && [ -n "${WEB_RUN[apache]:-}" ]; then
    if apache_test; then apache_reload && ok "Apache reiniciado (mod_php)"; else bad "apachectl -t falla: Apache no se reinicia."; fi
  fi
  if [ $ls -eq 1 ]; then
    if [ -x /usr/local/lsws/bin/lswsctrl ]; then run_cmd /usr/local/lsws/bin/lswsctrl restart; else svc_restart lsws; fi
  fi
  [ "$PANEL" = cpanel ] && [ -x /scripts/restartsrv_apache_php_fpm ] && run_cmd /scripts/restartsrv_apache_php_fpm
}

# --------------------------------------------- repositorios upstream
repo_has_upstream() {
  case $FAMILY in
    debian) grep -rqsE 'packages\.sury\.org|ondrej/php' /etc/apt/sources.list /etc/apt/sources.list.d/ ;;
    rhel) local r; for r in /etc/yum.repos.d/*remi*.repo; do [ -f "$r" ] && return 0; done; return 1 ;;
    *) return 1 ;;
  esac
}
add_upstream_repo() {
  repo_has_upstream && { ok "El repositorio upstream ya está configurado."; return 0; }
  case "$FAMILY:$OS_ID" in
    debian:ubuntu)
      run_sh "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common ca-certificates" &&
      run_sh "LC_ALL=C.UTF-8 add-apt-repository -y ppa:ondrej/php" && run_cmd apt-get update -qq ;;
    debian:debian|debian:raspbian)
      run_sh "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl" &&
      run_sh "curl -fsSLo /tmp/debsuryorg-archive-keyring.deb https://packages.sury.org/debsuryorg-archive-keyring.deb && dpkg -i /tmp/debsuryorg-archive-keyring.deb" &&
      run_sh "echo 'deb [signed-by=/usr/share/keyrings/deb.sury.org-php.gpg] https://packages.sury.org/php/ $OS_CODENAME main' > /etc/apt/sources.list.d/php.list" &&
      run_cmd apt-get update -qq ;;
    rhel:almalinux|rhel:rocky|rhel:centos|rhel:ol|rhel:rhel)
      case $OS_MAJOR in 8|9|10) ;; *) bad "Remi no está disponible para esta versión ($OS_NAME)."; return 1 ;; esac
      if [ "$OS_ID" = rhel ]; then run_cmd $DNF install -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-$OS_MAJOR.noarch.rpm"
      elif [ "$OS_ID" = ol ]; then run_cmd $DNF install -y "oracle-epel-release-el$OS_MAJOR"
      else run_cmd $DNF install -y epel-release; fi
      run_cmd $DNF install -y "https://rpms.remirepo.net/enterprise/remi-release-$OS_MAJOR.rpm" ;;
    *) bad "No hay repositorio upstream automático para $OS_NAME."; return 1 ;;
  esac
}

# ===================================================================== DIAGNOSE
print_header() {
  printf '%sBitForce PHP Agent v%s  ·  modo: %s%s\n' "$B" "$AGENT_VERSION" "$MODE" "$N"
  echo "Servidor : $HOST"
  echo "Fecha    : $(date '+%F %T %Z')"
  echo "Sistema  : $OS_NAME  [familia: $FAMILY]"
  echo "Usuario  : $(id -un) (uid $(id -u))"
  echo "Reporte  : $TXT"
  [ "$(id -u)" -ne 0 ] && warn "Sin root: revisión de procesos, configuraciones web y archivos incompleta. Usa sudo."
}

print_system() {
  section "1. Plataforma"
  info "Panel         : ${PANEL_NAME:-ninguno detectado}$([ $CLOUDLINUX -eq 1 ] && echo ' + CloudLinux')"
  local w s=""; for w in "${WEB[@]}"; do s="$s $w$([ -n "${WEB_RUN[$w]:-}" ] && echo '(activo)' || echo '(instalado)')"; done
  info "Servidor web  :${s:- ninguno detectado}"
  info "Puertos       : ${PORTS:-ninguno} $( [[ " $PORTS " =~ \ (80|443)\  ]] && echo '-> expuesto a la web')"
  info "Init          : $([ "$HAS_SYSTEMD" -eq 1 ] && echo systemd || echo 'sin systemd (init.d/openrc)')"
}

print_installs() {
  section "2. Instalaciones de PHP"
  if [ ${#INST_KEYS[@]} -eq 0 ]; then ok "No se encontró PHP en este servidor."; return; fi
  local k used i
  for k in "${INST_KEYS[@]}"; do
    used=0; for i in "${!SITE_KEY[@]}"; do [ "${SITE_KEY[$i]}" = "$k" ] && used=$((used+1)); done
    subhead "PHP ${I_BR[$k]}  ·  ${I_VER[$k]}  ·  $(status_label "${I_STATUS[$k]}")"
    info "Origen      : $(src_label "${I_SRC[$k]}")"
    [ -n "${I_PKG[$k]:-}" ] && info "Paquete     : ${I_PKG[$k]} ${I_PKGVER[$k]}"
    info "Componentes : ${I_KINDS[$k]// /, }"
    info "Binarios    : ${I_BINS[$k]}"
    [ -n "${I_SVCS[$k]:-}" ] && info "Servicios   : ${I_SVCS[$k]}"
    [ -n "${I_SOCKS[$k]:-}" ] && info "Escucha en  : ${I_SOCKS[$k]}"
    info "Sitios      : $used  ·  procesos activos: $(wc -w <<< "${I_RUN[$k]:-}")"
    local eol=${EOL[${I_BR[$k]}]:-}; info "Soporte     : hasta ${eol:-?}$([[ -n $eol && $eol < $(date +%F) ]] && echo '  (vencido)')"
    info "Estado      : ${I_WHY[$k]}"
    if [ "${I_STALE[$k]}" = 1 ]; then
      bad "Hay procesos que siguen usando el binario anterior: falta reiniciar."
      NEEDS_ACTION=1; SUMMARY+=("PHP ${I_BR[$k]}: reinicio pendiente")
    fi
    case ${I_STATUS[$k]} in
      VULNERABLE) NEEDS_ACTION=1; SUMMARY+=("PHP ${I_BR[$k]} (${I_VER[$k]}): VULNERABLE") ;;
      UNSUPPORTED) NEEDS_ACTION=1; SUMMARY+=("PHP ${I_BR[$k]} (${I_VER[$k]}): rama sin soporte, VULNERABLE") ;;
    esac
    [ "${I_BR[$k]}" = 8.2 ] && [ "${I_STATUS[$k]}" = PATCHED ] && [ "$used" -gt 0 ] && \
      RECS+=("PHP 8.2 deja de recibir parches el 2026-12-31: planifica el cambio de rama (plan --from 8.2 --to $RECOMMENDED_TARGET)")
  done
}

print_sites() {
  section "3. Cómo se sirve PHP (sitio -> versión)"
  [ -n "$APACHE_CTL" ] && info "Apache: mod_php $([ "$APACHE_MODPHP" -eq 1 ] && echo cargado || echo 'no cargado')$([ -n "$APACHE_GLOBAL_H" ] && echo "; handler FPM global: $APACHE_GLOBAL_H ($APACHE_GLOBAL_FILE)")"
  if [ ${#SITE_SRV[@]} -eq 0 ]; then info "No se encontraron sitios configurados."; return; fi
  local i k label nophp=0
  for i in "${!SITE_SRV[@]}"; do
    k=${SITE_KEY[$i]}
    if [ -z "$k" ]; then
      case ${SITE_HOW[$i]} in sin*) nophp=$((nophp+1)); continue ;; esac
      label="versión no identificada"
    else label="PHP ${I_BR[$k]} $(status_label "${I_STATUS[$k]}")"; fi
    printf '  - %-9s %s\n' "${SITE_SRV[$i]}" "${SITE_NAMES[$i]:-(sin nombre / compartido)}"
    info "-> $label  vía ${SITE_HOW[$i]}"
    info "   config: ${SITE_FILE[$i]}${SITE_ROOTS[$i]:+   raíz: ${SITE_ROOTS[$i]}}"
  done
  [ $nophp -gt 0 ] && info "Además hay $nophp configuraciones sin PHP (estáticas o proxy inverso)."
}

print_autoupdates() {
  section "4. Actualizaciones automáticas"
  case $FAMILY in
    debian)
      if { [ "$HAS_SYSTEMD" -eq 1 ] && systemctl is-enabled unattended-upgrades >/dev/null 2>&1; } || \
         grep -qs 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/*; then
        ok "unattended-upgrades activo (solo repos configurados en Origins-Pattern)."
        if repo_has_upstream && ! grep -qsiE 'sury|ondrej' /etc/apt/apt.conf.d/50unattended-upgrades; then
          warn "Usas Sury/Ondřej pero ese origen no está en Origins-Pattern: PHP no se actualiza solo."
        fi
      else warn "unattended-upgrades no está activo: los parches no se aplican solos."; fi ;;
    rhel)
      if [ "$HAS_SYSTEMD" -eq 1 ] && systemctl is-enabled dnf-automatic-install.timer >/dev/null 2>&1; then ok "dnf-automatic (instalación) activo."
      elif [ "$HAS_SYSTEMD" -eq 1 ] && systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1 && grep -qsE '^apply_updates[[:space:]]*=[[:space:]]*yes' /etc/dnf/automatic.conf; then ok "dnf-automatic activo con apply_updates = yes."
      elif [ "$HAS_SYSTEMD" -eq 1 ] && systemctl is-enabled yum-cron >/dev/null 2>&1; then ok "yum-cron activo."
      else warn "No hay actualizaciones automáticas (dnf-automatic / yum-cron)."; fi ;;
    *) info "Revisa manualmente la política de actualizaciones de $OS_NAME." ;;
  esac
  [ -n "$PANEL" ] && info "Panel $PANEL_NAME: revisa su propia configuración de actualizaciones."
}

CONTAINERS=()
check_docker() {
  section "5. Contenedores"
  if ! have docker; then info "Docker no está instalado."; return; fi
  if ! docker info >/dev/null 2>&1; then warn "Docker está instalado pero el servicio no responde (o falta permiso)."; return; fi
  local name image v br st found=0
  while IFS=$'\t' read -r name image; do
    v=$(timeout 15 docker exec "$name" sh -c 'php -r "echo PHP_VERSION;" 2>/dev/null || php-fpm -v 2>/dev/null | head -1' 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -n "$v" ] || continue
    found=1; br=$(branch_of "$v")
    if [ -n "${FIXED[$br]:-}" ] && ver_ge "$v" "${FIXED[$br]}"; then st=PATCHED; ok "$name ($image): PHP $v"
    else st=VULNERABLE; bad "$name ($image): PHP $v VULNERABLE"; NEEDS_ACTION=1; SUMMARY+=("Contenedor $name: PHP $v VULNERABLE"); fi
    CONTAINERS+=("$name|$image|$v|$st")
  done < <(docker ps --format '{{.Names}}\t{{.Image}}' 2>/dev/null)
  [ $found -eq 0 ] && ok "Ningún contenedor en ejecución con PHP."
  [ $found -eq 1 ] && info "Los contenedores se parchean actualizando la imagen: docker compose pull && docker compose up -d (o reconstruyendo el Dockerfile)."
}

web_users() {
  local u; for u in www-data apache nginx http nobody lighttpd caddy wwwrun lsadm $POOL_USERS; do
    grep -q "^$u:" /etc/passwd 2>/dev/null && echo "$u"
  done | sort -u
}
ioc_add() { IOC_FINDINGS+=("$1"); }
check_ioc() {
  section "6. Indicadores de compromiso (desde $SINCE · archivos de los últimos $DAYS días)"
  if [ "$NO_IOC" -eq 1 ]; then info "Omitido (--no-ioc)."; return; fi
  local out roots=() r d i uids="" u list

  if have journalctl; then
    out=$(timeout 60 journalctl --since "$SINCE" --no-pager 2>/dev/null | grep -iE 'php|lsphp' | grep -iE 'segfault|SIGSEGV|signal 11|signal 6|core dumped' | tail -15)
  fi
  out="$out$(grep -hiE 'SIGSEGV|signal 11|core dumped' /var/log/php*fpm*.log /var/log/php-fpm/*.log /var/opt/remi/php*/log/php-fpm/*.log 2>/dev/null | tail -10)"
  if [ -n "$out" ]; then
    warn "Caídas de PHP (segfault) desde $SINCE:"; echo "$out" | head -15 | sed 's/^/           /'
    SUSPICIOUS=1; ioc_add "Caídas de PHP (segfault) en logs"
  else ok "Sin caídas de PHP (segfault) en logs."; fi

  for i in "${!SITE_ROOTS[@]}"; do for r in ${SITE_ROOTS[$i]}; do roots+=("$r"); done; done
  roots+=("${WEBROOTS[@]}" /var/www /srv/www /usr/share/nginx/html /www/wwwroot)
  for d in /home/*/public_html /home/*/htdocs /var/www/vhosts; do roots+=("$d"); done
  list=$(for r in "${roots[@]}"; do r=${r%/}; [ -d "$r" ] && echo "$r"; done | sort -u | awk 'NR==1{p=$0; print; next} index($0, p"/")!=1 {p=$0; print}')
  [ -z "$list" ] && info "No se encontraron raíces web para revisar."
  while read -r r; do
    [ -n "$r" ] || continue
    subhead "Raíz web: $r"
    out=$(timeout 120 find "$r" -xdev -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.php[0-9]' \) -mtime -"$DAYS" 2>/dev/null | head -30)
    if [ -n "$out" ]; then warn "PHP modificados en los últimos $DAYS días (¿despliegues propios?):"; echo "$out" | sed 's/^/           /'
    else ok "Ningún archivo PHP modificado en los últimos $DAYS días."; fi
    out=$(timeout 300 find "$r" -xdev -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.php[0-9]' -o -name '*.inc' \) -size -2M -print0 2>/dev/null | \
          xargs -0 -r grep -lE 'eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13)|assert[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE)|(system|shell_exec|passthru|popen|proc_open)[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE|SERVER)|preg_replace[[:space:]]*\(.*/e["'"'"']|\$_(POST|GET|REQUEST|COOKIE)\[[^]]+\][[:space:]]*\(' 2>/dev/null | head -30)
    if [ -n "$out" ]; then bad "Archivos con patrones de webshell:"; echo "$out" | sed 's/^/           /'
      SUSPICIOUS=1; ioc_add "Posibles webshells en $r"
    else ok "Sin patrones típicos de webshell."; fi
    out=$(timeout 120 find "$r" -xdev -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.php[0-9]' -o -iname '*.phar' \) \
          \( -ipath "$r/*upload*" -o -ipath "$r/*/files/*" -o -ipath "$r/*/images/*" -o -ipath "$r/*/img/*" \) 2>/dev/null | grep -vE '/(vendor|node_modules)/' | head -20)
    if [ -n "$out" ]; then warn "Archivos PHP dentro de carpetas de subida o imágenes:"; echo "$out" | sed 's/^/           /'
      SUSPICIOUS=1; ioc_add "PHP en carpetas de subida de $r"
    else ok "Sin PHP en carpetas de subida o imágenes."; fi
  done <<< "$list"

  subhead "Usuarios web: $(web_users | xargs)"
  for u in $(web_users); do uids="$uids $(id -u "$u" 2>/dev/null)"; done
  out=""
  for i in "${!P_PID[@]}"; do
    [[ " $uids " == *" ${P_UID[$i]} "* ]] || continue
    case ${P_COMM[$i]} in php*|lsphp*|apache2|httpd|nginx|litespeed|lshttpd|caddy|lighttpd|sendmail|postdrop|crond|sh|bash) continue ;; esac
    local e; e=$(proc_exe "${P_PID[$i]}")
    out="$out${P_PID[$i]} ${P_COMM[$i]} $e"$'\n'
    if [[ ${P_COMM[$i]} =~ ^(nc|ncat|netcat|socat|xmrig|kinsing|kdevtmpfsi|minerd|perl|python[0-9.]*)$ ]] || [[ $e =~ ^/(tmp|var/tmp|dev/shm)/ ]] || [[ $e == *"(deleted)" ]]; then
      SUSPICIOUS=1; ioc_add "Proceso sospechoso del usuario web: ${P_COMM[$i]} ($e)"
    fi
  done
  if [ -n "$out" ]; then warn "Procesos de usuarios web que no son PHP ni servidor web:"; printf '%s' "$out" | head -15 | sed 's/^/           /'
  else ok "Sin procesos inusuales de usuarios web."; fi
  out=""
  for u in $(web_users); do
    [ "$u" = nobody ] && continue
    local cr; cr=$(crontab -l -u "$u" 2>/dev/null | grep -vE '^[[:space:]]*(#|$)')
    [ -n "$cr" ] && out="$out$u: $cr"$'\n'
  done
  if [ -n "$out" ]; then warn "Tareas cron de usuarios web (verifica que sean legítimas):"; printf '%s' "$out" | head -10 | sed 's/^/           /'
  else ok "Usuarios web sin tareas cron."; fi
  out=""
  for u in $(web_users); do out="$out$(find /tmp /var/tmp /dev/shm -xdev -user "$u" -type f \( -perm -u+x -o -name '*.php' -o -name '*.sh' \) 2>/dev/null | head -10)"; done
  if [ -n "$out" ]; then bad "Ejecutables o scripts de usuarios web en /tmp, /var/tmp o /dev/shm:"; echo "$out" | sed 's/^/           /'
    SUSPICIOUS=1; ioc_add "Ejecutables de usuario web en directorios temporales"
  else ok "Sin ejecutables de usuarios web en directorios temporales."; fi
}

build_recommendations() {
  local k used i have_pkg=0 have_stale=0 have_unsup="" own=0
  for k in "${INST_KEYS[@]}"; do
    used=0; for i in "${!SITE_KEY[@]}"; do [ "${SITE_KEY[$i]}" = "$k" ] && used=1; done
    case ${I_STATUS[$k]} in
      VULNERABLE|UNSUPPORTED)
        case ${I_SRC[$k]} in
          manual) RECS+=("PHP ${I_BR[$k]} está compilado a mano: recompila con la versión ${FIXED[${I_BR[$k]}]:-de una rama soportada} usando el mismo ./configure (php -i | grep 'Configure Command')") ;;
          plesk|aapanel|directadmin|cwp) own=1 ;;
          *) have_pkg=1 ;;
        esac
        [ "${I_STATUS[$k]}" = UNSUPPORTED ] && [ $used -eq 1 ] && have_unsup="$have_unsup ${I_BR[$k]}" ;;
    esac
    [ "${I_STALE[$k]}" = 1 ] && have_stale=1
    [ "${I_STATUS[$k]}" = UNSUPPORTED ] && [ $used -eq 0 ] && RECS+=("PHP ${I_BR[$k]} no lo usa ningún sitio detectado: considera desinstalarlo")
  done
  if [ $have_pkg -eq 1 ]; then RECS=("Aplicar el parche en la misma rama:  sudo bash $(basename "$0") fix" "${RECS[@]}")
  elif [ $have_stale -eq 1 ]; then RECS=("Reiniciar PHP para cargar el parche ya instalado:  sudo bash $(basename "$0") fix" "${RECS[@]}"); fi
  for br in $have_unsup; do RECS+=("PHP $br no recibirá este parche (salvo backport de la distro): sudo bash $(basename "$0") plan --from $br --to $RECOMMENDED_TARGET"); done
  [ $own -eq 1 ] && RECS+=("Actualizar PHP desde el panel $PANEL_NAME (ver instrucciones en el modo fix)")
  [ ${#IOC_FINDINGS[@]} -gt 0 ] && RECS=("Investigar los indicadores de compromiso ANTES de parchear: copia los archivos sospechosos y logs, aísla el sitio y rota credenciales" "${RECS[@]}")
}

print_verdict() {
  section "VEREDICTO"
  local r
  if [ $SUSPICIOUS -eq 1 ]; then bad "INDICADORES SOSPECHOSOS: revisar antes de dar el servidor por seguro."; EXIT_CODE=2
  elif [ $NEEDS_ACTION -eq 1 ]; then bad "REQUIERE ACCIÓN."; EXIT_CODE=1
  else ok "Sin instalaciones vulnerables ni indicadores de compromiso."; EXIT_CODE=0; fi
  for r in "${SUMMARY[@]}" "${IOC_FINDINGS[@]}"; do info "- $r"; done
  if [ ${#RECS[@]} -gt 0 ]; then subhead "Siguientes pasos"; for r in "${RECS[@]}"; do info "* $r"; done; fi
}

# ---------------------------------------------------------------- JSON
jesc() { local s=$1; s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\t'/\\t}; s=${s//$'\r'/}; s=${s//$'\n'/\\n}; printf '"%s"' "$s"; }
jarr() { local f=1 x; printf '['; for x in "$@"; do [ $f -eq 1 ] || printf ','; f=0; jesc "$x"; done; printf ']'; }
write_json() {
  local k i f=1 x
  {
    printf '{"agent":"bitforce-php-agent","agent_version":%s,"mode":%s,"host":%s,"date":%s,' \
      "$(jesc "$AGENT_VERSION")" "$(jesc "$MODE")" "$(jesc "$HOST")" "$(jesc "$(date '+%FT%T%z')")"
    printf '"os":{"id":%s,"name":%s,"version":%s,"family":%s},"panel":%s,"web_servers":%s,"listening_ports":[%s],' \
      "$(jesc "${OS_ID:-}")" "$(jesc "${OS_NAME:-}")" "$(jesc "${OS_VER:-}")" "$(jesc "${FAMILY:-}")" "$(jesc "${PANEL:-}")" \
      "$(jarr "${WEB[@]}")" "$(echo ${PORTS:-} | tr ' ' ',')"
    printf '"installations":['
    for k in "${INST_KEYS[@]}"; do
      [ $f -eq 1 ] || printf ','; f=0
      printf '{"branch":%s,"version":%s,"source":%s,"package":%s,"package_version":%s,"status":%s,"reason":%s,"eol":%s,"restart_pending":%s,"services":%s,"listen":%s,"binaries":%s}' \
        "$(jesc "${I_BR[$k]}")" "$(jesc "${I_VER[$k]}")" "$(jesc "${I_SRC[$k]}")" "$(jesc "${I_PKG[$k]:-}")" "$(jesc "${I_PKGVER[$k]:-}")" \
        "$(jesc "${I_STATUS[$k]}")" "$(jesc "${I_WHY[$k]}")" "$(jesc "${EOL[${I_BR[$k]}]:-}")" "$([ "${I_STALE[$k]}" = 1 ] && echo true || echo false)" \
        "$(jarr ${I_SVCS[$k]:-})" "$(jarr ${I_SOCKS[$k]:-})" "$(jarr ${I_BINS[$k]})"
    done
    printf '],"sites":['; f=1
    for i in "${!SITE_SRV[@]}"; do
      k=${SITE_KEY[$i]:-}
      [ -z "$k" ] && [[ ${SITE_HOW[$i]:-} == sin* ]] && continue
      [ $f -eq 1 ] || printf ','; f=0
      printf '{"server":%s,"names":%s,"config":%s,"docroot":%s,"handler":%s,"php_branch":%s,"php_status":%s}' \
        "$(jesc "${SITE_SRV[$i]}")" "$(jesc "${SITE_NAMES[$i]}")" "$(jesc "${SITE_FILE[$i]}")" "$(jesc "${SITE_ROOTS[$i]}")" \
        "$(jesc "${SITE_HOW[$i]:-}")" "$(jesc "${I_BR[$k]:-}")" "$(jesc "${I_STATUS[$k]:-}")"
    done
    printf '],"containers":['; f=1
    for x in "${CONTAINERS[@]}"; do
      IFS='|' read -r a b c d <<< "$x"; [ $f -eq 1 ] || printf ','; f=0
      printf '{"name":%s,"image":%s,"php_version":%s,"status":%s}' "$(jesc "$a")" "$(jesc "$b")" "$(jesc "$c")" "$(jesc "$d")"
    done
    printf '],"ioc":{"suspicious":%s,"findings":%s},' "$([ $SUSPICIOUS -eq 1 ] && echo true || echo false)" "$(jarr "${IOC_FINDINGS[@]}")"
    printf '"actions":%s,"recommendations":%s,"summary":%s,"backup":%s,"verdict":%s,"exit_code":%d}\n' \
      "$(jarr "${ACTIONS[@]}")" "$(jarr "${RECS[@]}")" "$(jarr "${SUMMARY[@]}")" "$(jesc "${BK_DIR:-}")" \
      "$(jesc "$(case ${EXIT_CODE:-3} in 0) echo OK ;; 1) echo ACTION_REQUIRED ;; 2) echo SUSPICIOUS ;; *) echo ERROR ;; esac)")" "${EXIT_CODE:-3}"
  } > "$JSON" 2>/dev/null
}

finish() {
  EXIT_CODE=${1:-${EXIT_CODE:-0}}
  write_json
  echo; echo "Reporte: $TXT"; echo "JSON   : $JSON"
  sleep 0.5
  exit "$EXIT_CODE"
}

do_diagnose() {
  print_system; print_installs; print_sites; print_autoupdates; check_docker; check_ioc
  build_recommendations; print_verdict
}

# ========================================================================= FIX
fix_packages_for() {   # paquetes o patrones a actualizar para una instalación
  local k=$1 br=${I_BR[$1]} xy src=${I_SRC[$1]}
  xy=$(xy_of "$br")
  case $FAMILY in
    debian) case $src in litespeed) installed_pkgs_matching "^lsphp$xy(-|$)" ;;
            *) installed_pkgs_matching "^(php$br(-|$)|libapache2-mod-php$br$)" ;; esac ;;
    rhel) case $src in   # nombres exactos instalados (dnf falla con patrones que no coinciden)
            remi-scl) installed_pkgs_matching "^php$xy-" ;; cpanel) installed_pkgs_matching "^ea-php$xy(-|$)" ;;
            cloudlinux) installed_pkgs_matching "^alt-php$xy(-|$)" ;; litespeed) installed_pkgs_matching "^lsphp$xy(-|$)" ;;
            *) installed_pkgs_matching "^(php|php-.+)$" ;;
          esac ;;
    suse) installed_pkgs_matching "^(php[0-9]+|apache2-mod_php[0-9]+)(-|$)" ;;
    alpine) installed_pkgs_matching "^php$xy(-|$)" ;;
  esac
}
pkg_upgrade() {   # $@ paquetes
  case $FAMILY in
    debian) DEBIAN_FRONTEND=noninteractive run_cmd apt-get install --only-upgrade -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@" ;;
    rhel) run_cmd $DNF -y upgrade "$@" ;;
    suse) run_cmd zypper --non-interactive update "$@" ;;
    alpine) run_cmd apk upgrade "$@" ;;
  esac
}
pkg_refresh() {
  case $FAMILY in
    debian) run_cmd apt-get update -qq ;; rhel) run_cmd $DNF -q makecache ;;
    suse) run_cmd zypper --non-interactive refresh ;; alpine) run_cmd apk update ;;
  esac
}
dnf_last_tx() { $DNF history list 2>/dev/null | awk '$1 ~ /^[0-9]+$/ {print $1; exit}'; }

do_fix() {
  need_root; take_lock
  print_system; print_installs; print_sites
  section "PLAN DE ACTUALIZACIÓN (misma rama)"
  local k targets=() manual=() pk n=0 PKG_ARR=() tmpa=()
  for k in "${INST_KEYS[@]}"; do
    case ${I_STATUS[$k]} in VULNERABLE|UNSUPPORTED) ;; *)
      [ "${I_STALE[$k]}" = 1 ] && { targets+=("$k"); info "PHP ${I_BR[$k]}: el parche ya está instalado; solo falta reiniciar."; }
      continue ;; esac
    case ${I_SRC[$k]} in
      manual|plesk|aapanel|directadmin|cwp) manual+=("$k") ;;
      *) targets+=("$k"); mapfile -t tmpa < <(fix_packages_for "$k"); pk="${tmpa[*]}"
         [ ${#tmpa[@]} -gt 0 ] && { PKG_ARR+=("${tmpa[@]}"); n=$((n+1)); }
         info "PHP ${I_BR[$k]} (${I_VER[$k]}, $(src_label "${I_SRC[$k]}")) -> $pk"
         [ "${I_STATUS[$k]}" = UNSUPPORTED ] && warn "PHP ${I_BR[$k]} no tiene soporte upstream: solo se corregirá si la distro publicó un backport." ;;
    esac
  done
  for k in "${manual[@]}"; do
    warn "PHP ${I_BR[$k]} ($(src_label "${I_SRC[$k]}")) no se actualiza con el gestor de paquetes:"
    case ${I_SRC[$k]} in
      manual) info "Recompila PHP ${FIXED[${I_BR[$k]}]:-(rama soportada)} con el mismo ./configure:"; cmdl "${I_CLI[$k]:-php} -i | grep 'Configure Command'" ;;
      *) panel_howto ;;
    esac
    SUMMARY+=("PHP ${I_BR[$k]}: requiere actualización manual o por panel")
  done
  if [ ${#targets[@]} -eq 0 ]; then
    [ ${#manual[@]} -eq 0 ] && ok "No hay nada que actualizar: todas las instalaciones están parchadas."
    EXIT_CODE=$([ ${#manual[@]} -gt 0 ] && echo 1 || echo 0); finish "$EXIT_CODE"
  fi
  [ -n "$PANEL" ] && info "Panel detectado: $PANEL_NAME (los paquetes se actualizan con el gestor del sistema)."
  info "Se conservan tus php.ini y pools (si hay conflicto se mantiene tu versión)."
  confirm "¿Respaldar configuración, actualizar y reiniciar PHP ahora?" || { warn "Cancelado por el usuario."; finish 1; }

  section "EJECUCIÓN"
  make_backup fix
  health_snapshot before
  local tx_before=""; [ "$FAMILY" = rhel ] && tx_before=$(dnf_last_tx)
  [ ${#PKG_ARR[@]} -gt 0 ] && { pkg_refresh; pkg_upgrade "${PKG_ARR[@]}"; }
  [ "$FAMILY" = rhel ] && { local tx_after; tx_after=$(dnf_last_tx); [ -n "$tx_after" ] && [ "$tx_after" != "$tx_before" ] && printf 'DNFTX\t%s\n' "$tx_after" >> "$BK_DIR/manifest"; }

  full_discovery
  local still=() up=()
  for k in "${INST_KEYS[@]}"; do
    case ${I_STATUS[$k]} in VULNERABLE|UNSUPPORTED) case ${I_SRC[$k]} in distro|local) up+=("$k") ;; esac ;; esac
  done
  if [ ${#up[@]} -gt 0 ]; then
    for k in "${up[@]}"; do warn "PHP ${I_BR[$k]} sigue en ${I_VER[$k]}: el repositorio de la distro aún no publica el parche."; done
    if [ "$UPSTREAM" -eq 1 ]; then
      info "Se usará el repositorio upstream de la MISMA rama (Sury / PPA de Ondřej / Remi)."
      if add_upstream_repo; then
        if [ "$FAMILY" = rhel ]; then
          for k in "${up[@]}"; do
            [ -n "${FIXED[${I_BR[$k]}]:-}" ] || continue
            case $OS_MAJOR in 8|9) run_cmd $DNF -y module reset php && run_cmd $DNF -y module enable "php:remi-${I_BR[$k]}" ;; esac
            mapfile -t tmpa < <(fix_packages_for "$k"); [ ${#tmpa[@]} -gt 0 ] && pkg_upgrade "${tmpa[@]}"
          done
        else
          PKG_ARR=(); for k in "${up[@]}"; do mapfile -t tmpa < <(fix_packages_for "$k"); PKG_ARR+=("${tmpa[@]}"); done
          [ ${#PKG_ARR[@]} -gt 0 ] && pkg_upgrade "${PKG_ARR[@]}"
        fi
        full_discovery
      fi
    else
      info "Opciones: esperar el aviso de seguridad de la distro, o repetir con --upstream-repo"
      info "para tomar la versión corregida de la misma rama desde Sury, el PPA de Ondřej o Remi."
    fi
  fi

  section "REINICIO DE SERVICIOS"
  local rk=()
  for k in "${INST_KEYS[@]}"; do
    case ${I_SRC[$k]} in manual|plesk|aapanel|directadmin|cwp) continue ;; esac
    rk+=("$k")
  done
  restart_php "${rk[@]}"
  sleep 2; full_discovery

  section "VERIFICACIÓN"
  local fail=0
  for k in "${INST_KEYS[@]}"; do
    if [ "${I_STATUS[$k]}" = PATCHED ] && [ "${I_STALE[$k]}" != 1 ]; then ok "PHP ${I_BR[$k]}: ${I_VER[$k]} PARCHADO (${I_WHY[$k]})"
    elif [ "${I_STATUS[$k]}" = PATCHED ]; then bad "PHP ${I_BR[$k]}: paquete parchado pero hay procesos con el binario anterior"; fail=1
    else bad "PHP ${I_BR[$k]}: ${I_VER[$k]} $(status_label "${I_STATUS[$k]}")"; fail=1; still+=("$k"); fi
  done
  subhead "Chequeo HTTP antes / después"
  health_snapshot after
  if ! health_compare; then
    fail=1; bad "Algún sitio dejó de responder bien. Revisa los logs; para volver atrás:"
    cmdl "sudo bash $(basename "$0") rollback --backup $BK_ID"
  fi
  for k in "${still[@]}"; do SUMMARY+=("PHP ${I_BR[$k]} sigue ${I_STATUS[$k]}"); done
  [ ${#still[@]} -gt 0 ] && for k in "${still[@]}"; do
    [ "${I_STATUS[$k]}" = UNSUPPORTED ] && RECS+=("Cambiar de rama: sudo bash $(basename "$0") plan --from ${I_BR[$k]} --to $RECOMMENDED_TARGET")
  done
  RECS+=("Si algo falla: sudo bash $(basename "$0") rollback --backup $BK_ID")
  section "RESULTADO"
  if [ $fail -eq 0 ]; then ok "Actualización completada. Respaldo: $BK_DIR"; finish 0
  else bad "La actualización no quedó completa. Respaldo: $BK_DIR"; finish 1; fi
}

# ======================================================== PLAN (compatibilidad)
# formato: tipo~~versión~~severidad~~patrón~~descripción
RULES=(
"F~~7.0~~ROTO~~mysql_connect mysql_pconnect mysql_query mysql_fetch_array mysql_fetch_assoc mysql_fetch_row mysql_fetch_object mysql_select_db mysql_real_escape_string mysql_escape_string mysql_num_rows mysql_close mysql_error mysql_result mysql_insert_id mysql_affected_rows~~Extensión mysql_* eliminada en 7.0: migrar a mysqli o PDO"
"F~~7.0~~ROTO~~ereg eregi ereg_replace eregi_replace split spliti sql_regcase~~Funciones ereg/split eliminadas en 7.0: usar preg_*"
"R~~7.2~~ROTO~~(^|[^A-Za-z0-9_>:\$])mcrypt_[a-z_]+[[:space:]]*\(~~Extensión mcrypt eliminada en 7.2: usar openssl o sodium"
"F~~8.0~~ROTO~~each create_function money_format fgetss get_magic_quotes_gpc get_magic_quotes_runtime image2wbmp convert_cyr_string hebrevc restore_include_path ezmlm_send __autoload~~Funciones eliminadas en PHP 8.0"
"R~~8.0~~ROTO~~\\\$[A-Za-z_][A-Za-z0-9_]*\{[[:space:]]*(\\\$|[0-9]|'|\")~~Acceso a cadenas con llaves \$s{0} eliminado en 8.0: usar \$s[0]"
"R~~8.0~~ROTO~~\((real|unset)\)~~Casts (real) y (unset) eliminados en 8.0"
"R~~8.0~~ROTO~~(^|[^A-Za-z0-9_>:\$])xmlrpc_[a-z_]+[[:space:]]*\(~~Extensión xmlrpc fuera del núcleo desde 8.0 (PECL)"
"F~~8.1~~DEPRECADO~~strftime gmstrftime date_sunrise date_sunset mhash mhash_count mhash_get_block_size mhash_get_hash_name mhash_keygen_s2k odbc_result_all~~Funciones deprecadas en 8.1"
"R~~8.1~~DEPRECADO~~FILTER_SANITIZE_(STRING|STRIPPED)~~FILTER_SANITIZE_STRING deprecado en 8.1"
"F~~8.2~~DEPRECADO~~utf8_encode utf8_decode~~utf8_encode/utf8_decode deprecadas en 8.2: usar mb_convert_encoding"
"R~~8.2~~DEPRECADO~~\"[^\"]*\\\$\{[A-Za-z_]~~Interpolación \"\${var}\" deprecada en 8.2: usar {\$var}"
"R~~8.3~~DEPRECADO~~(^|[^A-Za-z0-9_>:\$])(get_class|get_parent_class)[[:space:]]*\([[:space:]]*\)~~get_class()/get_parent_class() sin argumentos deprecados en 8.3"
"F~~8.3~~DEPRECADO~~assert_options~~assert_options() deprecada en 8.3"
"R~~8.4~~DEPRECADO~~[(,][[:space:]]*[A-Za-z_\\][A-Za-z0-9_\\]*[[:space:]]+&?\\\$[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=[[:space:]]*null~~Tipos nulos implícitos (Tipo \$x = null) deprecados en 8.4: usar ?Tipo"
"R~~8.4~~DEPRECADO~~(^|[^A-Za-z0-9_])E_STRICT([^A-Za-z0-9_]|$)~~Constante E_STRICT deprecada en 8.4"
"R~~8.4~~DEPRECADO~~trigger_error[[:space:]]*\(.*E_USER_ERROR~~trigger_error() con E_USER_ERROR deprecado en 8.4: lanzar una excepción"
"F~~8.4~~DEPRECADO~~mysqli_ping mysqli_kill mysqli_refresh~~Funciones mysqli deprecadas en 8.4"
"R~~8.4~~ROTO~~(^|[^A-Za-z0-9_>:\$])(imap|pspell|oci)_[a-z_]+[[:space:]]*\(~~Extensiones imap/pspell/oci8 fuera del núcleo en 8.4: instalar desde PECL"
"R~~8.5~~DEPRECADO~~\((boolean|integer|double|binary)\)~~Casts no canónicos (boolean)/(integer)/(double)/(binary) deprecados en 8.5"
)
REMOVED_EXT=("mysql~~7.0" "mssql~~7.0" "ereg~~7.0" "mcrypt~~7.2" "wddx~~7.4" "recode~~7.4" "interbase~~7.4" "xmlrpc~~8.0" "imap~~8.4" "pspell~~8.4" "oci8~~8.4")

constraint_tok() {   # $1 token  $2 versión destino completa
  local tok=${1#v} T=$2 op v base hi major minor n
  tok=${tok%%@*}; [ -z "$tok" ] && return 0
  case $tok in '*'|x|X) return 0 ;; esac
  [[ $tok =~ ^(\^|~|>=|<=|>|<|==|=|!=)?v?([0-9]+(\.[0-9xX*]+)*)$ ]] || return 0
  op=${BASH_REMATCH[1]}; v=${BASH_REMATCH[2]}
  if [[ $v == *[xX*]* ]]; then base=${v%%.[xX*]*}; hi=$(bump_last "$base"); ver_ge "$T" "$base" && ver_lt "$T" "$hi"; return; fi
  IFS=. read -r major minor _ <<< "$v"; n=$(tr -cd . <<< "$v" | wc -c)
  case $op in
    '^') ver_ge "$T" "$v" && ver_lt "$T" "$((major+1))" ;;
    '~') if [ "$n" -le 1 ]; then ver_ge "$T" "$v" && ver_lt "$T" "$((major+1))"; else ver_ge "$T" "$v" && ver_lt "$T" "$major.$((minor+1))"; fi ;;
    '>=') ver_ge "$T" "$v" ;; '>') ver_gt "$T" "$v" ;; '<=') ver_ge "$v" "$T" ;; '<') ver_lt "$T" "$v" ;;
    '!=') [ "$T" != "$v" ] ;;
    *) [[ $T == "$v" || $T == "$v".* ]] ;;
  esac
}
constraint_allows() {   # ¿la restricción composer "php" acepta la rama destino?
  local c=$1 T=$2 alt tok okk; local -a alts toks
  c=${c//||/|}; IFS='|' read -ra alts <<< "$c"
  for alt in "${alts[@]}"; do
    alt=${alt//,/ }
    if [[ $alt =~ ^[[:space:]]*([0-9][0-9.]*)[[:space:]]+-[[:space:]]+([0-9][0-9.]*)[[:space:]]*$ ]]; then
      ver_ge "$T" "${BASH_REMATCH[1]}" && ver_lt "$T" "$(bump_last "${BASH_REMATCH[2]}")" && return 0; continue
    fi
    read -ra toks <<< "$alt"; okk=1
    for tok in "${toks[@]}"; do constraint_tok "$tok" "$T" || { okk=0; break; }; done
    [ $okk -eq 1 ] && return 0
  done
  return 1
}

detect_app() {   # define APP_KIND y APP_VER
  local d=$1; APP_KIND="PHP genérico"; APP_VER=""
  if [ -f "$d/wp-includes/version.php" ]; then APP_KIND=WordPress; APP_VER=$(sed -nE "s/^\\\$wp_version[[:space:]]*=[[:space:]]*'([^']+)'.*/\1/p" "$d/wp-includes/version.php")
  elif [ -f "$d/core/lib/Drupal.php" ]; then APP_KIND=Drupal; APP_VER=$(sed -nE "s/.*const VERSION = '([^']+)'.*/\1/p" "$d/core/lib/Drupal.php")
  elif [ -f "$d/libraries/src/Version.php" ] || [ -f "$d/administrator/manifests/files/joomla.xml" ]; then APP_KIND=Joomla; APP_VER=$(sed -nE 's/.*<version>([^<]+)<.*/\1/p' "$d/administrator/manifests/files/joomla.xml" 2>/dev/null | head -1)
  elif [ -f "$d/bin/magento" ]; then APP_KIND=Magento
  elif [ -f "$d/config/settings.inc.php" ] || { [ -f "$d/app/AppKernel.php" ] && grep -qs PrestaShop "$d/composer.json"; }; then APP_KIND=PrestaShop
  elif [ -f "$d/version.php" ] && grep -qs '\$release' "$d/version.php" && [ -d "$d/admin" ]; then APP_KIND=Moodle; APP_VER=$(sed -nE "s/^\\\$release[[:space:]]*=[[:space:]]*'([^ ']+).*/\1/p" "$d/version.php")
  elif [ -f "$d/artisan" ]; then APP_KIND=Laravel; APP_VER=$(grep -oE '"laravel/framework"[[:space:]]*:[[:space:]]*"[^"]+"' "$d/composer.json" 2>/dev/null | cut -d'"' -f4)
  elif [ -f "$d/bin/console" ] || [ -f "$d/symfony.lock" ]; then APP_KIND=Symfony
  elif [ -f "$d/system/CodeIgniter.php" ] || [ -d "$d/vendor/codeigniter4" ]; then APP_KIND=CodeIgniter
  elif [ -f "$d/composer.json" ]; then APP_KIND="PHP con Composer"; fi
}

app_dirs_for() {   # carpetas de aplicación de los sitios que usan la rama $1
  local br=$1 i r d
  { for d in "${APPS[@]}"; do echo "$d"; done
    if [ ${#APPS[@]} -eq 0 ]; then
      for i in "${!SITE_SRV[@]}"; do
        [ -n "${SITE_KEY[$i]}" ] && [ "${I_BR[${SITE_KEY[$i]}]}" = "$br" ] || continue
        for r in ${SITE_ROOTS[$i]}; do
          r=${r%/}; [ -d "$r" ] || continue
          case ${r##*/} in public|web|pub|htdocs|public_html) [ -f "${r%/*}/composer.json" ] && r=${r%/*} ;; esac
          echo "$r"
        done
      done
    fi
  } | sort -u | head -20
}

php_files() { find "$1" -xdev \( -name vendor -o -name node_modules -o -name .git -o -name cache -o -path '*/storage/framework' \) -prune -o \
               -type f \( -name '*.php' -o -name '*.inc' -o -name '*.phtml' -o -name '*.module' \) -print0 2>/dev/null; }

scan_app() {   # $1 dir  $2 origen  $3 destino  $4 binario destino (opcional)  -> APP_BLOCK APP_WARN
  local d=$1 S=$2 T=$3 tbin=${4:-} list r typ rv sev pat desc re excl hits cnt detail lock cons
  APP_BLOCK=0; APP_WARN=0
  detect_app "$d"
  subhead "Aplicación: $d"
  info "Tipo: $APP_KIND${APP_VER:+ $APP_VER}"
  list=$(mktemp); php_files "$d" > "$list"
  local nfiles; nfiles=$(tr -cd '\0' < "$list" | wc -c)
  info "Archivos PHP analizados (sin vendor/): $nfiles"
  detail="$BASE-compat-$(echo "$d" | tr '/' '_' | sed 's/^_//').txt"
  echo "Compatibilidad $S -> $T  ·  $d" > "$detail"

  if [ -f "$d/composer.json" ]; then
    cons=$(grep -A20 '"require"' "$d/composer.json" | grep -oE '"php"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | cut -d'"' -f4)
    if [ -n "$cons" ]; then
      if constraint_allows "$cons" "${FIXED[$T]:-$T.0}"; then ok "composer.json exige php \"$cons\": acepta $T"
      else bad "composer.json exige php \"$cons\": NO acepta $T"; APP_BLOCK=1; fi
    fi
  fi
  lock="$d/composer.lock"
  if [ -f "$lock" ]; then
    local cli=${tbin:-${I_CLI[$(key_for_branch "$S")]:-$(command -v php)}}
    if [ -n "$tbin" ] && have composer; then
      info "composer check-platform-reqs con PHP $T:"
      (cd "$d" && timeout 120 "$tbin" "$(command -v composer)" check-platform-reqs --no-interaction 2>&1) | grep -E 'failed|missing' | head -15 | sed 's/^/           /' | tee -a "$detail"
      (cd "$d" && timeout 120 "$tbin" "$(command -v composer)" check-platform-reqs --no-interaction >/dev/null 2>&1) || APP_BLOCK=1
    elif [ -n "$cli" ]; then
      local bad_pk=() pname pver pcons
      while IFS=$'\t' read -r pname pver pcons; do
        [ -n "$pcons" ] || continue
        constraint_allows "$pcons" "${FIXED[$T]:-$T.0}" || bad_pk+=("$pname $pver (php $pcons)")
      done < <(timeout 30 "$cli" -r '$l=json_decode(file_get_contents($argv[1]),true); $a=array(); foreach(array("packages","packages-dev") as $s){ if(isset($l[$s])) $a=array_merge($a,$l[$s]); } foreach($a as $p){ if(isset($p["require"]["php"])) echo $p["name"],"\t",$p["version"],"\t",$p["require"]["php"],"\n"; }' "$lock" 2>/dev/null)
      if [ ${#bad_pk[@]} -gt 0 ]; then
        bad "Dependencias de composer.lock que no aceptan PHP $T: ${#bad_pk[@]}"
        printf '%s\n' "${bad_pk[@]}" | head -10 | sed 's/^/           - /'
        printf '%s\n' "${bad_pk[@]}" >> "$detail"; APP_BLOCK=1
        info "Actualiza esas dependencias (composer update) en un entorno de prueba."
      else ok "Dependencias de composer.lock compatibles con PHP $T."; fi
    fi
  fi

  for r in "${RULES[@]}"; do
    typ=${r%%~~*}; r=${r#*~~}; rv=${r%%~~*}; r=${r#*~~}; sev=${r%%~~*}; r=${r#*~~}; pat=${r%%~~*}; desc=${r#*~~}
    ver_lt "$S" "$rv" && ver_ge "$T" "$rv" || continue
    if [ "$typ" = F ]; then
      re="(^|[^A-Za-z0-9_>:\$\\\\])(${pat// /|})[[:space:]]*\("; excl="function[[:space:]]+&?(${pat// /|})[[:space:]]*\("
    else re=$pat; excl='^$'; fi
    hits=$(xargs -0 -r grep -HnE -- "$re" < "$list" 2>/dev/null | grep -vE -- "$excl" | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|\*|#)')
    [ -n "$hits" ] || continue
    cnt=$(wc -l <<< "$hits")
    if [ "$sev" = ROTO ]; then bad "[$rv] $desc: $cnt"; APP_BLOCK=1; else warn "[$rv] $desc: $cnt"; APP_WARN=1; fi
    head -3 <<< "$hits" | cut -c1-160 | sed 's/^/             /'
    { echo; echo "[$sev $rv] $desc ($cnt)"; echo "$hits"; } >> "$detail"
  done

  if [ -n "$tbin" ]; then
    local lint
    lint=$(head -c 2000000 "$list" | xargs -0 -r -n1 -P4 "$tbin" -l 2>&1 | grep -iE 'error' | grep -v 'No syntax errors' | head -20)
    if [ -n "$lint" ]; then bad "Errores de sintaxis con PHP $T:"; echo "$lint" | cut -c1-180 | sed 's/^/           /'; echo "$lint" >> "$detail"; APP_BLOCK=1
    else ok "Sintaxis válida en PHP $T (php -l)."; fi
  else
    info "Para validar la sintaxis con PHP $T, instala la rama en paralelo: modo stage."
  fi
  rm -f "$list"
  info "Detalle completo: $detail"
  [ "$APP_KIND" = WordPress ] && info "WordPress: revisa también la compatibilidad declarada de plugins y temas con PHP $T."
}

ext_list() { timeout 10 "$1" -m 2>/dev/null | grep -vE '^\[|^$' | tr 'A-Z' 'a-z' | sort -u; }
deb_ext_pkg() {
  case $1 in
    mysqli|mysqlnd|pdo_mysql) echo mysql ;; pgsql|pdo_pgsql) echo pgsql ;; sqlite3|pdo_sqlite) echo sqlite3 ;;
    dom|xml|simplexml|xmlreader|xmlwriter|xsl) echo xml ;; "zend opcache"|opcache) echo opcache ;;
    odbc|pdo_odbc) echo odbc ;; pdo_dblib|mssql) echo sybase ;; interbase|pdo_firebird) echo interbase ;;
    pdo_sqlsrv) echo sqlsrv ;;
    core|date|libxml|openssl|pcre|zlib|filter|hash|json|pcntl|random|reflection|spl|session|standard|ctype|exif|fileinfo|ftp|gettext|iconv|pdo|phar|posix|shmop|sockets|sysvmsg|sysvsem|sysvshm|tokenizer|calendar|ffi|sodium|mhash|lexbor|uri) echo "" ;;
    *) echo "$1" ;;
  esac
}
rpm_ext_pkgs() {   # candidatos en orden para Remi SCL
  case $1 in
    mysqli|mysqlnd|pdo_mysql) echo mysqlnd ;; pgsql|pdo_pgsql) echo pgsql ;; sqlite3|pdo_sqlite|pdo) echo pdo ;;
    dom|xml|simplexml|xmlreader|xmlwriter|xsl) echo xml ;; "zend opcache"|opcache) echo opcache ;;
    posix|shmop|sysvmsg|sysvsem|sysvshm) echo process ;; odbc|pdo_odbc) echo odbc ;; pdo_dblib) echo pdo-dblib ;;
    core|date|libxml|openssl|pcre|zlib|filter|hash|json|random|reflection|spl|session|standard|ctype|exif|fileinfo|ftp|gettext|iconv|phar|tokenizer|calendar|sockets|curl|lexbor|uri) echo "" ;;
    mbstring|gd|intl|soap|bcmath|gmp|ldap|tidy|sodium|enchant|snmp|pspell|imap|dba|ffi|pcntl) echo "$1" ;;
    imagick) echo "pecl-imagick-im7 pecl-imagick" ;; redis) echo "pecl-redis6 pecl-redis5 pecl-redis" ;;
    *) echo "pecl-$1 $1" ;;
  esac
}
apk_ext_pkgs() {
  case $1 in
    core|date|libxml|pcre|spl|standard|reflection|hash|random|filter|zlib|lexbor|uri) echo "" ;;
    "zend opcache") echo opcache ;; *) echo "$1 pecl-$1" ;;
  esac
}

ext_plan() {   # $1 clave origen  $2 rama destino  -> EXT_PKGS EXT_MISSING
  local sk=$1 T=$2 xy e c p bin found
  xy=$(xy_of "$T"); EXT_PKGS=(); EXT_MISSING=(); EXT_NOREPO=0
  bin=${I_CLI[$sk]:-${I_FPM[$sk]:-}}; [ -n "$bin" ] || return
  local base_ok=1
  case $FAMILY in debian) apt-cache show "php$T-cli" >/dev/null 2>&1 || base_ok=0 ;;
                  rhel) $DNF -q list "php$xy-php-cli" >/dev/null 2>&1 || base_ok=0 ;; esac
  [ $base_ok -eq 1 ] || { EXT_NOREPO=1; return; }
  EXT_NOREPO=0
  while read -r e; do
    [ -n "$e" ] || continue
    local r rv; for r in "${REMOVED_EXT[@]}"; do rv=${r#*~~}; [ "${r%%~~*}" = "$e" ] && ver_ge "$T" "$rv" && EXT_MISSING+=("$e (fuera del núcleo desde $rv)"); done
    case $FAMILY in
      debian) p=$(deb_ext_pkg "$e"); [ -n "$p" ] || continue; p="php$T-$p"
              if apt-cache show "$p" >/dev/null 2>&1; then [[ " ${EXT_PKGS[*]} " == *" $p "* ]] || EXT_PKGS+=("$p"); else EXT_MISSING+=("$e"); fi ;;
      rhel) found=""; for c in $(rpm_ext_pkgs "$e"); do
              $DNF -q list "php$xy-php-$c" >/dev/null 2>&1 && { found="php$xy-php-$c"; break; }
            done
            [ -z "$(rpm_ext_pkgs "$e")" ] && continue
            if [ -n "$found" ]; then [[ " ${EXT_PKGS[*]} " == *" $found "* ]] || EXT_PKGS+=("$found"); else EXT_MISSING+=("$e"); fi ;;
      alpine) found=""; for c in $(apk_ext_pkgs "$e"); do
              [ -n "$(apk search -x "php$xy-$c" 2>/dev/null)" ] && { found="php$xy-$c"; break; }
            done
            [ -z "$(apk_ext_pkgs "$e")" ] && continue
            if [ -n "$found" ]; then EXT_PKGS+=("$found"); else EXT_MISSING+=("$e"); fi ;;
    esac
  done < <(ext_list "$bin")
}

pick_source_branch() {   # rama origen: --from, o la rama más antigua usada por sitios
  [ -n "$FROM" ] && { echo "$FROM"; return; }
  local i k best=""
  for i in "${!SITE_KEY[@]}"; do
    k=${SITE_KEY[$i]}; [ -n "$k" ] || continue
    [ "${I_BR[$k]}" = "$TO" ] && continue
    if [ -z "$best" ] || ver_lt "${I_BR[$k]}" "$best"; then best=${I_BR[$k]}; fi
  done
  if [ -z "$best" ]; then
    for k in "${INST_KEYS[@]}"; do [ "${I_BR[$k]}" = "$TO" ] && continue
      if [ -z "$best" ] || ver_lt "${I_BR[$k]}" "$best"; then best=${I_BR[$k]}; fi; done
  fi
  echo "$best"
}

do_plan() {
  [ -n "$TO" ] || TO=$RECOMMENDED_TARGET
  local S; S=$(pick_source_branch)
  [ -n "$S" ] || { bad "No se encontró una rama de origen. Indica --from X.Y."; finish 3; }
  local sk tk tbin; sk=$(key_for_branch "$S"); tk=$(key_for_branch "$TO")
  tbin=""; [ -n "$tk" ] && tbin=${I_CLI[$tk]:-}
  section "PLAN DE MIGRACIÓN  PHP $S  ->  PHP $TO"
  info "PHP $S: ${EOL[$S]:+soporte hasta ${EOL[$S]}}$([ -n "$sk" ] && echo "  ·  instalada ${I_VER[$sk]} ($(src_label "${I_SRC[$sk]}"))")"
  info "PHP $TO: soporte hasta ${EOL[$TO]:-?}$([ -n "$tk" ] && echo "  ·  ya instalada ${I_VER[$tk]}")"
  [ "$TO" = 8.2 ] && warn "PHP 8.2 deja de recibir parches el 2026-12-31: conviene ir a 8.3 o 8.4."
  [ -z "${FIXED[$TO]:-}" ] && { bad "La rama destino $TO no tiene soporte: elige 8.3, 8.4 o 8.5."; finish 3; }
  ver_ge "$S" "$TO" && { bad "La rama destino debe ser mayor que la de origen ($S)."; finish 3; }

  section "SITIOS QUE CAMBIARÍAN"
  local i n=0
  for i in "${!SITE_SRV[@]}"; do
    [ -n "${SITE_KEY[$i]}" ] && [ "${I_BR[${SITE_KEY[$i]}]}" = "$S" ] || continue
    n=$((n+1)); info "- ${SITE_NAMES[$i]:-(sin nombre)}  [${SITE_SRV[$i]}, ${SITE_HOW[$i]}]"
  done
  [ $n -eq 0 ] && info "Ningún sitio detectado usa PHP $S (indica la carpeta con --app)."

  section "EXTENSIONES"
  [ -z "$sk" ] && info "PHP $S no está instalado en este servidor: no se pueden comparar extensiones."
  if [ -n "$sk" ]; then
    ext_plan "$sk" "$TO"
    if [ "$EXT_NOREPO" = 1 ]; then
      warn "El repositorio actual no ofrece PHP $TO: hace falta el repo upstream (stage --upstream-repo)."
      local e2 el=""; while read -r e2; do [ -n "$(deb_ext_pkg "$e2")" ] && el="$el $e2"; done < <(ext_list "${I_CLI[$sk]:-${I_FPM[$sk]}}")
      info "Extensiones de PHP $S a replicar:${el:- ninguna adicional}"
    else info "Paquetes a instalar en PHP $TO: ${EXT_PKGS[*]:-(ninguno adicional)}"; fi
    if [ "$EXT_NOREPO" = 1 ]; then :
    elif [ ${#EXT_MISSING[@]} -gt 0 ]; then warn "Sin paquete directo para PHP $TO: ${EXT_MISSING[*]}"; info "Revísalas: algunas se instalan desde PECL o ya no existen."
    else ok "Todas las extensiones de PHP $S tienen equivalente en PHP $TO."; fi
  fi

  section "COMPATIBILIDAD DEL CÓDIGO"
  local d blocks=0 warns=0 anyapp=0
  while read -r d; do
    [ -n "$d" ] && [ -d "$d" ] || continue; anyapp=1
    scan_app "$d" "$S" "$TO" "$tbin"
    [ $APP_BLOCK -eq 1 ] && blocks=$((blocks+1)); [ $APP_WARN -eq 1 ] && warns=$((warns+1))
  done < <(app_dirs_for "$S")
  [ $anyapp -eq 0 ] && info "No hay carpetas de aplicación para analizar. Usa --app /ruta/del/proyecto."
  info "Nota: es un análisis heurístico. Deprecado = avisos en log; ROTO = error fatal en $TO."

  section "PASOS RECOMENDADOS"
  local me; me="sudo bash $(basename "$0")"
  info "1. Respaldo completo: snapshot del VPS + volcado de la base de datos."
  info "2. Instalar PHP $TO en paralelo (no toca ningún sitio):"; cmdl "$me stage --from $S --to $TO$([ $UPSTREAM -eq 1 ] && echo ' --upstream-repo')"
  info "3. Corregir lo marcado como ROTO y actualizar dependencias en un entorno de prueba (composer update)."
  info "4. Pasar un sitio de prueba primero; el agente revierte solo si el sitio falla:"; cmdl "$me switch --from $S --to $TO --site dominio.com"
  info "5. Revisar logs de PHP $TO durante 24-48 h; luego pasar el resto:"; cmdl "$me switch --from $S --to $TO --all-sites"
  info "6. Volver atrás en cualquier momento:"; cmdl "$me rollback"
  info "7. Tras 1-2 semanas estables, desinstalar PHP $S."
  if [ $blocks -gt 0 ]; then bad "Hay $blocks aplicación(es) con bloqueos: corrígelos antes del paso 4."; finish 1
  else ok "Sin bloqueos detectados$([ $warns -gt 0 ] && echo " ($warns con avisos de deprecación)")."; finish 0; fi
}

# ======================================================================= STAGE
target_ini_dirs() {   # carpetas conf.d de la rama destino
  local T=$1 xy; xy=$(xy_of "$T")
  case $FAMILY in
    debian) echo "/etc/php/$T/fpm/conf.d /etc/php/$T/cli/conf.d" ;;
    rhel) echo "/etc/opt/remi/php$xy/php.d" ;;
    alpine) echo "/etc/php$xy/conf.d" ;;
  esac
}
INI_KEYS="memory_limit upload_max_filesize post_max_size max_execution_time max_input_time max_input_vars max_file_uploads date.timezone display_errors log_errors short_open_tag output_buffering session.gc_maxlifetime opcache.enable opcache.memory_consumption opcache.max_accelerated_files opcache.validate_timestamps opcache.revalidate_freq realpath_cache_size default_charset allow_url_fopen expose_php disable_functions"
ini_dump() { timeout 15 "$1" -i 2>/dev/null | awk -F' => ' 'NF>=2 {print $1 "\t" $2}'; }
migrate_ini() {   # $1 bin origen $2 bin destino $3 rama destino
  local src=$1 dst=$2 T=$3 key sv dv out="" d
  declare -A SV=() DV=()
  while IFS=$'\t' read -r key sv; do SV[$key]=$sv; done < <(ini_dump "$src")
  while IFS=$'\t' read -r key sv; do DV[$key]=$sv; done < <(ini_dump "$dst")
  for key in $INI_KEYS; do
    sv=${SV[$key]:-}; dv=${DV[$key]:-}
    [ -n "$sv" ] && [ "$sv" != "no value" ] && [ "$sv" != "$dv" ] || continue
    out="$out$key = $sv"$'\n'
  done
  [ -n "$out" ] || { ok "No hay ajustes de php.ini que migrar."; return; }
  for d in $(target_ini_dirs "$T"); do
    [ -d "$d" ] || continue
    { echo "; Ajustes migrados desde PHP $FROM_EFF por BitForce PHP Agent ($(date +%F))"; printf '%s' "$out"; } > "$d/99-bitforce-migrated.ini"
    ok "Ajustes de php.ini copiados a $d/99-bitforce-migrated.ini"
  done
  printf '%s' "$out" | sed 's/^/           /'
}
copy_pools() {   # pools personalizados de la rama origen a la destino
  local S=$1 T=$2 sxy txy sdir tdir f base
  sxy=$(xy_of "$S"); txy=$(xy_of "$T")
  case $FAMILY in
    debian) sdir="/etc/php/$S/fpm/pool.d"; tdir="/etc/php/$T/fpm/pool.d" ;;
    rhel) sdir=""; for f in "/etc/opt/remi/php$sxy/php-fpm.d" /etc/php-fpm.d; do [ -d "$f" ] && { sdir=$f; break; }; done; tdir="/etc/opt/remi/php$txy/php-fpm.d" ;;
    *) return ;;
  esac
  [ -d "$sdir" ] && [ -d "$tdir" ] || return
  for f in "$sdir"/*.conf; do
    base=$(basename "$f"); [ "$base" = www.conf ] && continue
    [ -e "$tdir/$base" ] && { info "Pool $base ya existe en PHP $T: se respeta."; continue; }
    sed -e "s#php$S#php$T#g" -e "s#php$sxy#php$txy#g" -e "s#php-fpm$sxy#php-fpm$txy#g" "$f" > "$tdir/$base"
    if grep -qE '^[[:space:]]*listen[[:space:]]*=[[:space:]]*([0-9.]+:)?[0-9]+[[:space:]]*$' "$tdir/$base"; then
      local pool; pool=$(sed -nE 's/^[[:space:]]*\[([^]]+)\].*/\1/p' "$tdir/$base" | head -1)
      sed -i -E "s#^[[:space:]]*listen[[:space:]]*=.*#listen = /run/php/php$T-${pool:-$base}.sock#" "$tdir/$base"
      warn "Pool $base escuchaba en un puerto TCP: en PHP $T usa /run/php/php$T-${pool:-$base}.sock"
    fi
    ok "Pool $base copiado a PHP $T"
  done
}
fix_listen_collisions() {   # evita que la rama destino escuche donde ya escucha otra
  local tk=$1 ff pool l u k other tconf newsock
  tconf=${I_CONF[$tk]:-$(fpm_conf_for "$tk")}; [ -n "$tconf" ] || return
  while IFS=$'\t' read -r ff pool l u; do
    for k in "${INST_KEYS[@]}"; do
      [ "$k" = "$tk" ] && continue
      for other in ${I_SOCKS[$k]:-}; do
        if [ "$(norm_listen "$other")" = "$(norm_listen "$l")" ]; then
          newsock="/run/php-fpm-${I_BR[$tk]}-$pool.sock"; [ -d /run/php ] && newsock="/run/php/php${I_BR[$tk]}-$pool.sock"
          sed -i -E "s#^[[:space:]]*listen[[:space:]]*=.*#listen = $newsock#" "$ff"
          warn "Pool $pool de PHP ${I_BR[$tk]} chocaba con PHP ${I_BR[$k]} ($l): ahora usa $newsock"
        fi
      done
    done
  done < <(fpm_listens "$tconf")
}
alt_snapshot() { have update-alternatives || return; local a; for a in php phar phar.phar php-fpm php-fpm.sock php-cgi php-cgi-bin phpdbg; do
  update-alternatives --query "$a" 2>/dev/null | awk -v a="$a" '/^Value:/{print a "\t" $2}'; done; }

do_stage() {
  need_root; take_lock
  [ -n "$TO" ] || { bad "Indica la rama destino con --to (recomendada: $RECOMMENDED_TARGET)."; finish 3; }
  [ -n "${FIXED[$TO]:-}" ] || { bad "La rama $TO no tiene soporte: elige 8.3, 8.4 o 8.5."; finish 3; }
  FROM_EFF=$(pick_source_branch)
  [ -n "$FROM_EFF" ] || { bad "No se encontró la rama de origen. Indica --from."; finish 3; }
  local sk tk xy; sk=$(key_for_branch "$FROM_EFF"); tk=$(key_for_branch "$TO"); xy=$(xy_of "$TO")
  section "INSTALAR PHP $TO EN PARALELO A PHP $FROM_EFF"
  [ "$TO" = 8.2 ] && warn "PHP 8.2 deja de recibir parches el 2026-12-31."
  [ -n "$PANEL" ] && [ "$PANEL" != cloudpanel ] && [ "$PANEL" != hestia ] && [ "$PANEL" != virtualmin ] && {
    warn "Servidor con $PANEL_NAME: instala PHP $TO desde el panel (MultiPHP / PHP Selector) para que el panel lo gestione."; finish 1; }
  case $FAMILY in suse) bad "openSUSE/SLES trae una sola versión de PHP por versión de la distro: el cambio de rama se hace actualizando la distro o con contenedores."; finish 1 ;;
                  unknown) bad "Distribución no soportada para instalar en paralelo."; finish 3 ;; esac

  local pkgs=() before_alt=""
  if [ -n "$tk" ] && [ -n "${I_FPM[$tk]:-}" ]; then ok "PHP $TO ya está instalado (${I_VER[$tk]}): se revisa su configuración."
  else
    ext_plan "$sk" "$TO"
    case $FAMILY in
      debian) apt-get update -qq >/dev/null 2>&1
              if ! apt-cache policy "php$TO-fpm" 2>/dev/null | grep -q 'Candidate: [0-9]'; then
                if [ "$UPSTREAM" -eq 1 ]; then add_upstream_repo || finish 1; ext_plan "$sk" "$TO"
                else bad "El repositorio de $OS_NAME no ofrece PHP $TO."; info "Repite con --upstream-repo para usar $([ "$OS_ID" = ubuntu ] && echo 'el PPA de Ondřej Surý' || echo 'el repositorio de Sury')."; finish 1; fi
              fi
              pkgs=("php$TO-fpm" "php$TO-cli" "${EXT_PKGS[@]}") ;;
      rhel) if ! repo_has_upstream; then
              if [ "$UPSTREAM" -eq 1 ]; then add_upstream_repo || finish 1; ext_plan "$sk" "$TO"
              else bad "Para instalar PHP $TO en paralelo se necesita Remi (SCL)."; info "Repite con --upstream-repo."; finish 1; fi
            fi
            pkgs=("php$xy-php-fpm" "php$xy-php-cli" "${EXT_PKGS[@]}") ;;
      alpine) pkgs=("php$xy" "php$xy-fpm" "${EXT_PKGS[@]}") ;;
    esac
    info "Paquetes: ${pkgs[*]}"
    [ ${#EXT_MISSING[@]} -gt 0 ] && warn "Extensiones sin paquete para PHP $TO: ${EXT_MISSING[*]}"
    info "Ningún sitio cambia en este paso."
    confirm "¿Instalar PHP $TO en paralelo?" || { warn "Cancelado."; finish 1; }
    make_backup stage
    before_alt=$(alt_snapshot)
    case $FAMILY in
      debian) run_sh "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends -o Dpkg::Options::=--force-confold ${pkgs[*]}" || { bad "Falló la instalación."; finish 1; } ;;
      rhel) run_cmd $DNF install -y "${pkgs[@]}" || { bad "Falló la instalación."; finish 1; } ;;
      alpine) run_cmd apk add "${pkgs[@]}" || { bad "Falló la instalación."; finish 1; } ;;
    esac
    if [ -n "$before_alt" ]; then   # que el "php" por defecto y php-fpm.sock no cambien solos
      local a v now
      while IFS=$'\t' read -r a v; do
        now=$(update-alternatives --query "$a" 2>/dev/null | awk '/^Value:/{print $2}')
        [ -n "$now" ] && [ "$now" != "$v" ] && run_cmd update-alternatives --set "$a" "$v" && info "Se mantiene $a -> $v"
      done <<< "$before_alt"
    fi
  fi
  full_discovery
  tk=$(key_for_branch "$TO"); sk=$(key_for_branch "$FROM_EFF")
  [ -n "$tk" ] && [ -n "${I_FPM[$tk]:-}" ] || { bad "No se encontró PHP-FPM $TO después de instalar."; finish 1; }

  section "CONFIGURACIÓN DE PHP $TO"
  [ -n "$sk" ] && migrate_ini "${I_FPM[$sk]:-${I_CLI[$sk]}}" "${I_FPM[$tk]}" "$TO"
  copy_pools "$FROM_EFF" "$TO"
  full_discovery; tk=$(key_for_branch "$TO")
  fix_listen_collisions "$tk"
  if timeout 20 "${I_FPM[$tk]}" -t >/dev/null 2>&1; then ok "Configuración de PHP-FPM $TO válida."
  else bad "php-fpm -t falla en PHP $TO:"; timeout 20 "${I_FPM[$tk]}" -t 2>&1 | tail -5 | sed 's/^/           /'; finish 1; fi
  local svc=${I_SVCS[$tk]%% *}
  if [ -z "$svc" ]; then case $FAMILY in debian) svc="php$TO-fpm" ;; rhel) svc="php$xy-php-fpm" ;; alpine) svc="php-fpm$xy" ;; esac; fi
  [ "$HAS_SYSTEMD" -eq 1 ] && run_cmd systemctl enable "$svc" >/dev/null
  [ "$HAS_SYSTEMD" -eq 0 ] && have rc-update && run_cmd rc-update add "$svc" default
  if svc_restart "$svc"; then ok "PHP-FPM $TO en ejecución ($svc)"; else warn "No se pudo iniciar el servicio $svc: inícialo manualmente antes del switch."; fi
  full_discovery; tk=$(key_for_branch "$TO")
  info "PHP $TO escucha en: ${I_SOCKS[$tk]:-?}"

  section "VALIDACIÓN DEL CÓDIGO CON PHP $TO"
  local d any=0 blocks=0
  while read -r d; do [ -n "$d" ] && [ -d "$d" ] || continue; any=1
    scan_app "$d" "$FROM_EFF" "$TO" "${I_CLI[$tk]:-}"; [ $APP_BLOCK -eq 1 ] && blocks=$((blocks+1))
  done < <(app_dirs_for "$FROM_EFF")
  [ $any -eq 0 ] && info "No hay carpetas de aplicación (usa --app)."

  section "SIGUIENTE PASO"
  info "PHP $TO está listo y ningún sitio cambió. Para pasar un sitio de prueba:"
  cmdl "sudo bash $(basename "$0") switch --from $FROM_EFF --to $TO --site dominio.com"
  [ $blocks -gt 0 ] && warn "Hay $blocks aplicación(es) con bloqueos: corrígelos antes del switch."
  finish 0
}

# ====================================================================== SWITCH
sed_esc() { printf '%s' "$1" | sed -E 's/[][\.*^$#/|()+?{}]/\\&/g'; }
target_socket() {   # $1 clave destino  [$2 handler origen]: socket equivalente o el principal
  local tk=$1 src=${2:-} s pick="" cand sxy txy
  if [ -n "$src" ] && [ -n "${SW_S:-}" ]; then
    src=$(norm_listen "$src"); sxy=$(xy_of "$SW_S"); txy=$(xy_of "${I_BR[$tk]}")
    cand=${src//php$SW_S/php${I_BR[$tk]}}; cand=${cand//php$sxy/php$txy}
    for s in ${I_SOCKS[$tk]:-}; do [ "$(norm_listen "$s")" = "$cand" ] && { echo "$s"; return; }; done
  fi
  for s in ${I_SOCKS[$tk]:-}; do [[ $s == */www.sock || $s == *php${I_BR[$tk]}-fpm.sock ]] && { pick=$s; break; }; done
  [ -n "$pick" ] || read -r pick _ <<< "${I_SOCKS[$tk]:-}"
  echo "$pick"
}
apache_block() {   # $1 socket o puerto destino
  case $1 in /*) printf '    <FilesMatch "\\.(php|phar|phtml)$">\n        SetHandler "proxy:unix:%s|fcgi://localhost"\n    </FilesMatch>\n' "$1" ;;
             *) printf '    <FilesMatch "\\.(php|phar|phtml)$">\n        SetHandler "proxy:fcgi://127.0.0.1:%s"\n    </FilesMatch>\n' "${1##*:}" ;; esac
}
UNDO_CMDS=()
switch_site() {   # $1 índice de sitio  $2 clave destino  -> 0 si cambió
  local i=$1 tk=$2 tsock f h newv changed=1 tmp
  f=$(readlink -f "${SITE_FILE[$1]}" 2>/dev/null || echo "${SITE_FILE[$1]}")   # editar el archivo real, no el enlace
  tsock=$(target_socket "$tk" "${SITE_HRAW[$i]%% *}")
  [ -n "$tsock" ] || tsock=$(target_socket "$tk")
  info "${SITE_NAMES[$i]:-$f} -> $tsock"
  backup_file "$f" || { bad "No se pudo respaldar $f"; return 1; }
  case ${SITE_SRV[$i]} in
    nginx)
      case $tsock in /*) newv="unix:$tsock" ;; *) newv="127.0.0.1:${tsock##*:}" ;; esac
      for h in ${SITE_HRAW[$i]}; do
        if [ -n "${NG_UP[$h]:-}" ]; then
          local uf; uf=$(readlink -f "${NG_UPFILE[$h]}" 2>/dev/null || echo "${NG_UPFILE[$h]}"); backup_file "$uf"
          sed -i -E "s#(^[[:space:]]*server[[:space:]]+)$(sed_esc "${NG_UP[$h]}")#\1$newv#" "$uf" && changed=0
          warn "Se cambió el upstream '$h' en $uf (afecta a todos los sitios que lo usan)."
        else
          sed -i -E "s#(fastcgi_pass[[:space:]]+)$(sed_esc "$h")([[:space:]]*;)#\1$newv\2#" "$f" && changed=0
        fi
      done ;;
    apache)
      if [ -n "${SITE_HRAW[$i]}" ]; then
        for h in ${SITE_HRAW[$i]}; do
          case $h in proxy:unix:*) local op=${h#proxy:unix:}; op=${op%%|*}
                       case $tsock in /*) sed -i -E "s#proxy:unix:$(sed_esc "$op")\|#proxy:unix:$tsock|#g" "$f" ;;
                                      *) sed -i -E "s#proxy:unix:$(sed_esc "$op")\|fcgi://[^\"[:space:]]*#proxy:fcgi://127.0.0.1:${tsock##*:}#g" "$f" ;; esac ;;
                     *fcgi://*) local hp=${h#*fcgi://}; hp=${hp%%/*}
                       case $tsock in /*) sed -i -E "s#proxy:fcgi://$(sed_esc "$hp")#proxy:unix:$tsock|fcgi://localhost#g; s#fcgi://$(sed_esc "$hp")#unix:$tsock|fcgi://localhost#g" "$f" ;;
                                      *) sed -i -E "s#fcgi://$(sed_esc "$hp")#fcgi://127.0.0.1:${tsock##*:}#g" "$f" ;; esac ;;
          esac
        done; changed=0
      else   # hereda mod_php o el handler global: se agrega un bloque propio al vhost
        if ! [[ " $APACHE_MODS " =~ \ proxy_fcgi_module\  ]]; then
          if have a2enmod; then run_cmd a2enmod proxy_fcgi setenvif >/dev/null && UNDO_CMDS+=("a2dismod -f proxy_fcgi")
          else bad "Falta el módulo proxy_fcgi de Apache."; return 1; fi
          APACHE_MODS="$APACHE_MODS proxy_fcgi_module"
        fi
        tmp=$(mktemp)
        BF_BLK="$(apache_block "$tsock")" awk 'tolower($0) ~ /^[ \t]*<\/virtualhost>/ { print "    # BitForce: PHP-FPM"; print ENVIRON["BF_BLK"] } { print }' "$f" > "$tmp" && cat "$tmp" > "$f"; rm -f "$tmp"
        changed=0
      fi ;;
    *) warn "${SITE_SRV[$i]}: cambia la versión desde su panel o configuración (no automatizado)."; return 1 ;;
  esac
  return $changed
}
restore_files() {   # restaura archivos registrados en el manifiesto
  local t f b
  while IFS=$'\t' read -r t f b; do [ "$t" = FILE ] && [ -f "$b" ] && cat "$b" > "$f" && info "Restaurado $f"; done < "$1"
}

do_switch() {
  need_root; take_lock
  [ -n "$TO" ] || { bad "Indica --to X.Y"; finish 3; }
  local S; S=$(pick_source_branch); [ -n "$S" ] || { bad "Indica --from X.Y"; finish 3; }
  [ ${#SITES_SEL[@]} -gt 0 ] || [ $ALL_SITES -eq 1 ] || { bad "Indica --site dominio.com (repetible) o --all-sites."; finish 3; }
  local tk; tk=$(key_for_branch "$TO")
  [ -n "$tk" ] && [ -n "${I_FPM[$tk]:-}" ] || { bad "PHP-FPM $TO no está instalado. Primero: stage --to $TO"; finish 1; }
  if [ -z "${I_RUN[$tk]:-}" ] && [ -n "${I_SVCS[$tk]:-}" ]; then svc_restart "${I_SVCS[$tk]%% *}"; full_discovery; tk=$(key_for_branch "$TO"); fi
  [ -n "${I_RUN[$tk]:-}" ] || { bad "PHP-FPM $TO no está en ejecución: inícialo antes del cambio (o repite stage --to $TO)."; finish 1; }
  SW_S=$S
  local tsock; tsock=$(target_socket "$tk")
  [ -n "$tsock" ] || { bad "No se pudo determinar dónde escucha PHP-FPM $TO."; finish 1; }

  section "CAMBIO DE PHP $S -> PHP $TO"
  info "Destino: PHP-FPM ${I_VER[$tk]} (${I_SOCKS[$tk]:-?})"
  local i s sel=() srvs=" "
  for i in "${!SITE_SRV[@]}"; do
    [ -n "${SITE_KEY[$i]}" ] && [ "${I_BR[${SITE_KEY[$i]}]}" = "$S" ] || continue
    if [ $ALL_SITES -eq 0 ]; then
      local m=0; for s in "${SITES_SEL[@]}"; do
        [[ " ${SITE_NAMES[$i]} " == *" $s "* || ${SITE_FILE[$i]} == *"$s"* ]] && m=1; done
      [ $m -eq 1 ] || continue
    fi
    sel+=("$i"); srvs="$srvs${SITE_SRV[$i]} "
    info "- ${SITE_NAMES[$i]:-(compartido)}  [${SITE_SRV[$i]}: ${SITE_FILE[$i]}]"
  done
  local global_swap=0
  if [ $ALL_SITES -eq 1 ] && [ -n "$APACHE_GLOBAL_H" ] && have a2enconf && [ -f "/etc/apache2/conf-available/php$TO-fpm.conf" ] && \
     [ "$(guess_branch "$APACHE_GLOBAL_H")" = "$S" ]; then global_swap=1; info "- handler global de Apache: php$S-fpm -> php$TO-fpm"; fi
  [ ${#sel[@]} -gt 0 ] || [ $global_swap -eq 1 ] || { bad "Ningún sitio coincide con la selección y usa PHP $S."; finish 1; }
  [ $SWITCH_CLI -eq 1 ] && info "- php de consola -> php$TO"
  confirm "¿Aplicar el cambio? (se revierte solo si falla la prueba)" || { warn "Cancelado."; finish 1; }

  make_backup switch
  health_snapshot before
  local fails=0
  for i in "${sel[@]}"; do switch_site "$i" "$tk" || fails=1; done
  if [ $global_swap -eq 1 ]; then
    run_cmd a2disconf "php$S-fpm" && run_cmd a2enconf "php$TO-fpm" && UNDO_CMDS+=("a2disconf php$TO-fpm" "a2enconf php$S-fpm")
    srvs="$srvs apache "
  fi
  local u; for u in "${UNDO_CMDS[@]}"; do printf 'UNDO\t%s\n' "$u" >> "$BK_DIR/manifest"; done

  local cfg_ok=1
  [[ $srvs == *" nginx "* ]] && { nginx_test || { bad "nginx -t falla:"; timeout 20 "$NGINX_BIN" -t 2>&1 | tail -4 | sed 's/^/           /'; cfg_ok=0; }; }
  [[ $srvs == *" apache "* ]] && { apache_test || { bad "apachectl -t falla:"; timeout 20 "$APACHE_CTL" -t 2>&1 | tail -4 | sed 's/^/           /'; cfg_ok=0; }; }
  if [ $cfg_ok -eq 0 ]; then
    warn "Revirtiendo cambios..."; restore_files "$BK_DIR/manifest"
    for u in "${UNDO_CMDS[@]}"; do run_sh "$u"; done
    bad "No se aplicó ningún cambio."; finish 1
  fi
  [[ $srvs == *" nginx "* ]] && nginx_reload
  [[ $srvs == *" apache "* ]] && apache_reload graceful
  sleep 3
  full_discovery
  subhead "Chequeo HTTP antes / después"
  health_snapshot after
  if ! health_compare; then
    warn "Un sitio falló después del cambio: se revierte automáticamente."
    restore_files "$BK_DIR/manifest"; for u in "${UNDO_CMDS[@]}"; do run_sh "$u"; done
    [[ $srvs == *" nginx "* ]] && nginx_reload; [[ $srvs == *" apache "* ]] && apache_reload graceful
    bad "Cambio revertido. Revisa el log de errores de PHP $TO y corrige la aplicación."
    finish 1
  fi
  if [ $SWITCH_CLI -eq 1 ] && have update-alternatives && [ -x "/usr/bin/php$TO" ]; then
    local old; old=$(update-alternatives --query php 2>/dev/null | awk '/^Value:/{print $2}')
    printf 'ALT\tphp\t%s\n' "$old" >> "$BK_DIR/manifest"
    run_cmd update-alternatives --set php "/usr/bin/php$TO"
    warn "Revisa las tareas cron que llaman a 'php': ahora usan PHP $TO."
  fi
  section "RESULTADO"
  full_discovery
  for i in "${!SITE_SRV[@]}"; do
    for s in "${sel[@]}"; do [ "$s" = "$i" ] && info "- ${SITE_NAMES[$i]:-(compartido)} -> PHP ${I_BR[${SITE_KEY[$i]:-x}]:-?}"; done
  done
  [ $fails -eq 1 ] && warn "Algunos sitios no se pudieron cambiar automáticamente."
  ok "Cambio aplicado. Para volver atrás: sudo bash $(basename "$0") rollback --backup $BK_ID"
  RECS+=("Revisar logs de PHP $TO durante 24-48 h" "Rollback: sudo bash $(basename "$0") rollback --backup $BK_ID")
  finish $fails
}

# ==================================================================== ROLLBACK
do_rollback() {
  need_root; take_lock
  local dir
  if [ -n "$BACKUP_ID" ]; then dir="$BACKUP_ROOT/$BACKUP_ID"
  else local cands=("$BACKUP_ROOT"/*-fix "$BACKUP_ROOT"/*-switch); [ ${#cands[@]} -gt 0 ] && dir=$(printf '%s\n' "${cands[@]}" | sort | tail -1); fi
  [ -n "$dir" ] && [ -f "$dir/manifest" ] || { bad "No se encontró el respaldo${BACKUP_ID:+ $BACKUP_ID} en $BACKUP_ROOT."; ls -1 "$BACKUP_ROOT" 2>/dev/null | sed 's/^/           /'; finish 3; }
  local mode; mode=$(awk -F'\t' '$1=="MODE"{print $2}' "$dir/manifest")
  section "ROLLBACK de $(basename "$dir") ($mode)"
  BK_DIR=$dir
  case $mode in
    switch)
      awk -F'\t' '$1=="FILE"{print "  - " $2}' "$dir/manifest"
      confirm "¿Restaurar estos archivos y recargar el servidor web?" || finish 1
      restore_files "$dir/manifest"
      local u a v
      while IFS=$'\t' read -r u a; do [ "$u" = UNDO ] && run_sh "$a"; done < <(tac "$dir/manifest" 2>/dev/null || cat "$dir/manifest")
      while IFS=$'\t' read -r u a v; do [ "$u" = ALT ] && [ -n "$v" ] && run_cmd update-alternatives --set "$a" "$v"; done < "$dir/manifest"
      [ -n "$NGINX_BIN" ] && nginx_test && nginx_reload
      [ -n "$APACHE_CTL" ] && apache_test && apache_reload graceful ;;
    fix)
      warn "Volver a la versión anterior deja PHP otra vez VULNERABLE. Úsalo solo para recuperar un sitio caído."
      local tx; tx=$(awk -F'\t' '$1=="DNFTX"{print $2}' "$dir/manifest" | tail -1)
      confirm "¿Revertir los paquetes de PHP a las versiones anteriores?" || finish 1
      case $FAMILY in
        rhel) [ -n "$tx" ] && run_cmd $DNF -y history undo "$tx" || bad "No hay transacción dnf registrada." ;;
        debian)
          local line name ver cur list=() debs=() deb
          while IFS='=' read -r name ver; do
            cur=$(dpkg-query -W -f='${Version}' "$name" 2>/dev/null); [ -n "$cur" ] && [ "$cur" != "$ver" ] || continue
            list+=("$name=$ver")
            for deb in /var/cache/apt/archives/"${name}_${ver//:/%3a}"_*.deb; do debs+=("$deb"); break; done
          done < "$dir/packages.txt"
          if [ ${#list[@]} -eq 0 ]; then ok "Los paquetes ya están en las versiones del respaldo."
          elif ! DEBIAN_FRONTEND=noninteractive run_cmd apt-get install -y --allow-downgrades -o Dpkg::Options::=--force-confold "${list[@]}"; then
            if [ ${#debs[@]} -gt 0 ]; then run_cmd dpkg -i "${debs[@]}"
            else bad "Las versiones anteriores ya no están en el repositorio ni en la caché de apt."; fi
          fi ;;
        *) bad "Rollback de paquetes no automatizado en $FAMILY. Versiones anteriores en $dir/packages.txt" ;;
      esac
      full_discovery; local ks=(); for k in "${INST_KEYS[@]}"; do ks+=("$k"); done; restart_php "${ks[@]}" ;;
    *) bad "Tipo de respaldo no soportado: $mode"; finish 3 ;;
  esac
  info "La configuración completa previa sigue en $dir/etc.tgz por si la necesitas."
  ok "Rollback completado."
  finish 0
}

# ======================================================================== MAIN
detect_os
detect_panel
PORTS=$(listen_ports | xargs)
print_header
full_discovery
case $MODE in
  diagnose) do_diagnose; finish "$EXIT_CODE" ;;
  fix) do_fix ;;
  plan) do_plan ;;
  stage) do_stage ;;
  switch) do_switch ;;
  rollback) do_rollback ;;
esac
