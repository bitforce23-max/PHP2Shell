#!/usr/bin/env bash
# =============================================================================
#  bitforce-run.sh - Ejecuta el BitForce PHP Agent en varios servidores por SSH
#  y junta los reportes en una carpeta local con un resumen CSV.
#  Funciona en Linux, macOS, WSL y Git Bash (Windows).
#
#  USO
#    ./bitforce-run.sh -f servidores.txt [-m modo] [-i] [-o carpeta] [-- opciones del agente]
#
#  EJEMPLOS
#    ./bitforce-run.sh -f servidores.txt                       # diagnóstico
#    ./bitforce-run.sh -f servidores.txt -m fix -- --yes       # parche desatendido
#    ./bitforce-run.sh -f servidores.txt -m plan -- --to 8.3   # plan de migración
#    ./bitforce-run.sh -f servidores.txt -i -m fix             # pide confirmación en cada uno
#
#  servidores.txt (una línea por servidor; # para comentarios)
#    usuario@host[:puerto]   [ruta/llave_privada]   [alias]
#    root@203.0.113.10
#    deploy@cliente1.com:2222  ~/.ssh/cliente1  tienda-cliente1
#
#  El usuario necesita sudo sin contraseña para modo desatendido; si no, usa -i.
# =============================================================================
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
AGENT="$HERE/bitforce-php-agent.sh"
LIST=""; MODE="diagnose"; INTERACTIVE=0; OUT="$HERE/reportes"
while [ $# -gt 0 ]; do
  case "$1" in
    -f) LIST=$2; shift ;;
    -m) MODE=$2; shift ;;
    -i) INTERACTIVE=1 ;;
    -o) OUT=$2; shift ;;
    -a) AGENT=$2; shift ;;
    -h|--help) sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --) shift; break ;;
    *) echo "Opción desconocida: $1"; exit 3 ;;
  esac
  shift
done
AGENT_ARGS=("$@")
[ -n "$LIST" ] && [ -f "$LIST" ] || { echo "Indica la lista de servidores con -f (ver --help)."; exit 3; }
[ -f "$AGENT" ] || { echo "No se encuentra el agente: $AGENT"; exit 3; }
case $MODE in diagnose|fix|plan|stage|switch|rollback) ;; *) echo "Modo inválido: $MODE"; exit 3 ;; esac

RUN_ID=$(date +%Y%m%d-%H%M%S)
DEST="$OUT/$RUN_ID-$MODE"; mkdir -p "$DEST"
CSV="$DEST/resumen.csv"
echo "servidor,alias,codigo,veredicto,sistema,panel,servidores_web,php,sitios_vulnerables,indicadores,reporte" > "$CSV"
SSH_BASE=(-o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=20)
[ $INTERACTIVE -eq 0 ] && SSH_BASE+=(-o BatchMode=yes)

quote_args() { local a out=""; for a in "$@"; do out="$out '${a//\'/\'\\\'\'}'"; done; echo "$out"; }

summarize() {   # $1 json  -> línea CSV (sin los dos primeros campos)
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$1" <<'PY'
import json, sys
try: d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception: print(",ERROR_JSON,,,,,,"); sys.exit()
php = "; ".join(f"{i['branch']}={i['version']}:{i['status']}" for i in d.get("installations", []))
vuln = sum(1 for s in d.get("sites", []) if s.get("php_status") in ("VULNERABLE", "UNSUPPORTED"))
q = lambda s: '"' + str(s).replace('"', "'") + '"'
print(",".join([q(d.get("verdict","")), q(d.get("os",{}).get("name","")), q(d.get("panel","")),
                q(" ".join(d.get("web_servers",[]))), q(php), str(vuln), q(" | ".join(d.get("ioc",{}).get("findings",[])))]))
PY
  else
    local v; v=$(grep -oE '"verdict":"[A-Z_]+"' "$1" | cut -d'"' -f4)
    echo "\"$v\",,,,,,"
  fi
}

printf '\nBitForce · modo %s · %s\n' "$MODE" "$DEST"
TOTAL=0; OKC=0; ACT=0; SUS=0; ERR=0
while read -r target key alias _ <&3; do
  case "$target" in ""|\#*) continue ;; esac
  TOTAL=$((TOTAL+1))
  host=${target%%:*}; port=22; [[ $target == *:* ]] && port=${target##*:}
  name=${alias:-${host#*@}}
  opts=("${SSH_BASE[@]}" -p "$port"); sopts=("${SSH_BASE[@]}" -P "$port")
  if [ -n "${key:-}" ] && [ "$key" != "-" ]; then key=${key/#\~/$HOME}; opts+=(-i "$key"); sopts+=(-i "$key"); fi
  sudo="sudo -n"; [ $INTERACTIVE -eq 1 ] && sudo="sudo"; [[ $host == root@* ]] && sudo=""
  printf '\n=== %s (%s) ===\n' "$name" "$host"
  mkdir -p "$DEST/$name"
  if ! scp -q "${sopts[@]}" "$AGENT" "$host:/tmp/bitforce-php-agent.sh" 2>"$DEST/$name/ssh-error.txt" < /dev/null; then
    echo "  ERROR: no se pudo copiar el agente ($(head -1 "$DEST/$name/ssh-error.txt"))"
    echo "\"$host\",\"$name\",255,\"SIN_CONEXION\",,,,,,," >> "$CSV"; ERR=$((ERR+1)); continue
  fi
  remote="sed -i 's/\r\$//' /tmp/bitforce-php-agent.sh; $sudo bash /tmp/bitforce-php-agent.sh $MODE -o /var/tmp/bitforce$( [ $INTERACTIVE -eq 0 ] && echo ' -q')$(quote_args "${AGENT_ARGS[@]+"${AGENT_ARGS[@]}"}")"
  if [ $INTERACTIVE -eq 1 ]; then ssh -t "${opts[@]}" "$host" "$remote" < /dev/tty | tee "$DEST/$name/consola.txt"; rc=${PIPESTATUS[0]}
  else ssh -n "${opts[@]}" "$host" "$remote" > "$DEST/$name/consola.txt" 2>&1; rc=$?; fi
  base=$(ssh -n "${opts[@]}" "$host" "ls -1t /var/tmp/bitforce/bitforce-*-$MODE.json 2>/dev/null | head -1" 2>/dev/null)
  base=${base%.json}
  if [ -n "$base" ]; then
    scp -q "${sopts[@]}" "$host:$base*" "$DEST/$name/" 2>/dev/null < /dev/null
    json="$DEST/$name/$(basename "$base").json"
  else json=""; fi
  case $rc in 0) st="OK"; OKC=$((OKC+1)) ;; 1) st="REQUIERE ACCIÓN"; ACT=$((ACT+1)) ;;
              2) st="SOSPECHOSO"; SUS=$((SUS+1)) ;; *) st="ERROR ($rc)"; ERR=$((ERR+1)) ;; esac
  echo "  Resultado: $st"
  grep -E '\[FALLA\]|\[AVISO\]' "$DEST/$name/consola.txt" 2>/dev/null | head -6 | sed 's/^/  /'
  if [ -n "$json" ] && [ -f "$json" ]; then
    echo "\"$host\",\"$name\",$rc,$(summarize "$json"),\"$name/$(basename "$base").txt\"" >> "$CSV"
  else
    echo "\"$host\",\"$name\",$rc,\"ERROR\",,,,,,,\"$name/consola.txt\"" >> "$CSV"
    if [ $rc -gt 2 ] && grep -qiE 'sudo|password|contraseña' "$DEST/$name/consola.txt"; then echo "  Sugerencia: el usuario necesita sudo sin contraseña o usa -i."; fi
  fi
done 3< "$LIST"

printf '\n=== RESUMEN: %d servidores · %d OK · %d requieren acción · %d sospechosos · %d con error ===\n' "$TOTAL" "$OKC" "$ACT" "$SUS" "$ERR"
echo "Resumen CSV: $CSV"
echo "Reportes   : $DEST/<servidor>/"
