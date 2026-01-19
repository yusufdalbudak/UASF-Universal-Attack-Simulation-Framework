#!/usr/bin/env bash
# HTTP Methods Library for UASF
# Provides POST/PUT/DELETE support with JSON payloads

# Temporarily disable nounset for safety
set +u 2>/dev/null || true

# Global defaults
HTTP_METHOD="${HTTP_METHOD:-GET}"
CONTENT_TYPE="${CONTENT_TYPE:-application/x-www-form-urlencoded}"

# Re-enable nounset
set -u 2>/dev/null || true

# Execute a request with specified method
# Usage: http_request METHOD URL [BODY] [EXTRA_HEADERS...]
http_request() {
  local method="${1:-GET}"
  local url="${2:-}"
  local body="${3:-}"
  shift 3 2>/dev/null || true
  local extra_headers=("$@")
  
  [[ -z "$url" ]] && echo "ERROR: No URL provided" && return 1
  
  # Build curl options - handle CURL_BASE safely
  local curl_opts=(-sS -L --max-time "${TIMEOUT:-8}")
  if [[ -n "${CID:-}" ]]; then
    curl_opts+=(-H "X-UASF-Correlation: $CID")
  fi
  curl_opts+=(-X "$method")
  
  # Add extra headers if provided
  for header in "${extra_headers[@]:-}"; do
    [[ -n "$header" ]] && curl_opts+=(-H "$header")
  done
  
  # Handle request body
  if [[ -n "$body" ]]; then
    if [[ "$body" == "{"* || "$body" == "["* ]]; then
      curl_opts+=(-H "Content-Type: application/json")
      curl_opts+=(-d "$body")
    else
      curl_opts+=(-H "Content-Type: $CONTENT_TYPE")
      curl_opts+=(-d "$body")
    fi
  fi
  
  curl "${curl_opts[@]}" "$url"
}

# Parse API payload format: METHOD|PATH|BODY
# Returns: Sets global vars API_METHOD, API_PATH, API_BODY
parse_api_payload() {
  local payload="${1:-}"
  [[ -z "$payload" ]] && return 1
  
  IFS='|' read -r API_METHOD API_PATH API_BODY <<< "$payload"
  API_METHOD="${API_METHOD:-GET}"
  API_PATH="${API_PATH:-/}"
  API_BODY="${API_BODY:-}"
}

# Execute API attack with JSON body
attack_api() {
  local module="${1:-}"
  local base_url="${2:-}"
  local payload="${3:-}"
  
  [[ -z "$base_url" || -z "$payload" ]] && return 1
  
  parse_api_payload "$payload"
  local full_url="${base_url}${API_PATH}"
  
  local ua=""
  if type pick_ua &>/dev/null; then
    ua="$(pick_ua)"
  else
    ua="UASF/2.0"
  fi
  
  local tmp start end ms http size ip
  tmp="$(mktemp)"
  start=$(date +%s%3N)
  
  local curl_cmd=(-sS -L --max-time "${TIMEOUT:-8}" -A "$ua" -X "$API_METHOD")
  if [[ -n "${CID:-}" ]]; then
    curl_cmd+=(-H "X-UASF-Correlation: $CID")
  fi
  
  if [[ -n "$API_BODY" ]]; then
    curl_cmd+=(-H "Content-Type: application/json" -d "$API_BODY")
  fi
  
  read -r http size ip < <(
    curl "${curl_cmd[@]}" -D - -o "$tmp" \
      -w "%{http_code} %{size_download} %{remote_ip}\n" \
      "$full_url" 2>/dev/null | tail -n1
  ) || { http="000"; size="0"; ip="-"; }
  
  end=$(date +%s%3N); ms=$((end-start))
  
  # Determine verdict
  local verdict="WARN"
  if head -c 8192 "$tmp" 2>/dev/null | grep -Eiq '(apptrana|access.?denied|blocked|forbidden)'; then
    verdict="BLOCK"
  elif [[ "$http" =~ ^40(3|6|9)$ || "$http" =~ ^50[0-9]$ ]]; then
    verdict="BLOCK"
  elif [[ "$http" =~ ^2[0-9][0-9]$ ]]; then
    verdict="PASS"
  fi
  
  echo "$verdict|$http|$ms|$full_url"
  rm -f "$tmp" 2>/dev/null || true
}

# Method selection prompt
select_http_method() {
  echo
  echo "HTTP Method for API tests:"
  echo "  1) GET only (demo-safe, default)"
  echo "  2) Include POST (limited state changes)"
  echo "  3) All methods (POST/PUT/DELETE - use with caution)"
  read -rp "Choice [1]: " method_choice
  
  case "${method_choice:-1}" in
    2) ENABLE_POST=true ;;
    3) ENABLE_POST=true; ENABLE_PUT=true; ENABLE_DELETE=true ;;
    *) ENABLE_POST=false ;;
  esac
}
