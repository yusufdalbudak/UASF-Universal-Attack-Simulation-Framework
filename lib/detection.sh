#!/usr/bin/env bash
# Detection Library for UASF
# WAF detection heuristics and fingerprinting
# Compatible with bash 3.x (no associative arrays)

# Detect WAF from response headers and body
# Uses pattern matching instead of associative arrays for compatibility
detect_waf() {
  local response_file="${1:-}"
  
  [[ -z "$response_file" || ! -f "$response_file" ]] && echo "unknown" && return
  
  local content
  content=$(head -c 16384 "$response_file" 2>/dev/null) || content=""
  
  # Check each WAF pattern
  if echo "$content" | grep -Eiq "apptrana|indusface"; then
    echo "apptrana"
  elif echo "$content" | grep -Eiq "cloudflare|cf-ray|__cfduid|cf-request-id"; then
    echo "cloudflare"
  elif echo "$content" | grep -Eiq "akamai|akamai-ghost|akamaighost|x-akamai"; then
    echo "akamai"
  elif echo "$content" | grep -Eiq "awselb|x-amz|aws-waf|x-amzn"; then
    echo "aws_waf"
  elif echo "$content" | grep -Eiq "incapsula|visid_incap|x-iinfo|x-cdn:imperva"; then
    echo "imperva"
  elif echo "$content" | grep -Eiq "mod.?security|owasp|modsec|mod_security"; then
    echo "modsecurity"
  elif echo "$content" | grep -Eiq "x-wa-info|bigip|f5|asm"; then
    echo "f5_bigip"
  elif echo "$content" | grep -Eiq "sucuri|x-sucuri"; then
    echo "sucuri"
  elif echo "$content" | grep -Eiq "barracuda|bwaf"; then
    echo "barracuda"
  elif echo "$content" | grep -Eiq "fortigate|fortiweb|fortinetfw"; then
    echo "fortinet"
  elif echo "$content" | grep -Eiq "palo.?alto|panw"; then
    echo "palo_alto"
  elif echo "$content" | grep -Eiq "radware|appwall"; then
    echo "radware"
  elif echo "$content" | grep -Eiq "citrix|netscaler"; then
    echo "citrix"
  elif echo "$content" | grep -Eiq "wallarm|x-wallarm"; then
    echo "wallarm"
  elif echo "$content" | grep -Eiq "reblaze|x-reblaze"; then
    echo "reblaze"
  else
    echo "unknown"
  fi
}

# Check if response indicates a block
is_blocked() {
  local http_code="${1:-0}"
  local response_file="${2:-}"
  
  # Check HTTP code first
  if [[ "$http_code" =~ ^40(3|6|9)$ || "$http_code" == "451" || "$http_code" =~ ^5[0-9][0-9]$ ]]; then
    return 0
  fi
  
  # Check for block signatures in body
  local block_patterns="access.?denied|request.?was.?blocked|not.?acceptable|forbidden|web.?application.?firewall|security.?policy|blocked.?by|attack.?detected|malicious.?request|unauthorized.?access|your.?ip.?has.?been.?blocked"
  
  if [[ -n "$response_file" && -f "$response_file" ]]; then
    if head -c 8192 "$response_file" 2>/dev/null | grep -Eiq "$block_patterns"; then
      return 0
    fi
  fi
  
  return 1
}

# Determine detailed verdict
get_verdict() {
  local http_code="${1:-0}"
  local response_file="${2:-}"
  local category="${3:-}"
  
  local waf_detected="unknown"
  if [[ -n "$response_file" && -f "$response_file" ]]; then
    waf_detected=$(detect_waf "$response_file")
  fi
  
  if is_blocked "$http_code" "$response_file"; then
    echo "BLOCK|$waf_detected"
    return
  fi
  
  case "$http_code" in
    2[0-9][0-9])
      if [[ "$category" == "redirect" && -n "$response_file" && -f "$response_file" ]]; then
        if head -c 4096 "$response_file" | grep -qi "location:.*evil\|location:.*http://"; then
          echo "PASS|exploit_confirmed"
          return
        fi
      fi
      if [[ "$waf_detected" != "unknown" ]]; then
        echo "WARN|$waf_detected"
      else
        echo "ALLOW|none"
      fi
      ;;
    3[0-9][0-9])
      echo "REDIRECT|$waf_detected"
      ;;
    404)
      echo "NOT_FOUND|$waf_detected"
      ;;
    429)
      echo "RATE_LIMITED|$waf_detected"
      ;;
    *)
      echo "WARN|$waf_detected"
      ;;
  esac
}

# Rate limit detection
detect_rate_limit() {
  local url="${1:-}"
  local requests="${2:-50}"
  local blocked=0
  local block_threshold=0
  local cid="${CID:-UASF-test}"
  
  [[ -z "$url" ]] && echo "ERROR|no_url" && return
  
  echo "Testing rate limit with $requests requests..."
  
  for i in $(seq 1 "$requests"); do
    local code
    code=$(curl -sS -o /dev/null -w "%{http_code}" \
      -H "X-UASF-Correlation: $cid" \
      --max-time 3 "$url?rate_test=$i" 2>/dev/null) || code="000"
    
    if [[ "$code" == "429" || "$code" =~ ^5[0-9][0-9]$ ]]; then
      block_threshold=$i
      blocked=1
      break
    fi
  done
  
  if [[ $blocked -eq 1 ]]; then
    echo "RATE_LIMIT_DETECTED|threshold=$block_threshold"
  else
    echo "NO_RATE_LIMIT|requests=$requests"
  fi
}

# Bot detection test
test_bot_detection() {
  local url="${1:-}"
  local ua="${2:-}"
  local cid="${CID:-UASF-test}"
  
  [[ -z "$url" || -z "$ua" ]] && echo "ERROR|missing_params" && return
  
  local code
  code=$(curl -sS -o /dev/null -w "%{http_code}" \
    -A "$ua" \
    -H "X-UASF-Correlation: $cid" \
    --max-time 5 "$url" 2>/dev/null) || code="000"
  
  if [[ "$code" =~ ^40(3|6|9)$ || "$code" == "429" ]]; then
    echo "BLOCKED|$ua"
  else
    echo "ALLOWED|$ua|$code"
  fi
}
