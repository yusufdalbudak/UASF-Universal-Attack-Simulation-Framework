#!/usr/bin/env bash
# Evasion Library for UASF
# Provides encoding and obfuscation functions for WAF bypass testing

# URL encode a string
urlencode() {
  local string="${1:-}"
  local strlen=${#string}
  local encoded=""
  local pos c o
  
  for (( pos=0 ; pos<strlen ; pos++ )); do
    c=${string:$pos:1}
    case "$c" in
      [-_.~a-zA-Z0-9]) o="$c" ;;
      *) printf -v o '%%%02X' "'$c" ;;
    esac
    encoded+="$o"
  done
  echo "$encoded"
}

# Double URL encode
double_urlencode() {
  urlencode "$(urlencode "${1:-}")"
}

# Triple URL encode (for deep WAF bypass)
triple_urlencode() {
  urlencode "$(urlencode "$(urlencode "${1:-}")")"
}

# Hex encode
hexencode() {
  echo -n "${1:-}" | xxd -p 2>/dev/null | tr -d '\n'
}

# Base64 encode
b64encode() {
  echo -n "${1:-}" | base64 2>/dev/null
}

# Unicode encode (\uXXXX format)
unicode_encode() {
  local string="${1:-}"
  local result=""
  for (( i=0; i<${#string}; i++ )); do
    local char="${string:$i:1}"
    local hex
    printf -v hex '%02X' "'$char"
    result+="\\u00$hex"
  done
  echo "$result"
}

# HTML entity encode
html_encode() {
  local string="${1:-}"
  local result=""
  for (( i=0; i<${#string}; i++ )); do
    local char="${string:$i:1}"
    local dec
    printf -v dec '%d' "'$char"
    result+="&#$dec;"
  done
  echo "$result"
}

# Mixed case transform (for case-insensitive bypass)
mixcase() {
  local string="${1:-}"
  local result=""
  for (( i=0; i<${#string}; i++ )); do
    local char="${string:$i:1}"
    if (( RANDOM % 2 )); then
      result+=$(echo "$char" | tr '[:lower:]' '[:upper:]')
    else
      result+=$(echo "$char" | tr '[:upper:]' '[:lower:]')
    fi
  done
  echo "$result"
}

# Insert SQL comments (/**/) between characters
comment_insert() {
  local string="${1:-}"
  local result=""
  for (( i=0; i<${#string}; i++ )); do
    result+="${string:$i:1}"
    if (( i < ${#string} - 1 )); then
      result+="/**/"
    fi
  done
  echo "$result"
}

# Whitespace variant (use tabs, newlines instead of spaces)
whitespace_variant() {
  local payload="${1:-}"
  local variants=('%09' '%0A' '%0C' '%0D' '%A0')
  local variant="${variants[$((RANDOM % ${#variants[@]}))]}"
  echo "${payload// /$variant}"
}

# Generate evasion variants for a payload
generate_evasion_variants() {
  local payload="${1:-}"
  [[ -z "$payload" ]] && return
  
  local variants=()
  
  variants+=("$payload")                          # Original
  variants+=("$(urlencode "$payload")")           # URL encoded
  variants+=("$(double_urlencode "$payload")")    # Double encoded
  variants+=("$(mixcase "$payload")")             # Mixed case
  variants+=("$(whitespace_variant "$payload")")  # Whitespace variant
  
  # Output one per line
  printf '%s\n' "${variants[@]}"
}

# Apply random evasion technique
random_evasion() {
  local payload="${1:-}"
  [[ -z "$payload" ]] && return
  
  local techniques=(
    "urlencode"
    "double_urlencode"
    "mixcase"
    "whitespace_variant"
    "comment_insert"
  )
  local technique="${techniques[$((RANDOM % ${#techniques[@]}))]}"
  $technique "$payload"
}
