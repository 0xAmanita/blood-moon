#!/usr/bin/env bash

# crawler.sh - crawl a target with katana, fetch each URL, and then scan for exposed secrets.
# For AUTHORIZED penetration testing only. Do not run against systems you don't own or lack permission to test.
# By: 0xAmanita & yvaar

set -uo pipefail

TARGET=""
DEPTH=3
CONCURRENCY=10
OUTDIR="./secret-crawl-$(date +%Y%m%d-%H%M%S)"
TIMEOUT=15
UA="Mozilla/5.0 (compatible; secret-crawler/1.0; +authorized-pentest)"
RATE_DELAY=0        # seconds between curls, bump up to be gentle
COOKIE=""           # e.g. "session=abc123" for authenticated crawls
HEADERS=()          # extra headers, e.g. -H "Authorization: Bearer x"

usage() {
  cat <<EOF
Usage: $0 -u <target-url> [options]

  -u   Target URL (required), e.g. https://example.com
  -d   Crawl depth               (default: $DEPTH)
  -c   Concurrency for scanning  (default: $CONCURRENCY)
  -o   Output directory          (default: timestamped dir)
  -t   Curl timeout seconds      (default: $TIMEOUT)
  -r   Delay between requests    (default: $RATE_DELAY)
  -C   Cookie string for authed crawl
  -H   Extra header (repeatable)
  -h   Help

Example:
  $0 -u https://example.com -d 3 -c 15 -r 0.2
EOF
  exit 1
}

while getopts "u:d:c:o:t:r:C:H:h" opt; do
  case $opt in
    u) TARGET="$OPTARG" ;;
    d) DEPTH="$OPTARG" ;;
    c) CONCURRENCY="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    t) TIMEOUT="$OPTARG" ;;
    r) RATE_DELAY="$OPTARG" ;;
    C) COOKIE="$OPTARG" ;;
    H) HEADERS+=("$OPTARG") ;;
    h|*) usage ;;
  esac
done

[[ -z "$TARGET" ]] && usage
command -v katana >/dev/null 2>&1 || { echo "[!] katana not found. Install: go install github.com/projectdiscovery/katana/cmd/katana@latest"; exit 1; }
command -v curl   >/dev/null 2>&1 || { echo "[!] curl not found."; exit 1; }

mkdir -p "$OUTDIR"
URLS_FILE="$OUTDIR/urls.txt"
FINDINGS="$OUTDIR/findings.txt"
BODIES_DIR="$OUTDIR/bodies"
mkdir -p "$BODIES_DIR"

echo "[*] Target: $TARGET"
echo "[*] Output: $OUTDIR"

# CRAWL
echo "[*] Running katana..."
KATANA_ARGS=(-u "$TARGET" -d "$DEPTH" -jc -kf all -silent -o "$URLS_FILE")
[[ -n "$COOKIE" ]] && KATANA_ARGS+=(-H "Cookie: $COOKIE")
for h in "${HEADERS[@]:-}"; do [[ -n "$h" ]] && KATANA_ARGS+=(-H "$h"); done

katana "${KATANA_ARGS[@]}"
URL_COUNT=$(wc -l < "$URLS_FILE" 2>/dev/null || echo 0)
echo "[*] Found $URL_COUNT URLs."
[[ "$URL_COUNT" -eq 0 ]] && { echo "[!] No URLs. Exiting."; exit 0; }

# SECRET PATTERNS
# Each entry: NAME|PCRE-regex. Grep runs with -P (Perl regex).
PATTERNS=(
  'AWS_Access_Key|AKIA[0-9A-Z]{16}'
  'AWS_Secret_Key|(?i)aws.{0,20}?(secret|access).{0,20}?[=:\"'"'"' ]([0-9a-zA-Z/+]{40})'
  'Google_API_Key|AIza[0-9A-Za-z_\-]{35}'
  'Google_OAuth|ya29\.[0-9A-Za-z_\-]+'
  'GitHub_Token|gh[pousr]_[0-9a-zA-Z]{36,255}'
  'GitHub_Classic|github_pat_[0-9a-zA-Z_]{22,255}'
  'Slack_Token|xox[baprs]-[0-9a-zA-Z\-]{10,72}'
  'Slack_Webhook|hooks\.slack\.com/services/[A-Za-z0-9/]+'
  'Stripe_Live|sk_live_[0-9a-zA-Z]{24,}'
  'Stripe_Restricted|rk_live_[0-9a-zA-Z]{24,}'
  'Twilio_SID|AC[a-z0-9]{32}'
  'SendGrid|SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}'
  'Mailgun|key-[0-9a-zA-Z]{32}'
  'Private_Key|-----BEGIN (RSA|EC|DSA|OPENSSH|PGP)? ?PRIVATE KEY-----'
  'JWT|eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'
  'Generic_API_Key|(?i)(api[_\-]?key|apikey)["'"'"' :=]+["'"'"' ]?[0-9a-zA-Z\-_]{16,64}'
  'Generic_Secret|(?i)(secret|token|passwd|password|pwd)["'"'"' :=]+["'"'"' ]?[^\s"'"'"'<>]{6,64}'
  'Bearer_Token|(?i)authorization:\s*bearer\s+[0-9a-zA-Z._\-]{10,}'
  'Basic_Auth_URL|[a-zA-Z]+://[^/\s:@]+:[^/\s:@]+@'
  'Heroku_Key|(?i)heroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
  'DB_Connection|(?i)(mongodb(\+srv)?|postgres(ql)?|mysql|redis)://[^\s"'"'"'<>]+'
  'Firebase|(?i)firebase.{0,30}["'"'"' :=]AIza[0-9A-Za-z_\-]{35}'
  'NPM_Token|npm_[0-9a-zA-Z]{36}'
  'Digital_Ocean|dop_v1_[a-f0-9]{64}'
)

# FETCH + SCAN
: > "$FINDINGS"

scan_url() {
  local url="$1"
  local safe body
  safe=$(echo -n "$url" | md5sum | cut -d' ' -f1)
  body="$BODIES_DIR/$safe.body"

  local curl_args=(-sSL --max-time "$TIMEOUT" -A "$UA" --compressed -o "$body" -w '%{http_code}')
  [[ -n "$COOKIE" ]] && curl_args+=(-b "$COOKIE")
  for h in "${HEADERS[@]:-}"; do [[ -n "$h" ]] && curl_args+=(-H "$h"); done

  local code
  code=$(curl "${curl_args[@]}" "$url" 2>/dev/null) || { rm -f "$body"; return; }
  [[ ! -s "$body" ]] && { rm -f "$body"; return; }

  local hit=0
  for entry in "${PATTERNS[@]}"; do
    local name="${entry%%|*}"
    local rx="${entry#*|}"
    local matches
    matches=$(grep -aoP "$rx" "$body" 2>/dev/null | sort -u | head -20)
    if [[ -n "$matches" ]]; then
      hit=1
      {
        echo "=================================================="
        echo "URL   : $url"
        echo "HTTP  : $code"
        echo "TYPE  : $name"
        echo "--------------------------------------------------"
        echo "$matches" | sed 's/^/  /'
        echo ""
      } >> "$FINDINGS"
    fi
  done

  if [[ "$hit" -eq 1 ]]; then
    echo "[+] SECRET  $code  $url"
  else
    echo "[-] clean   $code  $url"
    rm -f "$body"   # keep only bodies with hits
  fi

  [[ "$RATE_DELAY" != "0" ]] && sleep "$RATE_DELAY"
}
export -f scan_url
export BODIES_DIR FINDINGS TIMEOUT UA COOKIE RATE_DELAY
export PATTERNS_STR="$(printf '%s\n' "${PATTERNS[@]}")"

# xargs can't easily see the bash array, so re-hydrate patterns inside subshell:
# simpler: run sequentially if concurrency=1, else use xargs with a wrapper.
run_parallel() {
  # write a small worker that reloads patterns
  export -f scan_url
  # rebuild PATTERNS in each subshell via env
  mapfile -t _P <<< "$PATTERNS_STR"
  PATTERNS=("${_P[@]}")
  export PATTERNS
  scan_url "$1"
}

echo "[*] Scanning $URL_COUNT URLs (concurrency=$CONCURRENCY)..."
if [[ "$CONCURRENCY" -le 1 ]]; then
  while IFS= read -r u; do [[ -n "$u" ]] && scan_url "$u"; done < "$URLS_FILE"
else
  # Because bash arrays don't export, invoke a fresh bash that re-sources this script's patterns via a temp function file.
  WORKER="$OUTDIR/.worker.sh"
  {
    echo '#!/usr/bin/env bash'
    echo 'set -uo pipefail'
    declare -p PATTERNS
    echo "BODIES_DIR='$BODIES_DIR'; FINDINGS='$FINDINGS'; TIMEOUT='$TIMEOUT'; UA='$UA'; COOKIE='$COOKIE'; RATE_DELAY='$RATE_DELAY'"
    declare -f scan_url
    echo 'scan_url "$1"'
  } > "$WORKER"
  chmod +x "$WORKER"
  grep -v '^\s*$' "$URLS_FILE" | xargs -P "$CONCURRENCY" -I{} bash "$WORKER" "{}"
  rm -f "$WORKER"
fi

# REPORT
echo ""
echo "=================================================="
if [[ -s "$FINDINGS" ]]; then
  HITS=$(grep -c '^URL' "$FINDINGS")
  echo "[!] $HITS finding(s). See: $FINDINGS"
  echo "[*] Response bodies with hits: $BODIES_DIR"
else
  echo "[*] No secrets found."
fi
echo "[*] URL list: $URLS_FILE"
