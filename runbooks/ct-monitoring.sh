#!/usr/bin/env bash
set -euo pipefail

domain="${1:-${CT_DOMAIN:-enclava.dev}}"
state_dir="${CT_STATE_DIR:-runbooks/audits/ct-monitoring}"
allowed_issuer_regex="${CT_ALLOWED_ISSUER_REGEX:-}"
if [ -z "$allowed_issuer_regex" ]; then
  allowed_issuer_regex="Let.s Encrypt"
fi

mkdir -p "$state_dir"
state_file="$state_dir/seen-${domain}.txt"
report_file="$state_dir/report-${domain}.json"
tmp_json="$(mktemp)"
trap 'rm -f "$tmp_json"' EXIT

curl -fsSL --retry 3 --get \
  --data-urlencode "q=%.${domain}" \
  --data-urlencode "output=json" \
  "https://crt.sh/" >"$tmp_json"

if ! jq empty "$tmp_json" >/dev/null 2>&1; then
  echo "crt.sh returned non-JSON or truncated data for ${domain}" >&2
  exit 1
fi

touch "$state_file"

jq --arg domain "$domain" --arg issuer "$allowed_issuer_regex" '
  def names:
    (.name_value // "")
    | split("\n")
    | map(select(endswith($domain) or endswith("." + $domain)))
    | unique;
  [ .[]
    | select((names | length) > 0)
    | {
        id,
        logged_at: (.entry_timestamp // ""),
        not_before,
        not_after,
        issuer_name,
        names: names,
        unexpected_issuer: ((.issuer_name // "") | test($issuer) | not)
      }
  ]
  | unique_by(.id)
  | sort_by(.id)
' "$tmp_json" >"$report_file"

jq -r '.[].id' "$report_file" | sort -n >"$state_file.current"
new_ids="$(comm -13 <(sort -n "$state_file") "$state_file.current" | paste -sd, -)"
mv "$state_file.current" "$state_file"

unexpected_count="$(jq '[.[] | select(.unexpected_issuer)] | length' "$report_file")"
total_count="$(jq 'length' "$report_file")"

echo "ct_domain=${domain}"
echo "ct_total_certificates=${total_count}"
echo "ct_new_ids=${new_ids:-none}"
echo "ct_unexpected_issuer_count=${unexpected_count}"
echo "ct_report=${report_file}"

if [ "$unexpected_count" -ne 0 ]; then
  jq -r '.[] | select(.unexpected_issuer) | [.id, .issuer_name, (.names | join(","))] | @tsv' "$report_file" >&2
  exit 2
fi
