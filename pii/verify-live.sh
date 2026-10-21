#!/usr/bin/env bash
# Live verification of a running PII sterilization service and its real
# recall model (the unit tests use a stub; this is the check against the
# model itself):
#
#   PII_API_KEY=<the service's key> pii/verify-live.sh [host:port]
#
# host:port defaults to 127.0.0.1:8091, where pii.service binds.
set -u
HOST="${1:-127.0.0.1:8091}"
KEY="${PII_API_KEY:-}"
[ -n "$KEY" ] || { echo "set PII_API_KEY to the service's key"; exit 1; }

pass=0; fail=0
ok()  { pass=$((pass+1)); echo "ok   $1"; }
bad() { fail=$((fail+1)); echo "FAIL $1"; }

post() { # path json -> body
  curl -sf -m 600 -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
       -d "$2" "http://$HOST$1"
}
jget() { # json pyexpr
  python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"
}

# 1. health, no auth
curl -sf "http://$HOST/health" >/dev/null && ok "health" || bad "health"

# 2. auth enforced
code=$(curl -s -o /dev/null -w '%{http_code}' -d '{"text":"x"}' "http://$HOST/sterilize")
[ "$code" = 401 ] && ok "auth fail-closed (401 without key)" || bad "auth: got $code"

SCOPE="verify-$$"

# 3. rules-class PII all tokenized
T1='Marisol Vega (SSN 123-45-6789) can be reached at marisol.vega@example.com or (415) 555-0173. Card on file: 4111 1111 1111 1111. Her laptop is 10.20.30.44 / aa:bb:cc:dd:ee:01.'
R1=$(post /sterilize "$(python3 -c "import json;print(json.dumps({'text':'''$T1''','scope':'$SCOPE'}))")")
leak=$(echo "$R1" | jget "sum(x in d['text'] for x in ['Marisol','123-45-6789','marisol.vega','555-0173','4111','10.20.30.44','aa:bb:cc:dd:ee:01'])")
[ "$leak" = 0 ] && ok "sterilize: no rules-class or name leakage" || bad "sterilize leaked $leak spans: $(echo "$R1" | jget "d['text']")"

# 4. contextual PII a pattern cannot see (why the recall model is there)
T2='My daughter goes to Lincoln Elementary and we live at 4012 Maple Court. She sees Dr. Okafor for her asthma.'
R2=$(post /sterilize "$(python3 -c "import json;print(json.dumps({'text':'''$T2''','scope':'$SCOPE','verify':True}))")")
leak=$(echo "$R2" | jget "sum(x in d['text'] for x in ['Lincoln','4012','Maple','Okafor','asthma'])")
[ "$leak" = 0 ] && ok "contextual: school/address/doctor/medical caught" || bad "contextual leaked $leak: $(echo "$R2" | jget "d['text']")"

# 5. round trip back to the original
B1=$(post /rehydrate "$(echo "$R1" | jget "json.dumps({'text': d['text'], 'scope': '$SCOPE'})")")
same=$(echo "$B1" | jget "d['text'] == '''$T1'''")
[ "$same" = True ] && ok "rehydrate: byte-identical round trip" || bad "rehydrate mismatch"

# 6. token stability within scope
R3=$(post /sterilize "$(python3 -c "import json;print(json.dumps({'text':'Ping marisol.vega@example.com again.','scope':'$SCOPE'}))")")
tok1=$(echo "$R1" | jget "[f['token'] for f in d['findings'] if f['type']=='EMAIL'][0]")
stable=$(echo "$R3" | jget "'$tok1' in d['text']")
[ "$stable" = True ] && ok "stable token reuse in scope ($tok1)" || bad "token not stable"

# 7. scope isolation on recall
B2=$(post /rehydrate "$(echo "$R1" | jget "json.dumps({'text': d['text'], 'scope': 'other-scope'})")")
n=$(echo "$B2" | jget "d['restored']")
[ "$n" = 0 ] && ok "scope isolation: foreign scope restores nothing" || bad "cross-scope restore: $n"

# 8. non-PII technical text byte-identical
T4='Set net.core.rmem_max=26214400, then restart the collector; DSA ports stay tagged.'
R4=$(post /sterilize "$(python3 -c "import json;print(json.dumps({'text':'''$T4''','scope':'$SCOPE'}))")")
same=$(echo "$R4" | jget "d['text'] == '''$T4'''")
[ "$same" = True ] && ok "non-PII text untouched" || bad "non-PII mutated: $(echo "$R4" | jget "d['text']")"

echo "pii live verify: $pass/$((pass+fail))"
[ "$fail" = 0 ]
