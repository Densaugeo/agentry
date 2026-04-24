set -eu -o pipefail

curl -X POST -sS --fail-with-body \
    http://localhost:8000/api/challenge \
    --json '{"username": "test-user"}' \
    > temp/curl-challenge.json

python -m libden.pk.webauthn_tool authenticate \
    --challenge "$(jq '.challenge' temp/curl-challenge.json)" \
    --private-key test-user.pem \
    --origin localhost --credential-id "Nn20CDS45AgdiAN0b_v7SQ" \
    > temp/curl-authentication.json

curl -X POST -sS --fail-with-body \
    http://localhost:8000/api/login \
    --json @temp/curl-authentication.json \
    > temp/curl-token.txt

curl -X GET -sS --fail-with-body \
    http://localhost:8000/verify \
    --cookie "token=$(jq '.token' temp/curl-token.txt)" --head

printf '\n'
