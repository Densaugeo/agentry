set -eu -o pipefail

curl -X POST -sS --fail-with-body \
    http://localhost:8000/api/challenge \
    --json '{"username": "test-user"}' \
    > temp/curl-challenge.json

python -m libden.pk.client login \
    --challenge "$(jq '.challenge' temp/curl-challenge.json)" \
    --private-key test-user.pem \
    --rp-id localhost \
    --origin http://localhost:8000 \
    --credential-id "Nn20CDS45AgdiAN0b_v7SQ" \
    > temp/curl-login.json

curl -X POST -sS --fail-with-body \
    http://localhost:8000/api/login \
    --json @temp/curl-login.json \
    > temp/curl-token.txt

curl -X GET -sS --fail-with-body \
    http://localhost:8000/verify \
    --cookie "token=$(jq '.token' temp/curl-token.txt)" --head

printf '\n'
