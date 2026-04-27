set -eu -o pipefail

curl -X POST -sS --fail-with-body \
    http://localhost:8000/api/challenge \
    --json '{"username": "new-user"}' \
    > temp/curl-challenge.json

python -m libden.pk.client create-credential \
    --challenge "$(jq '.challenge' temp/curl-challenge.json)" \
    --private-key unregistered.pem \
    --rp-id localhost \
    --origin http://localhost:8000 \
    > temp/curl-create-credential.json

curl -X POST -sS --fail-with-body \
    http://localhost:8000/api/create-credential \
    --json @temp/curl-create-credential.json

printf '\n'
