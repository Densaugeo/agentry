set -eu -o pipefail

curl -X POST -sS --fail-with-body \
    http://localhost:8000/api/challenge \
    --json '{"username": "new-user"}' \
    > temp/curl-challenge.json

python -m libden.pk.webauthn_tool register \
    --challenge "$(jq '.challenge' temp/curl-challenge.json)" \
    --private-key unregistered.pem \
    --origin localhost --user-id "new-user" \
    > temp/curl-registration.json

curl -X POST -sS --fail-with-body \
    http://localhost:8000/api/register-key \
    --json @temp/curl-registration.json

printf '\n'
