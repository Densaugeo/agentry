set -eu -o pipefail

curl -X POST -sS --fail-with-body \
    http://localhost:8000/api/challenge \
    --json '{"username": "den-antares"}' \
    > temp/curl-challenge.json

python -m libden.pk.webauthn_tool register \
    --challenge "$(jq '.challenge' temp/curl-challenge.json)" \
    --private-key passkey.pem \
    --origin localhost --user-id "den-antares" \
    > temp/curl-registration.json

jq '. += { username: "den-antares" }' \
    temp/curl-registration.json > temp/curl-registration-full.json

curl -X POST -sS --fail-with-body \
    http://localhost:8000/api/register-key \
    --json @temp/curl-registration-full.json

printf '\n'
