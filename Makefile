.PHONY: webauthn-test

RESET=\x1b[0m
BOLD=\x1b[1m
AQUA=\x1b[38;2;26;186;151m
ORANGE=\x1b[38;2;236;182;74m

install:
	id agents || sudo useradd agents
	sudo usermod --append --groups agents $$USER
	
	sudo chgrp agents apptainers
	sudo chmod 2775 apptainers
	
	sudo chgrp agents -R local-share-opencode
	sudo find local-share-opencode -type d -exec chmod 2775 {} +
	sudo find local-share-opencode -type f -exec chmod 664 {} +

opencode: apptainers/opencode.sif
	@printf '\n$(ORANGE)Session history is broken again but session can be '
	@printf 'resumed with $(BOLD)$(AQUA)opencode -s '
	@printf 'ses_32b993f44ffeGpsiFilybTLCfH$(RESET)\n\n'
	
	@# Changing cwd breaks Opencode session history, so I'm waiting to move
	@# it
	sudo -u agents apptainer shell --containall \
		--bind .:/repo:rw \
		--bind local-share-opencode:/home/agents/.local/share/opencode:rw \
		--cwd /home/agents apptainers/opencode.sif

fido2:
	python -m flask --app fido2-test.server.server:app run

require-opencode.sif:
	@if [[ $$APPTAINER_CONTAINER != */opencode.sif ]]; then \
		printf '\n!!!! Must be run inside opencode.sif !!!!\n\n' ;\
		false ;\
	fi

watch: test-watch
	while true; do \
		make test-watch; \
		inotifywait --recursive --event modify --exclude .kate-swp \
			libden test; \
	done
test-watch: apptainers/opencode.sif require-opencode.sif passkey.pem passkey-2.pem
	python -u -m pytest -v --tb short --capture no --server once -m quick
test-prerelease: apptainers/opencode.sif require-opencode.sif passkey.pem passkey-2.pem
	python -u -m pytest -v --tb short --server each
	python -u -m pytest -v --tb short --server once -m quick
test-postrelease: apptainers/opencode.sif require-opencode.sif passkey.pem passkey-2.pem
	python -u -m pytest -v --tb short --server each
	python -u -m pytest -v --tb short --server once

webauthn-test:
	python -m uvicorn webauthn-test.app-fastapi:app --use-colors --reload

dev-pk: apptainers/opencode.sif
	# LIBDEN_KEYLIST=/repo/test/keys.toml
	apptainer exec --env LIBDEN_KEYLIST=/repo/test/keys.toml \
		--bind .:/repo:ro --cwd /repo $< \
		python -m uvicorn libden.pk.server:app --use-colors \
		--port 8000 --reload

# Apptainers are built using their restricted user. This recipe creates a
# temporary directory with the permissions to allow this
apptainers/%.sif: TMP = apptainers/$*-tmp
apptainers/%.sif: apptainers/%.Definitionfile
	mkdir -p $(TMP)
	sudo chown agents $(TMP)
	sudo -u agents apptainer build $(TMP)/image.sif $<
	sudo mv $(TMP)/image.sif $@
	sudo chown $$USER:$$USER $@
	sudo rm -rf $(TMP)

apptainers/python3.14.sif: apptainers/fedora.sif
apptainers/aider.sif: apptainers/fedora.sif
apptainers/opencode-partial.sif: apptainers/python3.14.sif
apptainers/opencode.sif: apptainers/opencode-partial.sif requirements.txt

clean:
	rm -f apptainers/*.sif
	rm -rf apptainers/*-tmp



# Two scratches for trying out new CLI passkey tool (currently in agentry
# project)
scratch: passkey.pem
	curl -X POST -ksS --fail-with-body http://localhost:8000/api/challenge \
		--json '{"username": "den-antares"}' \
		> passkey-challenge.json
	python -m libden.pk.webauthn_tool register \
		--challenge "$$(jq '.challenge' passkey-challenge.json)" \
		--private-key passkey.pem \
		--origin localhost --user-id den-antares \
		> passkey-registration.json
	jq '. += { rpId: "localhost", origin: "localhost", username: "den-antares" }' \
		passkey-registration.json > passkey-registration-full.json
	curl -X POST -ksS --fail-with-body \
		http://localhost:8000/api/register-key \
		--json @passkey-registration-full.json
	@printf '\n'

scratch-2: passkey.pem
	curl -X POST -ksS --fail-with-body http://localhost:8000/api/challenge \
		--json '{"username": "den-antares"}' \
		> passkey-challenge.json
	python libden.pk.webauthn_tool authenticate \
		--challenge "$$(jq '.challenge' passkey-challenge.json)" \
		--private-key passkey.pem \
		--origin localhost --credential-id "Nn20CDS45AgdiAN0b_v7SQ" \
		> passkey-authentication.json
	jq '. += { rpId: "localhost", origin: "localhost", username: "den-antares" }' \
		passkey-authentication.json > passkey-authentication-full.json
	curl -X POST -ksS --fail-with-body \
		http://localhost:8000/api/login \
		--json @passkey-authentication-full.json
	@printf '\n'

passkey.pem:
passkey-2.pem:
	openssl ecparam -genkey -name prime256v1 -out $@
