RESET=\x1b[0m
BOLD=\x1b[1m
AQUA=\x1b[38;2;26;186;151m
ORANGE=\x1b[38;2;236;182;74m

install:
	id agents || sudo useradd agents
	sudo usermod --append --groups agents $$USER
	
	sudo chgrp agents apptainers
	sudo chmod 2775 apptainers
	
	sudo chgrp agents -R apptainers/local-share-opencode
	sudo find apptainers/local-share-opencode -type d -exec chmod 2775 {} +
	sudo find apptainers/local-share-opencode -type f -exec chmod 664 {} +

opencode: apptainers/opencode.sif
	@printf '\n$(ORANGE)Session history is broken again but session can be '
	@printf 'resumed with $(BOLD)$(AQUA)opencode -s '
	@printf 'ses_32b993f44ffeGpsiFilybTLCfH$(RESET)\n\n'
	
	@# Changing cwd breaks Opencode session history, so I'm waiting to move
	@# it
	sudo -u agents apptainer shell --containall \
		--bind .:/repo:rw \
		--bind apptainers/local-share-opencode:/home/agents/.local/share/opencode:rw \
		--cwd /home/agents apptainers/opencode.sif

require-opencode.sif:
	@if [[ $$APPTAINER_CONTAINER != */opencode.sif ]]; then \
		printf '\n!!!! Must be run inside opencode.sif !!!!\n\n' ;\
		false ;\
	fi

watch: test-watch
	while true; do \
		inotifywait --recursive --event modify --exclude .kate-swp \
			libden test; \
		make test-watch; \
	done
test-watch: apptainers/opencode.sif require-opencode.sif
	python -u -m pytest -v --tb short --server once -m quick --capture no
test-prerelease: apptainers/opencode.sif require-opencode.sif
	python -u -m pytest -v --tb short --server once -m quick
	python -u -m pytest -v --tb short --server each -m "not manual"
	python -u -m pytest -v --tb short --server each -m manual --capture no
test-postrelease: apptainers/opencode.sif require-opencode.sif
	python -u -m pytest -v --tb short --server each
	python -u -m pytest -v --tb short --server once

dev-pk: apptainers/opencode.sif
	apptainer exec --env PKSERVER_TOML=/repo/test/pkserver.toml \
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
	rm -f test/temp/*
