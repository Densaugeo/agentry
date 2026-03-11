opencode: opencode.sif
	apptainer shell --containall \
		--bind .:/work:ro \
		--bind local-share-opencode:/home/den-antares/.local/share/opencode:rw \
		--cwd /work opencode.sif

fedora.sif: fedora.Definitionfile
	apptainer build $@ $<

aider.sif: aider.Definitionfile fedora.sif
	apptainer build $@ $<

opencode.sif: opencode.Definitionfile fedora.sif
	apptainer build $@ $<

clean:
	rm *.sif
