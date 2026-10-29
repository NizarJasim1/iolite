.PHONY: demo test build lint ci clean

demo:      ## run the offline end-to-end demo on bundled fixtures
	python3 -m iolite demo

test:      ## run the stdlib test suite (set ONYX_PATH to also run the compat test)
	python3 tests/run_all.py

build:     ## example: build an ONYX spec from the fixtures
	test -f engagement.json || python3 -m iolite roe-init
	python3 -m iolite build --roe engagement.json \
		--har fixtures/capture_A.har --har fixtures/capture_B.har \
		--js fixtures/app.current.js --sourcemap fixtures/app.js.map \
		--archived-js fixtures/app.archived.js \
		--graphql fixtures/graphql_introspection.json \
		--out spec.json --dossier surface.md

lint:      ## ruff (correctness rules)
	ruff check iolite tests

ci: test demo lint   ## what CI runs, locally
	@echo "ALL GREEN"

clean:
	rm -f demo_spec.json demo_surface.md spec.json surface.md engagement.json
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
