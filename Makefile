SHELL := /bin/sh
HELPER_IMAGE := ghcr.io/cenab/airgapproof-helper:0.1.0

.PHONY: build test check helper demo-prepare demo integration dashboard
build:
	mkdir -p bin
	go build -trimpath -o bin/airgapproof ./cmd/airgapproof

test:
	go test -race ./...

check: test
	go vet ./...
	test -z "$$(gofmt -l cmd internal)"

helper:
	docker build -f Dockerfile.helper -t $(HELPER_IMAGE) .

demo-prepare: build helper
	docker build --target remote -t airgapproof-demo:remote examples/ai-app
	docker build --target bundled -t airgapproof-demo:offline examples/ai-app
	bin/airgapproof prepare --config examples/ai-app/airgapproof.yaml

demo: demo-prepare
	bin/airgapproof test --config examples/ai-app/airgapproof.yaml --report reports/offline
	@status=0; bin/airgapproof test --config examples/ai-app/airgapproof.yaml --compose examples/ai-app/compose.remote.yaml --report reports/remote || status=$$?; test "$$status" -eq 1
	python3 scripts/check-demo.py reports/offline/report.json reports/remote/report.json

integration: build
	AIRGAPPROOF_INTEGRATION=1 go test -v ./internal/run ./internal/dashboard

dashboard: build
	docker compose -f deploy/compose.yaml up --build -d
