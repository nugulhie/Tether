up: dev-env
	cd infra && docker compose up --build
# infra/.env holds per-checkout development secrets (never committed). Created once, never overwritten.
dev-env:
	@test -f infra/.env || { umask 077; printf 'CONTENT_ENCRYPTION_KEY=%s\n' "$$(python3 -c 'import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())')" > infra/.env; echo "created infra/.env with a new development CONTENT_ENCRYPTION_KEY"; }
down:
	cd infra && docker compose down
launcher:
	python3 -m venv agent-launcher/.venv && agent-launcher/.venv/bin/pip install -e agent-launcher
policy-validate:
	cd services/policy-compiler && uv run -q --python 3.13 --with-editable . tether-policy validate ../../policies
gen:
	cd services/gateway-interceptor && mkdir -p interceptor/gen && uv run -q --no-project --python 3.13 --with grpcio-tools python -m grpc_tools.protoc -Iproto --python_out=interceptor/gen --grpc_python_out=interceptor/gen proto/*.proto
test: gen
	cd services/policy-compiler && uv run -q --python 3.13 --with pytest --with-editable . pytest -q tests
	cd services/policy-api && uv run -q --no-project --python 3.13 --with pytest --with httpx --with-editable ../policy-compiler --with fastapi --with sqlalchemy --with alembic --with pydantic --with 'PyJWT[crypto]' pytest -q -p no:warnings tests
	cd services/credential-broker && uv run -q --no-project --python 3.13 --with pytest --with httpx --with fastapi --with boto3 --with 'PyJWT[crypto]' pytest -q -p no:warnings tests
	cd services/llm-gateway && uv run -q --no-project --python 3.13 --with pytest --with httpx --with fastapi pytest -q -p no:warnings tests
	cd services/sandbox-orchestrator && uv run -q --no-project --python 3.13 --with pytest --with httpx --with fastapi --with pyyaml pytest -q -p no:warnings tests
	cd services/gateway-interceptor && uv run -q --no-project --python 3.13 --with pytest --with grpcio --with protobuf --with httpx --with 'PyJWT[crypto]' --with pyyaml --with-editable ../policy-compiler pytest -q -p no:warnings tests
	cd infra/github && uv run -q --no-project --python 3.13 --with pytest --with httpx pytest -q -p no:warnings tests
	cd agent-launcher && uv run -q --no-project --python 3.13 --with pytest --with httpx --with click --with websockets pytest -q -p no:warnings tests
	cd infra/mdm && uv run -q --no-project --python 3.13 --with pytest --with pyyaml pytest -q -p no:warnings tests
	cd local-agent && uv run -q --no-project --python 3.13 --with pytest --with httpx pytest -q -p no:warnings tests
	cd infra/gpu/network && uv run -q --no-project --python 3.13 --with pytest --with pyyaml pytest -q -p no:warnings tests
	cd infra/gpu/signing && uv run -q --no-project --python 3.13 --with pytest --with cryptography pytest -q -p no:warnings tests
# Release gate (ADR 0002, A-6): the built images talking to each other in development mode.
SMOKE = cd infra && docker compose -p tether-smoke -f docker-compose.yml -f ci/compose.smoke.yml
smoke: dev-env
	$(SMOKE) up -d --build --wait postgres policy-api credential-broker llm-gateway sandbox-orchestrator
	python3 infra/ci/smoke.py; rc=$$?; $(SMOKE) logs --no-color > infra/ci/smoke.log 2>&1; $(SMOKE) down -v; exit $$rc
launcher-pkg:
	cd agent-launcher && ./packaging/build-macos.sh
gpu-network:
	cd infra/gpu/network && uv run -q --no-project --python 3.13 --with pyyaml python generate.py
mdm:
	cd infra/mdm && uv run -q --no-project --python 3.13 --with pyyaml python generate.py
