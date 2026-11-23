up:
	cd infra && docker compose up --build
down:
	cd infra && docker compose down
launcher:
	python3 -m venv agent-launcher/.venv && agent-launcher/.venv/bin/pip install -e agent-launcher
policy-validate:
	cd services/policy-compiler && uv run -q --python 3.13 --with-editable . company-policy validate ../../policies
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
launcher-pkg:
	cd agent-launcher && ./packaging/build-macos.sh
mdm:
	cd infra/mdm && uv run -q --no-project --python 3.13 --with pyyaml python generate.py
