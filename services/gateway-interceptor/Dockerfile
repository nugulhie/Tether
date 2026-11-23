FROM python:3.13-slim
WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir grpcio-tools "grpcio>=1.66" "protobuf>=5.27" httpx "PyJWT[crypto]" PyYAML
COPY proto ./proto
COPY interceptor ./interceptor
# Generate stubs with the same protobuf runtime that serves them.
RUN mkdir -p interceptor/gen && python -m grpc_tools.protoc -Iproto --python_out=interceptor/gen --grpc_python_out=interceptor/gen proto/*.proto
# Company provider profiles are mounted at /profiles (openshell/profiles in this repository).
CMD ["python","-m","interceptor.server"]
