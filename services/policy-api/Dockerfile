# Build context is services/ (see infra/docker-compose.yml) so the shared
# policy compiler can be installed alongside the API.
FROM python:3.13-slim
WORKDIR /app
COPY policy-compiler /src/policy-compiler
RUN pip install --no-cache-dir /src/policy-compiler
COPY policy-api/pyproject.toml .
RUN pip install --no-cache-dir .
COPY policy-api/app ./app
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8080"]
