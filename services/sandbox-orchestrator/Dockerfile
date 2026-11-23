# The image must also contain the OpenShell CLI and the orchestrator's gateway identity
# (OPENSHELL_GATEWAY / mTLS bundle / OIDC client credentials), mounted from secrets.
FROM python:3.13-slim
WORKDIR /app
COPY pyproject.toml .
COPY orchestrator ./orchestrator
RUN pip install --no-cache-dir .
CMD ["uvicorn","orchestrator.main:app","--host","0.0.0.0","--port","8083"]
