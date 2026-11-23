FROM python:3.13-slim
WORKDIR /app
COPY pyproject.toml .
COPY gateway ./gateway
RUN pip install --no-cache-dir .
CMD ["uvicorn","gateway.main:app","--host","0.0.0.0","--port","8082"]
