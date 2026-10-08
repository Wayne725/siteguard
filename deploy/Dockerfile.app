FROM python:3.13-slim@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY local_ddos_lab/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY local_ddos_lab/*.py ./
COPY local_ddos_lab/index.html local_ddos_lab/ui.js ./
RUN mkdir -p runtime
CMD ["python", "-m", "uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-access-log"]
