FROM python:3.11-slim
WORKDIR /app
COPY services/orchestrator/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY common/ /app/common/
COPY services/orchestrator/ /app/
CMD ["python", "-u", "pipeline.py"]
