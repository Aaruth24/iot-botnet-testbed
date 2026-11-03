FROM python:3.11-slim
WORKDIR /app
COPY services/ids/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY common/ /app/common/
COPY services/ids/ /app/
CMD ["python", "-u", "ids_engine.py"]
