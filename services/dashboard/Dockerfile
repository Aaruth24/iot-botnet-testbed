FROM python:3.11-slim
WORKDIR /app
COPY services/dashboard/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY common/ /app/common/
COPY services/dashboard/ /app/
EXPOSE 8080
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--threads", "4", \
     "--timeout", "60", "--access-logfile", "-", "app:app"]
