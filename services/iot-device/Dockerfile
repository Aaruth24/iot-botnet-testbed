FROM python:3.11-slim
WORKDIR /app
COPY services/iot-device/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY common/ /app/common/
COPY services/iot-device/ /app/
CMD ["python", "-u", "device.py"]
