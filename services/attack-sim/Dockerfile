FROM python:3.11-slim
WORKDIR /app
COPY services/attack-sim/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY common/ /app/common/
COPY services/attack-sim/ /app/
CMD ["python", "-u", "simulator.py"]
