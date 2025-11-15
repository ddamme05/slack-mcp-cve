FROM python:3.11-slim

WORKDIR /app

RUN useradd -m -u 1000 worker && \
    chown -R worker:worker /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

USER worker

CMD ["python", "worker.py"]
