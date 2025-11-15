FROM python:3.11-alpine

WORKDIR /app

RUN adduser -D -u 1000 mcpserver && \
    chown -R mcpserver:mcpserver /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

USER mcpserver

CMD ["python", "server.py"]
