FROM python:3.11-slim

WORKDIR /app

# Install netcat/iproute2 for basic network diagnostics if needed
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 netcat-traditional && rm -rf /var/lib/apt/lists/*

COPY switch_server.py /app/switch_server.py

EXPOSE 8583

CMD ["python", "-u", "switch_server.py"]