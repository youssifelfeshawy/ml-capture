# Base image with Python
FROM python:3.12-slim

# Install system dependencies for Scapy (libpcap for packet capture)
RUN apt-get update && apt-get install -y libpcap-dev && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy the script into the container
COPY app.py .
COPY predict.py .
COPY stage1_model.pkl .
COPY stage2_model.pkl .
COPY scaler.pkl .
COPY le_attack.pkl .
COPY encoders.pkl .
COPY requirements.txt .
COPY entrypoint.sh .

# Install requirements
RUN pip install -r requirements.txt
RUN chmod +x /app/entrypoint.sh

# Use entrypoint to run both scripts (no CMD needed, as entrypoint handles it)
ENTRYPOINT ["/app/entrypoint.sh"]
