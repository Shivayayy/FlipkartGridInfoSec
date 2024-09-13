FROM python:3.11.1

WORKDIR /app

COPY req.txt .
RUN pip install --no-cache-dir -r req.txt

# Install RabbitMQ server, Java, and download ZAP
RUN apt-get update && apt-get install -y \
    rabbitmq-server \
    wget \
    openjdk-11-jdk \
    && wget https://github.com/zaproxy/zaproxy/releases/download/v2.15.0/ZAP_2.15.0_Linux.tar.gz \
    && tar -xvzf ZAP_2.15.0_Linux.tar.gz \
    && rm -rf ZAP_2.15.0_Linux.tar.gz \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# Expose port 8000
EXPOSE 8000

# Start RabbitMQ, Celery, ZAP, and Django server
CMD ["sh", "-c", "service rabbitmq-server start && celery -A apiSecurityShield worker --loglevel=error & nohup ./ZAP_2.15.0/zap.sh -daemon > zap.log 2>&1 & python manage.py runserver"]
