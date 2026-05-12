FROM python:3.13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends skopeo openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py supervisord.conf .

EXPOSE 8080
CMD ["supervisord", "-c", "/app/supervisord.conf"]
