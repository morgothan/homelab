FROM python:3.13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends skopeo openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r -g 1001 appuser \
    && groupadd -r -g 996 docker \
    && useradd -r -u 1001 -g appuser -G docker -m -d /home/appuser appuser

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py supervisord.conf .
# supervisord runs as root (needs docker socket + ssh key access),
# but forks all worker processes as appuser via supervisord.conf user= directives.
# The /data bind-mount must be chowned to uid 1001 on the host before first run:
#   sudo chown -R 1001:1001 <dockerdir>/homelab-news/data

EXPOSE 8080
CMD ["supervisord", "-c", "/app/supervisord.conf"]
