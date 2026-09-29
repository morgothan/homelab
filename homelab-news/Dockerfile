FROM python:3.13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends gosu skopeo openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r -g 1001 appuser \
    && useradd -r -u 1001 -g appuser -m -d /home/appuser appuser

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
ENV TIKTOKEN_CACHE_DIR=/opt/tiktoken-cache
RUN python -c 'import tiktoken; tiktoken.get_encoding("cl100k_base"); tiktoken.get_encoding("o200k_base")' \
    && chmod -R a+rX /opt/tiktoken-cache
COPY *.py supervisord.conf entrypoint.sh ./
COPY homelab_news ./homelab_news
RUN chmod 0755 /app/entrypoint.sh
ENV HEADROOM_WORKSPACE_DIR=/home/appuser/.headroom
ENV DOCKER_AUTH_FILE=/home/appuser/.docker/config.json
# The /data bind-mount must be chowned to uid 1001 on the host before first run:
#   sudo chown -R 1001:1001 <dockerdir>/homelab-news/data

EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["supervisord", "-c", "/app/supervisord.conf"]
