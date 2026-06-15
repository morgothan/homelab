FROM python:3.12-slim
RUN pip install --no-cache-dir 'headroom-ai[proxy]'
EXPOSE 8787
CMD ["headroom", "proxy", "--host", "0.0.0.0", "--stateless", "--no-telemetry"]
