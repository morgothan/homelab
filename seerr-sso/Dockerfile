FROM python:3.12-alpine
WORKDIR /app
RUN pip install --no-cache-dir flask requests
COPY app.py .
CMD ["python", "app.py"]
