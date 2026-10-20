FROM docker.io/library/python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY app/ ./app/

CMD ["python", "-m", "app.monitor"]
