FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements-api.txt .
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements-api.txt

COPY dp_advice/ dp_advice/
COPY web/ web/

EXPOSE 8000

CMD ["python", "web/app.py"]
