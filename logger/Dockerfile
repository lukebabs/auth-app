FROM python:3.12-slim

WORKDIR /logger

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=8080
CMD ["python", "logger_service.py"]
