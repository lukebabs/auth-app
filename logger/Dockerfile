FROM python:3.11-slim

WORKDIR /logger

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=5001
CMD ["python", "logger_service.py"]
