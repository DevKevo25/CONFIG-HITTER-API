FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY decryptors/ ./decryptors/
COPY app.py .

ENV PORT=5000
EXPOSE $PORT

CMD ["python", "app.py"]