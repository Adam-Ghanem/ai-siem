FROM python:3.11-slim
WORKDIR /app
COPY backend ./backend
COPY data ./data
RUN pip install --no-cache-dir -r backend/requirements.txt
ENV PYTHONPATH=/app
ENV AI_SIEM_HOST=0.0.0.0
ENV AI_SIEM_PORT=8000
ENV AI_SIEM_ALLOWED_ORIGIN=http://localhost:5173
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
