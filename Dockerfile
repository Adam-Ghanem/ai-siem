FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && addgroup --system appgroup \
    && adduser --system --ingroup appgroup appuser
COPY backend ./backend
COPY data ./data
RUN mkdir -p logs && chown -R appuser:appgroup /app
ENV PYTHONPATH=/app
ENV AI_SIEM_HOST=0.0.0.0
ENV AI_SIEM_PORT=8000
ENV AI_SIEM_ALLOWED_ORIGIN=http://localhost:5173
USER appuser
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3).read()"
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
