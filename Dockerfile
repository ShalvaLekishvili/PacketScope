FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PACKETSCOPE_WORKDIR=/data/sessions

RUN useradd --system --uid 10001 --create-home packetscope
WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY packetscope ./packetscope
RUN python -m pip install --no-cache-dir . \
    && mkdir -p /data/sessions \
    && chown -R packetscope:packetscope /data

USER packetscope
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2).read()" || exit 1

CMD ["uvicorn", "packetscope.api:app", "--host", "0.0.0.0", "--port", "8000"]
