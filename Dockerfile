FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libmagic1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements-dev.txt ./
RUN pip install -r requirements.txt \
    && pip install openpyxl

COPY . .

RUN useradd --create-home --uid 1000 deepeye \
    && mkdir -p reports data logs \
    && chown -R deepeye:deepeye /app
USER deepeye

ENTRYPOINT ["python", "deep_eye.py"]
CMD ["--help"]
