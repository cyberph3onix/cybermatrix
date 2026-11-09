FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 UV_PYTHON_DOWNLOADS=never UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv
RUN pip install --no-cache-dir uv==0.12.12 && useradd --create-home --uid 10001 app
WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY app ./app
COPY data ./data
# Bake the dnstwist lookalike index (~300k permutations, ~10 s of CPU here, minutes on a 0.1-CPU host) into the
# image so a cold start only loads data/.cache/permutations-*.json.gz instead of rebuilding it.
RUN /app/.venv/bin/python -c "from app.checks.lookalike import permutation_index; print(len(permutation_index()), 'lookalike permutations cached')"
# data/ is written at runtime: the OpenPhish feed and the dnstwist permutation cache.
RUN chown -R app:app /app/data
USER app

EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=60s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"
CMD ["/app/.venv/bin/uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
