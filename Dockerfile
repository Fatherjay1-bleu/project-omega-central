# Public, read-only hackathon demonstration. Builds native engines on Linux.
FROM python:3.12-slim AS native-build
RUN apt-get update && apt-get install -y --no-install-recommends gcc g++ && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY native/ ./native/
RUN mkdir -p build \
    && gcc -std=c11 -Wall -Wextra -Werror -O2 native/validator.c -o build/validator -lm \
    && g++ -std=c++17 -Wall -Wextra -Werror -O2 native/scorer.cpp -o build/scorer

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8080
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt "gunicorn>=23,<24"
COPY app.py public_demo.py ./
COPY sentinel/ ./sentinel/
COPY data/ ./data/
COPY templates/ ./templates/
COPY --from=native-build /app/build/ ./build/
RUN useradd --create-home --uid 10001 demo && chown -R demo:demo /app
USER demo
EXPOSE 8080
CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT:-8080} --workers 1 --threads 4 --timeout 30 public_demo:application"]
