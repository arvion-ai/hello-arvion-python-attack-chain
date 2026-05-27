# INTENTIONALLY MISCONFIGURED — three IaC violations the Arvion
# scanner should pick up:
#
#   1. Runs as root (no USER directive). RCE via SSTI immediately
#      escalates to root-on-container.
#   2. Copies the entire repo (.env included) into the image with a
#      blanket `COPY . .`. The .env containing AWS keys ships
#      baked into the production image.
#   3. EXPOSEs 0.0.0.0:8000 without a reverse proxy / TLS, and
#      doesn't drop capabilities or set --read-only on the FS.

FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Blanket copy — includes .env with leaked credentials.
COPY . .

EXPOSE 8000

# No USER directive — runs as root.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
