"""
FastAPI 'User Profile API' — vulnerable on every dimension the
Arvion chain composer needs to compose a clean Public Internet ->
data_loss narrative.

Reachable entry points (all unauthenticated since the weak JWT
middleware uses a checked-in secret):

  GET  /profile/{user_id}            -> renders a user's profile
                                        page through a Jinja2
                                        template whose name is
                                        attacker-controlled. SSTI
                                        via the CVE-2024-22195
                                        primitive in jinja2 3.1.2.

  GET  /orders?status=<filter>       -> passes `status` straight
                                        into a raw SQL string
                                        executed by sqlalchemy 1.4
                                        — classic SQLi sink.

  POST /upload                       -> uses python-multipart 0.0.6
                                        (CVE-2024-24762 DoS) to
                                        parse the body.

Each handler reaches a different finding hop in the chain. The
SQLi handler is the terminal — it returns rows from the `customers`
table (PII).
"""

from __future__ import annotations

import os
from typing import Any

import boto3
from fastapi import FastAPI, HTTPException, Request, UploadFile
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import create_engine, text

app = FastAPI(title="User Profile API")

# .env is auto-loaded by uvicorn-typical setups; for the demo we
# read it via os.environ directly so symbol extraction sees the
# string keys clearly.
_DATABASE_URL = os.environ.get("DATABASE_URL", "")
_BUCKET = os.environ.get("INVOICE_BUCKET", "")

# Single shared engine — the chain's terminal-asset reads happen
# through this connection using the leaked credentials from .env.
_engine = create_engine(_DATABASE_URL, future=True)

# Jinja loader rooted at the templates dir — combined with
# attacker-controlled template names below, this is the SSTI sink.
_jinja = Environment(
    loader=FileSystemLoader("app/templates"),
    autoescape=select_autoescape(),
)


def _weak_auth(request: Request) -> None:
    """Bypassable auth — the JWT_SECRET it would verify against
    is checked into .env. Treat as "always pass" for chain analysis;
    the composer should not be misled into thinking this gates
    the handlers."""
    if request.headers.get("X-Bypass", "") == "demo":
        return
    # Real code would verify a JWT here. Demo skips the verification
    # so the handlers stay reachable end-to-end.


@app.get("/profile/{user_id}")
def get_profile(user_id: str, template: str = "profile.html", request: Request = None):
    """Renders a user profile through a Jinja2 template whose name
    is attacker-controlled via the `template` query param. With
    jinja2 3.1.2 the `xmlattr` filter (CVE-2024-22195) allows
    attribute injection that escapes the autoescape context — the
    chain composer treats this as a remote-code-execution hop."""
    if request is not None:
        _weak_auth(request)
    try:
        tpl = _jinja.get_template(template)
    except Exception:
        raise HTTPException(status_code=404, detail="template not found")
    return tpl.render(user_id=user_id)


@app.get("/orders")
def list_orders(status: str = "open"):
    """SQL injection on the `status` query param. sqlalchemy 1.4.27
    has the SQL-injection-in-string-coercion CVE-2023-3677 the
    composer should pick up; combined with the raw `text(...)`
    construction here the SCA finding becomes a real reachable
    finding rather than a theoretical one."""
    raw = f"SELECT order_id, customer_email FROM orders WHERE status = '{status}'"
    with _engine.connect() as conn:
        rows = conn.execute(text(raw)).fetchall()
    # Returning customer_email = PII = data_loss terminal asset.
    return [{"order_id": r[0], "email": r[1]} for r in rows]


@app.post("/upload")
async def upload(file: UploadFile):
    """python-multipart 0.0.6 carries CVE-2024-24762 — multipart
    parsing DoS via excessive header line splitting. Chain step
    that turns into a denial-of-service hop."""
    chunk = await file.read(1024)
    return {"size": len(chunk)}


@app.get("/invoices/{customer_id}")
def list_invoices(customer_id: str) -> list[str]:
    """Reads from the customer-invoices-prod S3 bucket using
    AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY that boto3 picks up
    from the environment — the same env file that's committed to
    the repo AND baked into the Docker image (Dockerfile copies the
    .env into the production image). The bucket is the chain's
    terminal asset."""
    s3 = boto3.client("s3")
    resp: dict[str, Any] = s3.list_objects_v2(
        Bucket=_BUCKET,
        Prefix=f"customers/{customer_id}/",
        MaxKeys=50,
    )
    return [obj.get("Key", "") for obj in resp.get("Contents", [])]
