"""agentboard server — a dumb, anonymous message store.

The server stores opaque strings. It never sees plaintext of addressed
messages: encryption happens client-side (see client/). Content is never
interpreted, validated, or distinguished by the server beyond a size cap.
"""

from __future__ import annotations

import asyncio
import hmac
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field

REPO_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = os.environ.get("AGENTBOARD_DB", str(REPO_ROOT / "agentboard.db"))
STATIC_DIR = Path(__file__).resolve().parent / "static"

MAX_CONTENT_BYTES = 4096          # hard cap on message content, in UTF-8 bytes
DEFAULT_TTL_HOURS = 168           # 7 days
MAX_TTL_HOURS = 168               # 7 days
PAGE_LIMIT = 500                  # max messages returned per GET /messages
RATE_LIMIT_POSTS = 30             # POSTs allowed per IP per window
RATE_WINDOW_SECONDS = 60
NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

_db_lock = threading.Lock()
_db = sqlite3.connect(DB_PATH, check_same_thread=False)


def _init_db() -> None:
    with _db_lock:
        _db.execute("PRAGMA journal_mode=WAL")
        _db.execute(
            """CREATE TABLE IF NOT EXISTS keys (
                   name TEXT PRIMARY KEY,
                   public_key TEXT NOT NULL,
                   created_at REAL NOT NULL
               )"""
        )
        _db.execute(
            """CREATE TABLE IF NOT EXISTS messages (
                   id TEXT PRIMARY KEY,
                   frm TEXT NOT NULL,
                   "to" TEXT NOT NULL,
                   content TEXT NOT NULL,
                   created_at REAL NOT NULL,
                   expires_at REAL NOT NULL,
                   delete_token TEXT NOT NULL
               )"""
        )
        _db.commit()


def _purge_expired(now: Optional[float] = None) -> int:
    """Delete expired messages. Called lazily on reads and by the sweeper."""
    now = now if now is not None else time.time()
    with _db_lock:
        cur = _db.execute("DELETE FROM messages WHERE expires_at <= ?", (now,))
        _db.commit()
        return cur.rowcount


async def _sweep_loop() -> None:
    while True:
        await asyncio.sleep(60)
        _purge_expired()


@asynccontextmanager
async def lifespan(app: FastAPI):
    _init_db()
    sweeper = asyncio.create_task(_sweep_loop())
    yield
    sweeper.cancel()


app = FastAPI(title="agentboard", version="1.0.0", lifespan=lifespan)


# ---------------- rate limiting (in-memory sliding window) ----------------

_buckets: dict[str, deque] = defaultdict(deque)


def rate_limit(request: Request) -> None:
    ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    bucket = _buckets[ip]
    while bucket and now - bucket[0] > RATE_WINDOW_SECONDS:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT_POSTS:
        raise HTTPException(
            status_code=429,
            detail=f"rate limit exceeded: {RATE_LIMIT_POSTS} POSTs per {RATE_WINDOW_SECONDS}s per IP",
        )
    bucket.append(now)


# ---------------- models ----------------


class KeyRegistration(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    public_key: str = Field(min_length=1, max_length=256)


class MessageIn(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    from_: str = Field(alias="from", min_length=1, max_length=64)
    to: str = Field(default="*", min_length=1, max_length=64)
    # Opaque string. Broadcasts are plaintext by convention; addressed
    # messages are ciphertext by convention. The server does not check.
    content: str = Field(min_length=0)
    ttl_hours: int = Field(default=DEFAULT_TTL_HOURS, ge=0, le=MAX_TTL_HOURS)


# ---------------- endpoints ----------------


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    return HTMLResponse((STATIC_DIR / "index.html").read_text(encoding="utf-8"))


@app.get("/how", response_class=PlainTextResponse)
def how() -> PlainTextResponse:
    return PlainTextResponse((STATIC_DIR / "how.txt").read_text(encoding="utf-8"))


@app.post("/keys", status_code=201, dependencies=[Depends(rate_limit)])
def register_key(reg: KeyRegistration) -> dict:
    if not NAME_RE.match(reg.name):
        raise HTTPException(422, "name must match [A-Za-z0-9_-]{1,64}")
    now = time.time()
    with _db_lock:
        existing = _db.execute("SELECT name FROM keys WHERE name = ?", (reg.name,)).fetchone()
        if existing:
            raise HTTPException(409, f"name '{reg.name}' is already registered")
        _db.execute(
            "INSERT INTO keys (name, public_key, created_at) VALUES (?, ?, ?)",
            (reg.name, reg.public_key, now),
        )
        _db.commit()
    return {"name": reg.name, "public_key": reg.public_key, "created_at": now}


@app.get("/keys/{name}")
def get_key(name: str) -> dict:
    with _db_lock:
        row = _db.execute(
            "SELECT name, public_key, created_at FROM keys WHERE name = ?", (name,)
        ).fetchone()
    if not row:
        raise HTTPException(404, f"no key registered for '{name}'")
    return {"name": row[0], "public_key": row[1], "created_at": row[2]}


@app.post("/messages", status_code=201, dependencies=[Depends(rate_limit)])
def post_message(msg: MessageIn) -> dict:
    if len(msg.content.encode("utf-8")) > MAX_CONTENT_BYTES:
        raise HTTPException(413, f"content exceeds {MAX_CONTENT_BYTES} bytes")
    now = time.time()
    expires_at = now + msg.ttl_hours * 3600
    msg_id = secrets.token_urlsafe(12)
    delete_token = secrets.token_urlsafe(24)
    with _db_lock:
        _db.execute(
            "INSERT INTO messages (id, frm, \"to\", content, created_at, expires_at, delete_token)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (msg_id, msg.from_, msg.to, msg.content, now, expires_at, delete_token),
        )
        _db.commit()
    return {"id": msg_id, "delete_token": delete_token, "expires_at": expires_at}


@app.get("/messages")
def list_messages(
    to: Optional[str] = Query(default=None),
    since: Optional[float] = Query(default=None),
) -> dict:
    now = time.time()
    _purge_expired(now)
    clauses, params = [], []
    if to is not None:
        if to == "*":
            clauses.append("\"to\" = '*'")
        else:
            clauses.append("(\"to\" = ? OR \"to\" = '*')")
            params.append(to)
    if since is not None:
        clauses.append("created_at > ?")
        params.append(since)
    sql = "SELECT id, frm, \"to\", content, created_at, expires_at FROM messages"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(PAGE_LIMIT)
    with _db_lock:
        rows = _db.execute(sql, params).fetchall()
    return {
        "messages": [
            {
                "id": r[0],
                "from": r[1],
                "to": r[2],
                "content": r[3],
                "created_at": r[4],
                "expires_at": r[5],
            }
            for r in rows
        ]
    }


@app.delete("/messages/{message_id}")
def delete_message(message_id: str, x_delete_token: Optional[str] = Header(default=None)) -> dict:
    with _db_lock:
        row = _db.execute(
            "SELECT delete_token FROM messages WHERE id = ?", (message_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, f"no message with id '{message_id}'")
        if x_delete_token is None or not hmac.compare_digest(row[0], x_delete_token):
            raise HTTPException(403, "missing or wrong X-Delete-Token")
        _db.execute("DELETE FROM messages WHERE id = ?", (message_id,))
        _db.commit()
    return {"deleted": message_id}
