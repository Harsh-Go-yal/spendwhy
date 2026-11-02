"""SpendWhy: bank alert -> 2 minutes to upload a bill -> otherwise a voice agent calls to ask why."""
import asyncio
import email
import email.header
import hashlib
import hmac
import html
import imaplib
import io
import json
import logging
import os
import re
import secrets
import sqlite3
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

import httpx
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from PIL import Image, ImageOps, UnidentifiedImageError
from pydantic import BaseModel

BASE = Path(__file__).parent
load_dotenv(BASE / ".env")
log = logging.getLogger("spendwhy")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def env(name, default=""):
    return os.getenv(name, default).strip()


SARVAM_API_KEY = env("SARVAM_API_KEY")
SARVAM_VOICE_API_KEY = env("SARVAM_VOICE_API_KEY")
SARVAM_ORG_ID = env("SARVAM_ORG_ID")
SARVAM_WORKSPACE_ID = env("SARVAM_WORKSPACE_ID")
SARVAM_APP_ID = env("SARVAM_APP_ID")
SARVAM_APP_VERSION = env("SARVAM_APP_VERSION")
SARVAM_CONNECTION_ID = env("SARVAM_CONNECTION_ID")
SARVAM_AGENT_PHONE = env("SARVAM_AGENT_PHONE")
CALL_LANGUAGE = env("CALL_LANGUAGE")
PUBLIC_URL = env("PUBLIC_URL").rstrip("/")
WEBHOOK_SECRET = env("WEBHOOK_SECRET")
# Vercel freezes the app between requests and wipes its disk, so background loops and saved accounts can't work.
# There it runs as a demo only: no Gmail, no real calls, and the dashboard's polling moves the flow along.
SERVERLESS = bool(env("VERCEL"))
DEMO_MODE = SERVERLESS or env("DEMO_MODE", "true").lower() in ("1", "true", "yes")
BILL_WAIT_SECONDS = int(env("BILL_WAIT_SECONDS", "120"))
CALL_THRESHOLD = float(env("CALL_THRESHOLD", "100"))
AUTO_POLL_SECONDS = int(env("AUTO_POLL_SECONDS", "60"))
# An alert older than this never auto-dials, so the first sync can't trigger a burst of calls for old spends.
FRESH_ALERT_SECONDS = int(env("FRESH_ALERT_SECONDS", "600"))
CALL_TIMEOUT_SECONDS = int(env("CALL_TIMEOUT_SECONDS", "300"))
DOC_TIMEOUT_SECONDS = int(env("DOC_TIMEOUT_SECONDS", "120"))
MAX_CALLS_PER_DAY = int(env("MAX_CALLS_PER_DAY", "10"))
MAX_UPLOAD_BYTES = 15 * 1024 * 1024
SESSION_DAYS = 30

DATA_DIR = Path(env("DATA_DIR") or ("/tmp/spendwhy" if SERVERLESS else BASE))
DB_PATH = DATA_DIR / "spendwhy.db"
IST = timezone(timedelta(hours=5, minutes=30))
SARVAM_DOC_BASE = "https://api.sarvam.ai/doc-ai/v1"
SESSION_COOKIE = "spendwhy_session"
STATE_COOKIE = "spendwhy_oauth_state"

BILL_SCHEMA = {
    "type": "object",
    "properties": {
        "merchant": {"type": "string", "description": "Shop or merchant name"},
        "items": {
            "type": "array",
            "items": {"type": "string"},
            "description": 'What was bought, e.g. "Paneer roll"',
        },
        "total_amount": {"type": "number", "description": "Grand total in INR"},
        "bill_date": {"type": "string", "description": "Date on the bill"},
    },
}

CATEGORY_WORDS = {
    "Food & Dining": "food roll paneer pizza burger biryani chai tea coffee cafe restaurant dosa thali meal lunch dinner "
    "breakfast snack swiggy zomato dhaba bakery sandwich momo juice canteen kitchen",
    "Groceries": "grocery groceries milk vegetables fruit atta rice dal bigbasket blinkit zepto dmart kirana instamart",
    "Shopping": "shirt jeans shoes clothes amazon flipkart myntra ajio shopping mall gift",
    "Transport": "uber ola rapido metro cab taxi auto petrol diesel fuel irctc train flight bus parking",
    "Bills & Utilities": "electricity recharge broadband wifi airtel jio rent gas bill utility",
    "Entertainment": "movie netflix spotify pvr inox bookmyshow game concert hotstar",
    "Health": "pharmacy medicine doctor hospital clinic apollo medplus lab",
    "Education": "book course tuition college school udemy coursera stationery",
}

_bg_tasks = set()
_sync_locks = {}


def spawn(coro):
    task = asyncio.create_task(coro)
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)
    return task


def fernet():
    """App passwords are encrypted at rest with SECRET_KEY, or a key generated once in DATA_DIR."""
    key = env("SECRET_KEY")
    if not key:
        path = DATA_DIR / ".secret.key"
        if not path.exists():
            path.write_text(Fernet.generate_key().decode())
        key = path.read_text().strip()
    return Fernet(key.encode())


def encrypt_token(value):
    return fernet().encrypt(value.encode()).decode()


def decrypt_token(value):
    return fernet().decrypt(value.encode()).decode()


# ---------- Database ----------


def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with db() as c:
        c.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY, created_at REAL, email TEXT UNIQUE, name TEXT, phone TEXT,
                call_consent_at REAL, gmail_password TEXT,
                gmail_last_sync REAL, gmail_error TEXT, api_token TEXT);
            CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id TEXT, expires_at REAL);
            CREATE TABLE IF NOT EXISTS transactions (
                id TEXT PRIMARY KEY, user_id TEXT, created_at REAL, txn_at REAL, amount REAL, direction TEXT,
                merchant TEXT, bank TEXT, status TEXT, bill_deadline REAL, raw_alert TEXT, source TEXT,
                reason TEXT, reason_source TEXT, category TEXT, worth_it TEXT,
                attempt_id TEXT, call_started_at REAL, failure_reason TEXT, transcript TEXT,
                simulated INTEGER DEFAULT 0, document_id TEXT);
            CREATE TABLE IF NOT EXISTS documents (
                id TEXT PRIMARY KEY, user_id TEXT, created_at REAL, filename TEXT, status TEXT, merchant TEXT,
                items TEXT, total_amount REAL, bill_date TEXT, txn_id TEXT, message TEXT, simulated INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS seen_emails (user_id TEXT, key TEXT, PRIMARY KEY (user_id, key));
            CREATE TABLE IF NOT EXISTS call_log (user_id TEXT, at REAL);
            CREATE INDEX IF NOT EXISTS idx_txn_user ON transactions (user_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_txn_status ON transactions (status, bill_deadline);
            CREATE INDEX IF NOT EXISTS idx_doc_user ON documents (user_id, created_at);
            """
        )
        # A restart loses the background job, so don't let a dead upload hold calls back forever.
        c.execute("UPDATE documents SET status='failed', message='Interrupted by a restart' WHERE status='processing'")


def update_txn(txn_id, **fields):
    cols = ", ".join(f"{k}=?" for k in fields)
    with db() as c:
        c.execute(f"UPDATE transactions SET {cols} WHERE id=?", (*fields.values(), txn_id))


def update_user(user_id, **fields):
    cols = ", ".join(f"{k}=?" for k in fields)
    with db() as c:
        c.execute(f"UPDATE users SET {cols} WHERE id=?", (*fields.values(), user_id))


def get_txn(txn_id):
    with db() as c:
        row = c.execute("SELECT * FROM transactions WHERE id=?", (txn_id,)).fetchone()
    return dict(row) if row else None


def get_user(user_id):
    with db() as c:
        row = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return dict(row) if row else None


def txn_json(row):
    t = dict(row)
    t.pop("user_id", None)
    t["transcript"] = json.loads(t["transcript"]) if t["transcript"] else []
    t["simulated"] = bool(t["simulated"])
    return t


def doc_json(row):
    d = dict(row)
    d.pop("user_id", None)
    d["items"] = json.loads(d["items"]) if d["items"] else []
    d["simulated"] = bool(d["simulated"])
    return d


def create_txn(user_id, amount, direction, merchant, bank, raw_alert, source, txn_at=None):
    now = time.time()
    txn_at = txn_at or now
    deadline = None
    if direction != "debit":
        status = "ignored"
    elif amount < CALL_THRESHOLD:
        status = "small"
    elif now - txn_at > FRESH_ALERT_SECONDS:
        status = "unexplained"
    else:
        status = "waiting_for_bill"
        deadline = now + BILL_WAIT_SECONDS
    txn_id = uuid.uuid4().hex[:12]
    with db() as c:
        c.execute(
            "INSERT INTO transactions (id, user_id, created_at, txn_at, amount, direction, merchant, bank, status,"
            " bill_deadline, raw_alert, source, category) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (txn_id, user_id, now, txn_at, amount, direction, merchant, bank, status, deadline, raw_alert, source,
             categorize(merchant)),
        )
    log.info("txn %s: %s status=%s", txn_id, direction, status)
    return txn_id


def categorize(text):
    words = set(re.findall(r"[a-z]+", (text or "").lower()))
    for category, vocab in CATEGORY_WORDS.items():
        if words & set(vocab.split()):
            return category
    return "Other"


def fmt_ist(ts):
    return datetime.fromtimestamp(ts, IST).strftime("%d %b, %I:%M %p").lstrip("0")


# ---------- Alert parsing ----------

AMOUNT_RE = re.compile(r"(?:\brs\.?|\binr|₹)\s*([\d,]+(?:\.\d{1,2})?)", re.I)
# "Credit/Debit Card" is in every bank's boilerplate, and a card name is not a direction.
DEBIT_RE = re.compile(
    r"\b(?:debited|debit(?![\s/]*(?:credit\s*)?card)|spent|withdrawn|auto\s?pay\b[^\n]*?\bprocessed)\b", re.I
)
# Mentions money and a direction, but no money has moved: autopay reminders ("To Be Debited By") and failed payments.
NOT_A_TXN_RE = re.compile(
    r"\b(?:upcoming|to be debited|will be debited|reminder|statement|pre-?approved|declined|failed|unsuccessful|"
    r"not processed|could not be processed)\b",
    re.I,
)
CREDIT_RE = re.compile(r"\b(?:credited|credit(?![\s/]*(?:debit\s*)?card)|received|refund(?:ed)?)\b", re.I)
FOOTER_RE = re.compile(
    r"if this transaction was not initiated|always open to help|regards,|system generated|"
    r"please do not share|do not share|to block upi",
    re.I,
)
BANK_RE = re.compile(
    r"\b(axis|hdfc|icici|sbi|state bank|kotak|yes ?bank|idfc|indusind|pnb|punjab national|bank of baroda|"
    r"canara|federal bank|rbl|au small|paytm payments)\b",
    re.I,
)
BANK_NAMES = {"sbi": "SBI", "state bank": "SBI", "hdfc": "HDFC Bank", "icici": "ICICI Bank", "pnb": "PNB",
              "punjab national": "PNB", "rbl": "RBL Bank", "idfc": "IDFC First Bank"}
SENDER_RE = re.compile(r"bank|hdfc|icici|sbi|axis|kotak|idfc|indusind|pnb|canara|rbl", re.I)
ACCOUNT_RE = re.compile(r"\ba/?c\b|\baccount\b|\bupi\b|\bvpa\b|\bcard\b", re.I)
PAYMENT_TOKENS = {"UPI", "P2A", "P2M", "MOB", "TPFT", "NEFT", "IMPS", "RTGS", "ACH", "POS", "ECOM", "INB", "BIL"}


def strip_html(raw):
    raw = re.sub(r"(?is)<!--.*?-->|<(style|script|head)\b.*?</\1>", " ", raw)
    raw = re.sub(r"(?i)<(br|/p|/tr|/td|/div|/li|/h\d)\b[^>]*>", "\n", raw)
    raw = re.sub(r"<[^>]+>", " ", raw)
    return html.unescape(raw).replace("\xa0", " ")


def clean_name(name):
    name = re.sub(r"\s+", " ", name).strip(" .,:;-")[:40]
    return name.title() if name.isupper() else name


def from_slash_path(path):
    """Axis-style UPI/P2A/851400353555/MADHUR GOYAL: first segment that is neither a code nor a number."""
    for part in path.split("/"):
        part = part.strip()
        if re.search(r"[A-Za-z]", part) and part.upper() not in PAYMENT_TOKENS:
            return clean_name(part)
    return None


def extract_merchant(text):
    m = re.search(r"Transaction Info:?\s*([^\n]+)", text, re.I)
    if m:
        name = from_slash_path(m.group(1)) if "/" in m.group(1) else clean_name(m.group(1))
        if name:
            return name
    m = re.search(r"Auto\s?Pay\b.*?\bof\s+\S+\s*[\d,.]+\s+for\s+(.+?)\s+(?:has been\s+)?processed", text, re.I)
    if m:
        return clean_name(m.group(1))
    m = re.search(r"\bby\s+([A-Z0-9]+/[^\n]+?)(?:\.(?:\s|$)|$)", text, re.M)
    if m and (name := from_slash_path(m.group(1))):
        return name
    m = re.search(r"\bVPA\s+([\w.\-+]+@[\w.\-]+)", text, re.I)
    if m:
        return m.group(1).lower()
    for m in re.finditer(r"\b(?:at|to)\s+([A-Za-z0-9][\w &.\-'*]{1,40}?)\s+(?:on|via|ref)\b", text, re.I):
        if not re.match(r"(?i)(your|a/?c|account|the)\b", m.group(1)):
            return clean_name(m.group(1))
    m = re.search(r"\bInfo:\s*([^\n]+)", text, re.I)
    if m:
        return clean_name(m.group(1))
    return "Unknown merchant"


def extract_bank(text, sender):
    m = BANK_RE.search(f"{sender} {text}")
    if not m:
        return "Bank"
    key = m.group(1).lower()
    return BANK_NAMES.get(key) or (m.group(1).title() + ("" if "bank" in key else " Bank"))


def parse_alert(subject, body, sender=""):
    """Returns the parsed alert, or None when the email isn't a real transaction alert."""
    cut = FOOTER_RE.search(body)
    body = body[: cut.start()] if cut else body
    body = re.sub(r"\[\]\([^)]*\)|\|", " ", body)  # table markup when the body arrives converted to markdown
    body = re.sub(r"[ \t]+", " ", body)
    body = re.sub(r"\n\s*\n+", "\n", body).strip()
    text = f"{subject}\n{body}"

    amount = AMOUNT_RE.search(text)
    if not amount or NOT_A_TXN_RE.search(text):
        return None
    direction = None
    for part in (subject, body):
        debit, credit = DEBIT_RE.search(part), CREDIT_RE.search(part)
        if debit or credit:
            # "debited from your a/c, credited to X" is a debit: whichever comes first decides.
            if debit and (not credit or debit.start() < credit.start()):
                direction = "debit"
            else:
                direction = "credit"
            break
    # The Gmail search is broad, and a promo mentioning "spent Rs 500" must never ring a phone.
    if not direction or not (SENDER_RE.search(sender) and ACCOUNT_RE.search(text)):
        return None
    value = float(amount.group(1).replace(",", "") or 0)
    if value <= 0:
        return None
    return {"amount": value, "direction": direction, "merchant": extract_merchant(body),
            "bank": extract_bank(text, sender), "raw": text[:1500]}


def is_seen(user_id, key):
    with db() as c:
        return c.execute("SELECT 1 FROM seen_emails WHERE user_id=? AND key=?", (user_id, key)).fetchone() is not None


def ingest_email(user_id, message_id, subject, body, sender, date_ts):
    """Shared by the Gmail sync and /api/ingest/email. Returns the new txn id, or None for duplicates and non-alerts."""
    # The fingerprint stops the same email being added twice through two routes, which use different ids.
    fingerprint = "fp:" + hashlib.sha1(f"{subject}|{int(date_ts or 0)}".encode()).hexdigest()
    with db() as c:
        if c.execute("SELECT 1 FROM seen_emails WHERE user_id=? AND key IN (?,?)",
                     (user_id, message_id, fingerprint)).fetchone():
            return None
        c.executemany("INSERT OR IGNORE INTO seen_emails VALUES (?,?)",
                      [(user_id, message_id), (user_id, fingerprint)])
    parsed = parse_alert(subject, body, sender)
    if not parsed:
        return None
    return create_txn(user_id, parsed["amount"], parsed["direction"], parsed["merchant"], parsed["bank"],
                      parsed["raw"], "gmail", txn_at=date_ts)


# ---------- Gmail over IMAP ----------


class GmailAccessLost(Exception):
    pass


def imap_open(address, password):
    conn = imaplib.IMAP4_SSL("imap.gmail.com")
    try:
        conn.login(address, password)
    except imaplib.IMAP4.error:
        try:
            conn.logout()
        except (imaplib.IMAP4.error, OSError):
            pass
        raise GmailAccessLost("Reconnect Gmail: Google rejected the app password")
    return conn


def imap_check(address, password):
    imap_open(address, password).logout()


def message_text(msg):
    plain, markup = "", ""
    for part in msg.walk():
        if part.get_content_maintype() != "text" or part.get_filename():
            continue
        try:
            decoded = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", "replace")
        except (AttributeError, LookupError):
            continue
        if part.get_content_subtype() == "plain":
            plain += decoded
        elif part.get_content_subtype() == "html":
            markup += decoded
    return plain if AMOUNT_RE.search(plain) or not markup else strip_html(markup)


def decode_subject(value):
    parts = email.header.decode_header(value or "")
    return "".join(p.decode(enc or "utf-8", "replace") if isinstance(p, bytes) else p for p, enc in parts)


def fetch_alert_emails(address, password):
    conn = imap_open(address, password)
    try:
        status, _ = conn.select('"[Gmail]/All Mail"', readonly=True)
        if status != "OK":
            conn.select("INBOX", readonly=True)  # the All Mail folder has a different name on non-English accounts
        query = '"(debited OR spent OR \\"transaction alert\\" OR credited OR \\"auto pay\\") newer_than:1d"'
        status, data = conn.uid("SEARCH", None, "X-GM-RAW", query)
        if status != "OK":
            raise RuntimeError("Gmail search failed")
        out = []
        for uid in data[0].split()[-50:]:
            status, parts = conn.uid("FETCH", uid, "(BODY.PEEK[])")
            if status == "OK" and parts and isinstance(parts[0], tuple):
                out.append(email.message_from_bytes(parts[0][1]))
        return out
    finally:
        try:
            conn.logout()
        except (imaplib.IMAP4.error, OSError):
            pass


async def sync_user(user):
    lock = _sync_locks.setdefault(user["id"], asyncio.Lock())
    async with lock:
        try:
            messages = await asyncio.to_thread(fetch_alert_emails, user["email"], decrypt_token(user["gmail_password"]))
        except GmailAccessLost as e:
            update_user(user["id"], gmail_error=str(e))
            raise
        except (imaplib.IMAP4.error, OSError, RuntimeError) as e:
            log.warning("gmail sync failed for user %s: %s", user["id"], type(e).__name__)
            update_user(user["id"], gmail_error="Couldn't reach Gmail. Trying again next minute.")
            raise RuntimeError("Couldn't reach Gmail") from e
        new = 0
        for msg in messages:
            subject = decode_subject(msg.get("Subject"))
            msg_id = msg.get("Message-ID") or f"{subject}|{msg.get('Date')}"
            try:
                sent = parsedate_to_datetime(msg.get("Date"))
                # A "-0000" date comes back without a zone, and the server's local time would make it look hours old.
                ts = (sent if sent.tzinfo else sent.replace(tzinfo=timezone.utc)).timestamp()
            except (TypeError, ValueError):
                ts = time.time()
            if ingest_email(user["id"], msg_id, subject, message_text(msg), msg.get("From", ""), ts):
                new += 1
        update_user(user["id"], gmail_last_sync=time.time(), gmail_error=None)
        return {"scanned": len(messages), "new": new}


# ---------- Accounts ----------


def upsert_user(address, name, phone, password=None):
    address = address.lower()
    with db() as c:
        row = c.execute("SELECT id FROM users WHERE email=?", (address,)).fetchone()
        user_id = row["id"] if row else uuid.uuid4().hex[:16]
        if not row:
            c.execute("INSERT INTO users (id, created_at, email, api_token) VALUES (?,?,?,?)",
                      (user_id, time.time(), address, secrets.token_urlsafe(32)))
        c.execute("UPDATE users SET name=?, phone=?, call_consent_at=? WHERE id=?", (name, phone, time.time(), user_id))
        if password:
            c.execute("UPDATE users SET gmail_password=?, gmail_error=NULL WHERE id=?",
                      (encrypt_token(password), user_id))
    return user_id


def set_session_cookie(response, token):
    response.set_cookie(SESSION_COOKIE, token, max_age=SESSION_DAYS * 86400, httponly=True, samesite="lax",
                        secure=PUBLIC_URL.startswith("https"))


def create_session(user_id):
    token = secrets.token_urlsafe(32)
    now = time.time()
    with db() as c:
        c.execute("DELETE FROM sessions WHERE expires_at<?", (now,))
        c.execute("INSERT INTO sessions VALUES (?,?,?)",
                  (hashlib.sha256(token.encode()).hexdigest(), user_id, now + SESSION_DAYS * 86400))
    return token


def current_user(request: Request):
    """Dashboard cookie, or `Authorization: Bearer <api_token>` for the WhatsApp bot."""
    bearer = request.headers.get("authorization", "")
    with db() as c:
        if bearer.lower().startswith("bearer ") and bearer[7:].strip():
            row = c.execute("SELECT * FROM users WHERE api_token=?", (bearer[7:].strip(),)).fetchone()
        else:
            digest = hashlib.sha256(request.cookies.get(SESSION_COOKIE, "").encode()).hexdigest()
            row = c.execute(
                "SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token_hash=? AND s.expires_at>?",
                (digest, time.time()),
            ).fetchone()
    if not row:
        raise HTTPException(401, "Sign in first")
    return dict(row)


def me_json(user):
    return {
        "email": user["email"],
        "name": user["name"],
        "phone": user["phone"],
        "gmail_connected": bool(user["gmail_password"]),
        "gmail_last_sync": user["gmail_last_sync"],
        "gmail_error": user["gmail_error"],
        "api_token": user["api_token"],
        "voice_missing": [] if DEMO_MODE else voice_config_missing(),
    }


# ---------- Sarvam Document AI ----------


def to_pdf(data):
    """Returns PDF bytes for an image or PDF upload."""
    if data[:5] == b"%PDF-":
        return data
    try:
        img = ImageOps.exif_transpose(Image.open(io.BytesIO(data))).convert("RGB")
    except (UnidentifiedImageError, OSError) as e:
        raise ValueError("Upload a JPG, PNG or PDF") from e
    img.thumbnail((2400, 2400))
    out = io.BytesIO()
    img.save(out, "PDF")
    return out.getvalue()


def find_key(obj, key):
    """Document AI nests fields differently per job, so look for the key at any depth."""
    if isinstance(obj, dict):
        if obj.get(key) not in (None, ""):
            return obj[key]
        obj = list(obj.values())
    if isinstance(obj, list):
        for value in obj:
            found = find_key(value, key)
            if found not in (None, ""):
                return found
    return None


def normalize_bill(result):
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except ValueError:
            result = {}
    total = find_key(result, "total_amount")
    if isinstance(total, str):
        digits = re.sub(r"[^\d.]", "", total)
        try:
            total = float(digits)
        except ValueError:
            total = None
    items = find_key(result, "items") or []
    if isinstance(items, str):
        items = [i.strip() for i in items.split(",") if i.strip()]
    items = [(i.get("name") or i.get("description") or str(i)) if isinstance(i, dict) else str(i) for i in items]
    return {"merchant": str(find_key(result, "merchant") or "Unknown shop"), "items": items,
            "total_amount": float(total) if isinstance(total, (int, float)) else None,
            "bill_date": str(find_key(result, "bill_date") or "")}


async def sarvam_extract(pdf_bytes, filename):
    headers = {"api-subscription-key": SARVAM_API_KEY}
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.post(
            f"{SARVAM_DOC_BASE}/job/extract",
            headers=headers,
            files={"file": (filename, pdf_bytes, "application/pdf")},
            data={"schema": json.dumps(BILL_SCHEMA), "language": "en-IN", "output_format": "json"},
        )
        if r.status_code >= 400:
            raise RuntimeError(f"Document AI rejected the upload ({r.status_code}): {r.text[:200]}")
        job_id = r.json().get("job_id")
        if not job_id:
            raise RuntimeError(f"Document AI returned no job_id: {r.text[:200]}")
        give_up = time.time() + DOC_TIMEOUT_SECONDS
        while time.time() < give_up:
            await asyncio.sleep(3)
            s = await client.get(f"{SARVAM_DOC_BASE}/job/{job_id}/status", headers=headers)
            s.raise_for_status()
            body = s.json()
            state = str(body.get("status") or body.get("job_state") or "").lower()
            if state in ("failed", "rejected"):
                raise RuntimeError(f"Document AI job {state}: {str(body.get('error_message') or '')[:200]}")
            if state in ("completed", "partially_completed"):
                res = await client.get(f"{SARVAM_DOC_BASE}/job/{job_id}/results", headers=headers)
                res.raise_for_status()
                return res.json().get("result", res.json())
    raise RuntimeError("Document AI timed out")


def simulated_bill(user_id, txn_hint):
    """Only reached with DEMO_MODE on and no Sarvam key; the UI labels the result as simulated."""
    with db() as c:
        row = c.execute(
            "SELECT * FROM transactions WHERE user_id=? AND status='waiting_for_bill'"
            " ORDER BY (id=?) DESC, created_at DESC LIMIT 1",
            (user_id, txn_hint or ""),
        ).fetchone()
    amount = row["amount"] if row else 450.0
    merchant = row["merchant"] if row else "Sharma Sweets"
    return {"merchant": merchant, "items": ["Paneer roll", "Masala chai"], "total_amount": amount,
            "bill_date": datetime.now(IST).strftime("%d-%m-%Y")}


def match_bill(user_id, total, txn_hint=None):
    """Most recent waiting debit within ₹5 or 5% of the bill; the row the user uploaded from wins if it also fits."""
    with db() as c:
        rows = c.execute(
            "SELECT * FROM transactions WHERE user_id=? AND status='waiting_for_bill' ORDER BY created_at DESC",
            (user_id,),
        ).fetchall()
    fits = [r for r in rows if abs(r["amount"] - total) <= 5 or abs(r["amount"] - total) <= 0.05 * total]
    fits.sort(key=lambda r: r["id"] != txn_hint)
    return fits[0] if fits else None


async def process_document(user_id, doc_id, data, txn_hint):
    simulated = False
    try:
        # The bill is only held in memory for this job and is not kept on disk.
        pdf = await asyncio.to_thread(to_pdf, data)
        if SARVAM_API_KEY:
            bill = normalize_bill(await sarvam_extract(pdf, f"{doc_id}.pdf"))
        elif DEMO_MODE:
            await asyncio.sleep(2)
            bill, simulated = simulated_bill(user_id, txn_hint), True
        else:
            raise RuntimeError("SARVAM_API_KEY is not set")
    except Exception as e:  # any failure must release the held call, so the flow still ends in a phone call
        log.warning("document %s failed: %s", doc_id, e)
        with db() as c:
            c.execute("UPDATE documents SET status='failed', message=? WHERE id=?",
                      (f"Couldn't read this bill: {str(e)[:200]}", doc_id))
        return

    total = bill["total_amount"]
    txn = match_bill(user_id, total, txn_hint) if total else None
    txn_id = None
    if txn:
        items = ", ".join(bill["items"]) or bill["merchant"]
        with db() as c:
            # The status guard makes this the single winner against the deadline loop.
            cur = c.execute(
                "UPDATE transactions SET status='explained_by_bill', reason=?, reason_source='bill', category=?,"
                " document_id=? WHERE id=? AND status='waiting_for_bill'",
                (f"Bill: {items}", categorize(f"{items} {bill['merchant']}"), doc_id, txn["id"]),
            )
            txn_id = txn["id"] if cur.rowcount else None
    if txn_id:
        message = f"Matched to ₹{txn['amount']:,.2f} at {txn['merchant']}. Call cancelled."
    elif total:
        message = f"Bill read: ₹{total:,.2f} at {bill['merchant']} — no pending alert matched"
    else:
        message = f"Read a bill from {bill['merchant']} but couldn't find a total"
    with db() as c:
        c.execute(
            "UPDATE documents SET status='done', merchant=?, items=?, total_amount=?, bill_date=?, txn_id=?,"
            " message=?, simulated=? WHERE id=?",
            (bill["merchant"], json.dumps(bill["items"]), total, bill["bill_date"], txn_id, message, int(simulated),
             doc_id),
        )


# ---------- Sarvam voice call ----------

CALLABLE = ("waiting_for_bill", "unexplained", "no_answer", "failed")


def webhook_url():
    return f"{PUBLIC_URL}/api/webhooks/sarvam?secret={WEBHOOK_SECRET}"


def voice_config_missing():
    required = {"SARVAM_VOICE_API_KEY": SARVAM_VOICE_API_KEY, "SARVAM_ORG_ID": SARVAM_ORG_ID,
                "SARVAM_WORKSPACE_ID": SARVAM_WORKSPACE_ID, "SARVAM_APP_ID": SARVAM_APP_ID,
                "SARVAM_APP_VERSION": SARVAM_APP_VERSION, "SARVAM_CONNECTION_ID": SARVAM_CONNECTION_ID,
                "SARVAM_AGENT_PHONE": SARVAM_AGENT_PHONE, "PUBLIC_URL": PUBLIC_URL, "WEBHOOK_SECRET": WEBHOOK_SECRET}
    return [k for k, v in required.items() if not v]


def call_blocker(user):
    """Why this person can't be phoned right now."""
    if not user or not user["phone"] or not user["call_consent_at"]:
        return "Add your phone and agree to calls first"
    missing = voice_config_missing()
    if missing:
        return "Server is missing: " + ", ".join(missing)
    with db() as c:
        calls = c.execute("SELECT COUNT(*) FROM call_log WHERE user_id=? AND at>?",
                          (user["id"], time.time() - 86400)).fetchone()[0]
    if calls >= MAX_CALLS_PER_DAY:
        return f"Daily limit of {MAX_CALLS_PER_DAY} calls reached"
    return None


async def place_call(txn_id):
    """Claims the row first so a call can never be placed twice or race a matching bill. False if it lost."""
    marks = ",".join("?" * len(CALLABLE))
    with db() as c:
        cur = c.execute(
            f"UPDATE transactions SET status='calling', call_started_at=?, failure_reason=NULL"
            f" WHERE id=? AND status IN ({marks})",
            (time.time(), txn_id, *CALLABLE),
        )
    if not cur.rowcount:
        return False
    t = get_txn(txn_id)
    if DEMO_MODE:
        update_txn(txn_id, attempt_id=f"demo-{txn_id}", simulated=1)
        if not SERVERLESS:
            spawn(simulate_call(txn_id))
        return True
    user = get_user(t["user_id"])
    blocked = call_blocker(user)
    if blocked:
        update_txn(txn_id, status="failed", failure_reason=blocked)
        return True
    with db() as c:
        c.execute("INSERT INTO call_log VALUES (?,?)", (user["id"], time.time()))
    app_config = {
        "app_id": SARVAM_APP_ID,
        "app_version": int(SARVAM_APP_VERSION) if SARVAM_APP_VERSION.isdigit() else SARVAM_APP_VERSION,
        "connection_config": {"connection_id": SARVAM_CONNECTION_ID, "agent_phone_number": SARVAM_AGENT_PHONE},
        "agent_variables": {"user_name": first_name(user), "amount": f"{t['amount']:g}", "merchant": t["merchant"],
                            "txn_time": fmt_ist(t["txn_at"])},
    }
    if CALL_LANGUAGE:
        app_config["app_overrides"] = {"initial_language_name": CALL_LANGUAGE}
    payload = {"app_config": app_config, "user_config": {"user_phone_number": user["phone"]},
               "webhook_config": {"url": webhook_url(), "metadata": {"txn_id": txn_id}}}
    url = f"https://apps.sarvam.ai/api/outbounds/v1/orgs/{SARVAM_ORG_ID}/workspaces/{SARVAM_WORKSPACE_ID}/outbounds"
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(url, headers={"X-API-Key": SARVAM_VOICE_API_KEY}, json=payload)
        if r.status_code >= 400:
            raise RuntimeError(f"Sarvam returned {r.status_code}: {r.text[:200]}")
        update_txn(txn_id, attempt_id=r.json().get("attempt_id"))
    except (httpx.HTTPError, RuntimeError, ValueError) as e:
        log.warning("call failed for %s: %s", txn_id, e)
        update_txn(txn_id, status="failed", failure_reason=str(e)[:300])
    return True


def first_name(user):
    return (user["name"] or user["email"].split("@")[0]).split()[0]


def apply_call_result(payload):
    meta = (payload.get("webhook_config") or {}).get("metadata") or payload.get("metadata") or {}
    t = get_txn(meta.get("txn_id")) if meta.get("txn_id") else None
    if not t and payload.get("attempt_id"):
        with db() as c:
            row = c.execute("SELECT * FROM transactions WHERE attempt_id=?", (payload["attempt_id"],)).fetchone()
        t = dict(row) if row else None
    if not t:
        return None
    # A bill or a typed reason already answered this one; a late webhook must not overwrite it.
    if t["status"] not in ("calling", "no_answer", "failed"):
        return t["id"]

    transcript = [{"role": m.get("role"), "text": m.get("en_text") or m.get("text") or ""}
                  for m in payload.get("interaction_transcript") or []]
    # Sarvam's schema sends connectivity_status (null if the call never connected); status is the older documented name.
    status = str(payload.get("connectivity_status") or payload.get("status") or "").lower()
    if status in ("no_answer", "busy"):
        update_txn(t["id"], status="no_answer", failure_reason=payload.get("failure_reason") or status,
                   transcript=json.dumps(transcript))
    elif status != "connected":
        update_txn(t["id"], status="failed", failure_reason=payload.get("failure_reason") or status or "unknown",
                   transcript=json.dumps(transcript))
    else:
        final = {**(payload.get("output_agent_variables") or {}), **(payload.get("final_agent_variables") or {})}
        # Sarvam's extraction filled worth_it="no" on a wrong-number test call, which would count as regret.
        unanswered = {"declined": "You preferred not to say on the call", "callback": "You were busy on the call",
                      "wrong_person": "Someone else answered the call"}.get(final.get("call_outcome"))
        if unanswered:
            update_txn(t["id"], status="unexplained", failure_reason=unanswered, transcript=json.dumps(transcript))
            return t["id"]
        said = " ".join(m["text"] for m in transcript if m["role"] == "user").strip()
        reason = final.get("spend_reason") or said or "Call connected, no reason captured"
        worth = str(final.get("worth_it") or "").strip().lower()
        update_txn(t["id"], status="explained", reason=reason, reason_source="call",
                   category=final.get("category") or categorize(f"{reason} {t['merchant']}"),
                   worth_it=worth if worth in ("yes", "no") else None, failure_reason=None,
                   transcript=json.dumps(transcript))
    return t["id"]


DEMO_ANSWERS = {
    "Food & Dining": ("Team dinner after the hackathon sprint", "yes", "Took the team out for dinner after the sprint."),
    "Groceries": ("Weekly groceries for the flat", "yes", "Just the weekly groceries for the flat."),
    "Shopping": ("Impulse-bought sneakers in a sale", "no", "Honestly, I saw a sale and bought sneakers."),
    "Entertainment": ("Movie night with friends", "yes", "Movie tickets with friends."),
    "Transport": ("Cab to the airport", "yes", "Cab to the airport, I was running late."),
}


async def simulate_call(txn_id):
    await asyncio.sleep(5)
    finish_simulated_call(txn_id)


def finish_simulated_call(txn_id):
    t = get_txn(txn_id)
    if not t or t["status"] != "calling":
        return
    user = get_user(t["user_id"])
    category = t["category"] if t["category"] in DEMO_ANSWERS else "Shopping"
    reason, worth, spoken = DEMO_ANSWERS.get(t["category"]) or ("Late-night online order I didn't need", "no",
                                                                "A late-night online order. I didn't really need it.")
    agent_open = (f"Hi {first_name(user) if user else 'there'}! ₹{t['amount']:g} was spent at {t['merchant']} on "
                  f"{fmt_ist(t['txn_at'])} and no bill was shared. What was it for?")
    apply_call_result({
        "attempt_id": t["attempt_id"], "status": "connected", "webhook_config": {"metadata": {"txn_id": txn_id}},
        "final_agent_variables": {"spend_reason": reason, "category": category, "worth_it": worth},
        "interaction_transcript": [
            {"role": "agent", "en_text": agent_open},
            {"role": "user", "en_text": spoken},
            {"role": "agent", "en_text": "Got it, I've saved that. Looking back, was it worth it?"},
            {"role": "user", "en_text": "Yes, totally worth it." if worth == "yes" else "No, I regret that one."},
            {"role": "agent", "en_text": "Thanks for telling me. Have a good one!"},
        ],
    })


# ---------- Background loops ----------


async def serverless_tick():
    """Does the deadline loop's job on each dashboard poll, since nothing runs between requests on Vercel."""
    now = time.time()
    for row in due_for_call(now)[0]:
        await place_call(row["id"])
    with db() as c:
        done = c.execute("SELECT id FROM transactions WHERE status='calling' AND simulated=1 AND call_started_at<=?",
                         (now - 5,)).fetchall()
    for row in done:
        finish_simulated_call(row["id"])


def due_for_call(now):
    with db() as c:
        # A bill uploaded in time is still being read: hold the call until Document AI answers.
        due = c.execute(
            "SELECT t.id, t.user_id FROM transactions t WHERE t.status='waiting_for_bill' AND t.bill_deadline<=?"
            " AND NOT EXISTS (SELECT 1 FROM documents d WHERE d.user_id=t.user_id AND d.status='processing'"
            " AND d.created_at<=t.bill_deadline) ORDER BY t.bill_deadline",
            (now,),
        ).fetchall()
        busy = {r["user_id"] for r in c.execute("SELECT DISTINCT user_id FROM transactions WHERE status='calling'")}
    return due, busy


async def deadline_loop():
    while True:
        try:
            now = time.time()
            with db() as c:
                c.execute(
                    "UPDATE transactions SET status='failed', failure_reason='No webhook from Sarvam. Check PUBLIC_URL.'"
                    " WHERE status='calling' AND call_started_at<?",
                    (now - CALL_TIMEOUT_SECONDS,),
                )
            due, busy = due_for_call(now)
            for row in due:
                # One phone, one line: a second simultaneous call to the same person would just come back busy.
                if not DEMO_MODE and row["user_id"] in busy:
                    continue
                await place_call(row["id"])
                busy.add(row["user_id"])
        except Exception:
            log.exception("deadline loop error")
        await asyncio.sleep(5)


async def gmail_loop():
    gate = asyncio.Semaphore(5)

    async def one(user):
        async with gate:
            try:
                await sync_user(user)
            except (GmailAccessLost, RuntimeError):
                pass  # sync_user recorded it for that person's dashboard

    while True:
        try:
            with db() as c:
                # A rejected password stays rejected until the person reconnects, and retrying can get them blocked.
                users = c.execute(
                    "SELECT * FROM users WHERE gmail_password IS NOT NULL"
                    " AND (gmail_error IS NULL OR gmail_error NOT LIKE 'Reconnect%')"
                ).fetchall()
            await asyncio.gather(*(one(dict(u)) for u in users))
        except Exception:
            log.exception("gmail loop error")
        await asyncio.sleep(AUTO_POLL_SECONDS)


@asynccontextmanager
async def lifespan(_app):
    init_db()
    if not SERVERLESS:
        spawn(deadline_loop())
        spawn(gmail_loop())
    yield
    for task in list(_bg_tasks):
        task.cancel()


if SERVERLESS:
    init_db()  # a cold start may not run the lifespan before the first request

app = FastAPI(title="SpendWhy", lifespan=lifespan)


# ---------- Sign-in ----------


class ConnectIn(BaseModel):
    name: str
    email: str
    phone: str = ""
    app_password: str = ""
    consent: bool = False


@app.post("/api/connect")
async def connect(body: ConnectIn):
    """One form instead of OAuth. A working Gmail app password is what proves the inbox is yours."""
    address = body.email.strip().lower()
    password = re.sub(r"\s", "", body.app_password)
    phone = re.sub(r"[\s-]", "", body.phone)
    if not re.fullmatch(r"[^@\s]+@[^@\s]+", address):
        raise HTTPException(400, "Enter your Gmail address")
    if SERVERLESS and password:
        raise HTTPException(400, "This demo doesn't take app passwords")
    if not SERVERLESS and not re.fullmatch(r"\+[1-9]\d{9,14}", phone):
        raise HTTPException(400, "Enter the phone number with its country code, like +919876543210")
    if not SERVERLESS and not body.consent:
        raise HTTPException(400, "SpendWhy can't call you until you agree to the calls")
    if password:
        try:
            await asyncio.to_thread(imap_check, address, password)
        except GmailAccessLost:
            raise HTTPException(401, "Google rejected that. Check the email and the 16-letter app password.")
        except OSError:
            raise HTTPException(502, "Couldn't reach Gmail. Try again.")
    else:
        with db() as c:
            taken = c.execute("SELECT 1 FROM users WHERE email=? AND gmail_password IS NOT NULL", (address,)).fetchone()
        # Without this, typing someone's email would open their dashboard.
        if taken or not DEMO_MODE:
            raise HTTPException(401, "Enter the Gmail app password")
    user_id = upsert_user(address, body.name.strip()[:80], phone, password or None)
    if password:
        spawn(first_sync(user_id))
    response = JSONResponse(me_json(get_user(user_id)))
    set_session_cookie(response, create_session(user_id))
    return response


async def first_sync(user_id):
    try:
        await sync_user(get_user(user_id))
    except (GmailAccessLost, RuntimeError):
        pass  # recorded for the dashboard


@app.post("/auth/logout")
def logout(request: Request):
    digest = hashlib.sha256(request.cookies.get(SESSION_COOKIE, "").encode()).hexdigest()
    with db() as c:
        c.execute("DELETE FROM sessions WHERE token_hash=?", (digest,))
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE)
    return response


# ---------- API ----------


class DemoAlert(BaseModel):
    amount: float
    merchant: str = "Blue Tokai Coffee"


class EmailIn(BaseModel):
    message_id: str
    subject: str
    body: str
    sender: str = ""
    date: str | None = None


class ReasonIn(BaseModel):
    reason: str
    category: str | None = None
    worth_it: str | None = None


@app.get("/api/config")
def config():
    return {
        "demo_mode": DEMO_MODE,
        "serverless": SERVERLESS,
        "bill_wait_seconds": BILL_WAIT_SECONDS,
        "call_threshold": CALL_THRESHOLD,
        "poll_seconds": AUTO_POLL_SECONDS,
        "doc_ai_configured": bool(SARVAM_API_KEY),
    }


@app.get("/api/me")
def me(user=Depends(current_user)):
    return me_json(user)


@app.delete("/api/me")
def delete_me(user=Depends(current_user)):
    """Removes everything stored for this person, including their app password."""
    with db() as c:
        for table in ("transactions", "documents", "seen_emails", "call_log", "sessions"):
            c.execute(f"DELETE FROM {table} WHERE user_id=?", (user["id"],))
        c.execute("DELETE FROM users WHERE id=?", (user["id"],))
    _sync_locks.pop(user["id"], None)
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE)
    return response


@app.get("/api/transactions")
async def transactions(user=Depends(current_user)):
    if SERVERLESS:
        await serverless_tick()
    with db() as c:
        rows = c.execute("SELECT * FROM transactions WHERE user_id=? ORDER BY created_at DESC LIMIT 200",
                         (user["id"],)).fetchall()
    return {"now": time.time(), "transactions": [txn_json(r) for r in rows]}


@app.get("/api/stats")
def stats(user=Depends(current_user)):
    with db() as c:
        rows = c.execute("SELECT * FROM transactions WHERE user_id=? AND direction='debit' AND status!='ignored'",
                         (user["id"],)).fetchall()
    bill = [r for r in rows if r["status"] == "explained_by_bill"]
    call = [r for r in rows if r["status"] == "explained" and r["reason_source"] == "call"]
    judged = [r for r in rows if r["worth_it"] in ("yes", "no")]
    regret = sum(r["amount"] for r in judged if r["worth_it"] == "no")
    judged_total = sum(r["amount"] for r in judged)
    return {
        "total_spent": sum(r["amount"] for r in rows),
        "count": len(rows),
        "bill_count": len(bill),
        "bill_amount": sum(r["amount"] for r in bill),
        "call_count": len(call),
        "call_amount": sum(r["amount"] for r in call),
        "regret_amount": regret,
        "regret_pct": round(100 * regret / judged_total) if judged_total else 0,
        "judged_count": len(judged),
    }


@app.post("/api/sync")
async def sync(user=Depends(current_user)):
    if not user["gmail_password"]:
        raise HTTPException(400, "This account has no Gmail connected")
    try:
        return await sync_user(user)
    except GmailAccessLost as e:
        raise HTTPException(409, str(e))
    except RuntimeError as e:
        raise HTTPException(502, str(e))


@app.post("/api/ingest/email")
def ingest(mail: EmailIn, user=Depends(current_user)):
    """Takes an alert read elsewhere, e.g. through the Gmail MCP, and runs it through the same parser as the sync."""
    ts = None
    if mail.date:
        try:
            ts = datetime.fromisoformat(mail.date.replace("Z", "+00:00")).timestamp()
        except ValueError:
            raise HTTPException(400, "date must be ISO 8601")
    txn_id = ingest_email(user["id"], mail.message_id, mail.subject, mail.body, mail.sender, ts)
    return {"created": bool(txn_id), "transaction": txn_json(get_txn(txn_id)) if txn_id else None}


@app.post("/api/demo/alert")
def demo_alert(alert: DemoAlert, user=Depends(current_user)):
    if alert.amount <= 0:
        raise HTTPException(400, "Amount must be more than 0")
    merchant = alert.merchant.strip()[:40] or "Unknown merchant"
    raw = (f"INR {alert.amount:.2f} was debited from your A/c no. XX0000.\n"
           f"Transaction Info: UPI/P2M/000000000000/{merchant}\n(Demo alert)")
    txn_id = create_txn(user["id"], alert.amount, "debit", merchant, "Demo Bank", raw, "demo")
    return txn_json(get_txn(txn_id))


@app.post("/api/demo/reset")
def demo_reset(user=Depends(current_user)):
    # seen_emails stays: Gmail alerts that were already imported shouldn't reappear after a reset.
    with db() as c:
        c.execute("DELETE FROM transactions WHERE user_id=?", (user["id"],))
        c.execute("DELETE FROM documents WHERE user_id=?", (user["id"],))
    return {"ok": True}


def require_txn(txn_id, user):
    t = get_txn(txn_id)
    # Same answer for someone else's row as for a missing one, so ids can't be probed.
    if not t or t["user_id"] != user["id"]:
        raise HTTPException(404, "Transaction not found")
    return t


@app.post("/api/transactions/{txn_id}/call")
async def call_now(txn_id: str, user=Depends(current_user)):
    require_txn(txn_id, user)
    if not await place_call(txn_id):
        raise HTTPException(409, "This transaction can't be called right now")
    return txn_json(get_txn(txn_id))


@app.post("/api/transactions/{txn_id}/reason")
def set_reason(txn_id: str, body: ReasonIn, user=Depends(current_user)):
    t = require_txn(txn_id, user)
    reason = body.reason.strip()
    if not reason:
        raise HTTPException(400, "Reason can't be empty")
    worth = body.worth_it if body.worth_it in ("yes", "no") else None
    update_txn(txn_id, status="explained", reason=reason[:500], reason_source="typed",
               category=body.category or categorize(f"{reason} {t['merchant']}"), worth_it=worth, failure_reason=None)
    return txn_json(get_txn(txn_id))


@app.post("/api/transactions/{txn_id}/ignore")
def ignore(txn_id: str, user=Depends(current_user)):
    require_txn(txn_id, user)
    update_txn(txn_id, status="ignored")
    return txn_json(get_txn(txn_id))


@app.post("/api/webhooks/sarvam")
async def sarvam_webhook(request: Request, secret: str = Query("")):
    # Without this check anyone could write a reason onto any transaction.
    if not DEMO_MODE and (not WEBHOOK_SECRET or not hmac.compare_digest(secret, WEBHOOK_SECRET)):
        raise HTTPException(401, "Bad secret")
    if DEMO_MODE and WEBHOOK_SECRET and not hmac.compare_digest(secret, WEBHOOK_SECRET):
        raise HTTPException(401, "Bad secret")
    try:
        payload = await request.json()
    except ValueError:
        raise HTTPException(400, "Expected JSON")
    log.info("sarvam webhook: attempt=%s", payload.get("attempt_id"))
    return {"ok": True, "txn_id": apply_call_result(payload)}


@app.post("/api/documents")
async def upload_document(
    file: UploadFile = File(...),
    txn_id: str | None = Form(None),
    wait: bool = Query(False, description="Hold the response until the bill is read. Useful for the WhatsApp bot."),
    user=Depends(current_user),
):
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if not data:
        raise HTTPException(400, "Empty file")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "File is over 15 MB")
    doc_id = uuid.uuid4().hex[:12]
    with db() as c:
        c.execute("INSERT INTO documents (id, user_id, created_at, filename, status) VALUES (?,?,?,?,'processing')",
                  (doc_id, user["id"], time.time(), (file.filename or "bill")[:120]))
    task = spawn(process_document(user["id"], doc_id, data, txn_id))
    if wait or SERVERLESS:
        await task  # a frozen function would never finish it afterwards
    with db() as c:
        return doc_json(c.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone())


@app.get("/api/documents")
def list_documents(user=Depends(current_user)):
    with db() as c:
        rows = c.execute("SELECT * FROM documents WHERE user_id=? ORDER BY created_at DESC LIMIT 50",
                         (user["id"],)).fetchall()
    return [doc_json(r) for r in rows]


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/")
def index():
    return FileResponse(BASE / "static" / "index.html")


app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=env("HOST", "127.0.0.1"), port=int(env("PORT", "8000")))
