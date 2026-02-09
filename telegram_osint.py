#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Autore: Simone D'Agostino
# License: AGPL-3.0

import os
import sys
import json
import csv
import time
import math
import asyncio
import sqlite3
import warnings
import argparse
import hashlib
import logging
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from datetime import datetime, timezone, timedelta
from io import StringIO

from telethon import TelegramClient
from telethon.tl.types import (
    MessageMediaPhoto, MessageMediaDocument, MessageMediaWebPage,
    User, PeerChannel, Channel, Chat
)
from telethon.errors import (
    FloodWaitError, SessionPasswordNeededError,
    RpcCallFailError, TimeoutError as TLTimeoutError
)

import qrcode

warnings.filterwarnings("ignore", message="Using async sessions support is an experimental feature")

STATE_FILE = "state.json"
LOG_FILE = "scraper.log"

DB_PRAGMAS = [
    ("journal_mode", "WAL"),
    ("synchronous", "NORMAL"),
    ("temp_store", "MEMORY"),
    ("cache_size", "-20000"),
    ("busy_timeout", "7000"),
    ("foreign_keys", "ON"),
]

BATCH_SIZE = 300
STATE_SAVE_INTERVAL = 100
MAX_CONCURRENT_DOWNLOADS = 5
OVERLAP_IDS = 60

AI_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
DEDUP_THRESHOLD = 0.93
DEDUP_KNN_K = 12
KMEANS_K = 10
ANOMALY_Z = 2.8
TRIAGE_LIMIT = 300

CAMPAIGN_DAYS = 14
CAMPAIGN_DBSCAN_EPS = 0.18
CAMPAIGN_MIN_SAMPLES = 3
CAMPAIGN_MAX_DOCS = 3000

DEFAULT_DEFANG = True


def setup_logging():
    logger = logging.getLogger("tg_scraper")
    logger.setLevel(logging.INFO)

    fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)

    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(fmt)

    logger.handlers.clear()
    logger.addHandler(ch)
    logger.addHandler(fh)
    return logger


LOGGER = setup_logging()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def now_utc_str() -> str:
    return utc_now().strftime("%Y-%m-%d %H:%M:%S")


def to_utc_ts(dt: Optional[datetime]) -> int:
    if not dt:
        return int(utc_now().timestamp())
    if dt.tzinfo is None:
        return int(dt.replace(tzinfo=timezone.utc).timestamp())
    return int(dt.astimezone(timezone.utc).timestamp())


def ts_to_str(ts: int) -> str:
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def display_ascii_art():
    WHITE = "\033[97m"
    RESET = "\033[0m"
    art = r"""
         .-.
      .-(   )-.
     (   .-.   )        OFFLINE OSINT LAB
      `-(   )-`         TELEGRAM SCRAPER
         `-`
   __________________________________________________
  |  forensic db | ioc extract | ai triage | reports |
  |__________________________________________________|
    """
    print(WHITE + art + RESET)


def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)


def slug(s: str) -> str:
    return "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in (s or "")).strip("_")[:80] or "no_username"


def is_channel_id(s: str) -> bool:
    return s.lstrip("-").isdigit()


def short(s: str, n=160) -> str:
    s = (s or "").replace("\n", " ").strip()
    return s[:n] + ("…" if len(s) > n else "")


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def defang_text(s: str) -> str:
    if not s:
        return s
    s = s.replace("http://", "hxxp://").replace("https://", "hxxps://")
    s = s.replace(".", "[.]")
    return s


RE_URL = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.IGNORECASE)
RE_DOMAIN = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}))\b", re.IGNORECASE)
RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
RE_EMAIL = re.compile(r"\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,63}\b", re.IGNORECASE)
RE_HASH = re.compile(r"\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b", re.IGNORECASE)
RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
RE_ONION = re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.IGNORECASE)
RE_TG = re.compile(r"(?:t\.me/|telegram\.me/|@)([a-z0-9_]{4,32})", re.IGNORECASE)


def normalize_url(u: str) -> str:
    u = (u or "").strip().strip("()[]{}<>,.;'\"“”")
    if u.lower().startswith("www."):
        u = "http://" + u
    u = u.replace("&amp;", "&")
    return u


def extract_iocs(text: str) -> Dict[str, List[str]]:
    t = text or ""
    out = {"url": [], "domain": [], "ipv4": [], "email": [], "hash": [], "cve": [], "onion": [], "tg": []}

    for m in RE_URL.findall(t):
        out["url"].append(normalize_url(m))
    for m in RE_DOMAIN.findall(t):
        out["domain"].append(m.lower())
    for m in RE_IPV4.findall(t):
        out["ipv4"].append(m)
    for m in RE_EMAIL.findall(t):
        out["email"].append(m.lower())
    for m in RE_HASH.findall(t):
        out["hash"].append(m.lower())
    for m in RE_CVE.findall(t):
        out["cve"].append(m.upper())
    for m in RE_ONION.findall(t):
        out["onion"].append(m.lower())
    for m in RE_TG.findall(t):
        out["tg"].append(m.lower())

    for k in out:
        seen = set()
        uniq = []
        for x in out[k]:
            if x not in seen:
                uniq.append(x)
                seen.add(x)
        out[k] = uniq
    return out


@dataclass
class MessageData:
    message_id: int
    date: str
    date_ts: int
    sender_id: Optional[int]
    first_name: Optional[str]
    last_name: Optional[str]
    username: Optional[str]
    message: str
    media_type: Optional[str]
    media_path: Optional[str]
    reply_to: Optional[int]
    post_author: Optional[str]
    views: Optional[int]
    forwards: Optional[int]
    reactions: Optional[str]


class telegram-opsint:
    def __init__(self):
        self.state = self.load_state()
        self.client: Optional[TelegramClient] = None
        self.continuous_scraping_active = False
        self.db_connections: Dict[str, sqlite3.Connection] = {}

        self.batch_size = int(self.state.get("batch_size", BATCH_SIZE))
        self.state_save_interval = int(self.state.get("state_save_interval", STATE_SAVE_INTERVAL))
        self.max_concurrent_downloads = int(self.state.get("max_concurrent_downloads", MAX_CONCURRENT_DOWNLOADS))
        self.overlap_ids = int(self.state.get("overlap_ids", OVERLAP_IDS))

        self.state.setdefault("api_id", None)
        self.state.setdefault("api_hash", None)
        self.state.setdefault("scrape_media", False)
        self.state.setdefault("defang_reports", DEFAULT_DEFANG)

        self.state.setdefault("channels", {})
        self.state.setdefault("channel_names", {})
        self.state.setdefault("continuous_interval_sec", 90)
        self.save_state()

    def load_state(self) -> Dict[str, Any]:
        if os.path.exists(STATE_FILE):
            try:
                with open(STATE_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def save_state(self):
        try:
            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(self.state, f, indent=2, ensure_ascii=False)
        except Exception as e:
            LOGGER.warning(f"Failed to save state: {e}")

    def get_channel_checkpoint(self, channel_id: str) -> Tuple[int, int]:
        ch = self.state["channels"].get(channel_id, {})
        last_id = int(ch.get("last_message_id", 0) or 0)
        last_ts = int(ch.get("last_date_ts", 0) or 0)
        return last_id, last_ts

    def set_channel_checkpoint(self, channel_id: str, last_message_id: int, last_date_ts: int, flush: bool = True):
        ch = self.state["channels"].setdefault(channel_id, {})
        ch["last_message_id"] = int(last_message_id or 0)
        ch["last_date_ts"] = int(last_date_ts or 0)
        if flush:
            self.save_state()

    def get_db_connection(self, channel_id: str) -> sqlite3.Connection:
        if channel_id in self.db_connections:
            return self.db_connections[channel_id]

        ch_dir = Path(channel_id)
        ensure_dir(ch_dir)

        db_path = ch_dir / f"{channel_id}.db"
        conn = sqlite3.connect(str(db_path), check_same_thread=False, isolation_level=None)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        for k, v in DB_PRAGMAS:
            try:
                cur.execute(f"PRAGMA {k}={v};")
            except Exception:
                pass

        cur.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id INTEGER UNIQUE,
            date TEXT,
            date_ts INTEGER,
            sender_id INTEGER,
            first_name TEXT,
            last_name TEXT,
            username TEXT,
            message TEXT,
            media_type TEXT,
            media_path TEXT,
            reply_to INTEGER,
            post_author TEXT,
            views INTEGER,
            forwards INTEGER,
            reactions TEXT
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS scrape_runs (
            run_id TEXT,
            started_ts INTEGER,
            ended_ts INTEGER,
            channel_id TEXT,
            from_id INTEGER,
            to_id INTEGER,
            processed INTEGER,
            inserted INTEGER,
            ignored INTEGER,
            errors INTEGER,
            floodwait_seconds INTEGER,
            note TEXT
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id INTEGER,
            date_ts INTEGER,
            channel_id TEXT,
            ioc_type TEXT,
            ioc_value TEXT,
            UNIQUE(channel_id, message_id, ioc_type, ioc_value)
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS embeddings_cache (
            channel_id TEXT,
            message_id INTEGER,
            text_hash TEXT,
            dim INTEGER,
            vec BLOB,
            created_ts INTEGER,
            PRIMARY KEY(channel_id, message_id)
        );
        """)

        cur.execute("CREATE INDEX IF NOT EXISTS idx_message_id ON messages(message_id);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_date_ts ON messages(date_ts);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_sender ON messages(sender_id);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_reply_to ON messages(reply_to);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(ioc_value);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_emb_hash ON embeddings_cache(text_hash);")

        self.db_connections[channel_id] = conn
        return conn

    def close_db_connections(self):
        for conn in self.db_connections.values():
            try:
                conn.close()
            except Exception:
                pass
        self.db_connections.clear()

    def batch_insert_messages(self, channel_id: str, rows: List[MessageData]) -> Tuple[int, int]:
        if not rows:
            return (0, 0)
        conn = self.get_db_connection(channel_id)

        data = [
            (
                m.message_id, m.date, m.date_ts, m.sender_id, m.first_name, m.last_name, m.username,
                m.message, m.media_type, m.media_path, m.reply_to, m.post_author,
                m.views, m.forwards, m.reactions
            )
            for m in rows
        ]

        inserted = 0
        ignored = 0
        try:
            cur = conn.cursor()
            cur.execute("BEGIN;")
            before = conn.total_changes
            cur.executemany("""
                INSERT OR IGNORE INTO messages
                (message_id, date, date_ts, sender_id, first_name, last_name, username,
                 message, media_type, media_path, reply_to, post_author, views,
                 forwards, reactions)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, data)
            conn.commit()
            inserted = conn.total_changes - before
            ignored = max(0, len(rows) - inserted)
        except sqlite3.OperationalError as e:
            try:
                conn.rollback()
            except Exception:
                pass
            if "locked" in str(e).lower():
                time.sleep(1.2)
                try:
                    cur = conn.cursor()
                    cur.execute("BEGIN;")
                    before = conn.total_changes
                    cur.executemany("""
                        INSERT OR IGNORE INTO messages
                        (message_id, date, date_ts, sender_id, first_name, last_name, username,
                         message, media_type, media_path, reply_to, post_author, views,
                         forwards, reactions)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """, data)
                    conn.commit()
                    inserted = conn.total_changes - before
                    ignored = max(0, len(rows) - inserted)
                except Exception:
                    try:
                        conn.rollback()
                    except Exception:
                        pass
            else:
                LOGGER.warning(f"DB insert error: {e}")
        except Exception as e:
            try:
                conn.rollback()
            except Exception:
                pass
            LOGGER.warning(f"DB insert general error: {e}")

        return inserted, ignored

    def update_media_path(self, channel_id: str, message_id: int, media_path: str):
        conn = self.get_db_connection(channel_id)
        try:
            cur = conn.cursor()
            cur.execute("BEGIN;")
            cur.execute("UPDATE messages SET media_path=? WHERE message_id=?;", (media_path, message_id))
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass

    def insert_iocs_for_message(self, channel_id: str, message_id: int, date_ts: int, text: str):
        i = extract_iocs(text)
        rows = []
        for typ, vals in i.items():
            for v in vals:
                rows.append((message_id, date_ts, channel_id, typ, v))
        if not rows:
            return
        conn = self.get_db_connection(channel_id)
        try:
            cur = conn.cursor()
            cur.execute("BEGIN;")
            cur.executemany("""
                INSERT OR IGNORE INTO iocs(message_id, date_ts, channel_id, ioc_type, ioc_value)
                VALUES (?, ?, ?, ?, ?);
            """, rows)
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass

    def add_scrape_run(self, channel_id: str, run_id: str, started_ts: int, ended_ts: int,
                       from_id: int, to_id: int, processed: int, inserted: int, ignored: int,
                       errors: int, floodwait_seconds: int, note: str = ""):
        conn = self.get_db_connection(channel_id)
        try:
            cur = conn.cursor()
            cur.execute("BEGIN;")
            cur.execute("""
                INSERT INTO scrape_runs(run_id, started_ts, ended_ts, channel_id, from_id, to_id,
                                        processed, inserted, ignored, errors, floodwait_seconds, note)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (run_id, started_ts, ended_ts, channel_id, from_id, to_id,
                  processed, inserted, ignored, errors, floodwait_seconds, note))
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass

    def display_qr_code_ascii(self, qr_login):
        qr = qrcode.QRCode(box_size=1, border=1)
        qr.add_data(qr_login.url)
        qr.make()
        buf = StringIO()
        qr.print_ascii(out=buf)
        buf.seek(0)
        print(buf.read())

    async def qr_code_auth(self) -> bool:
        print("\n[QR] Telegram: Settings > Devices > Scan QR\n")
        qr_login = await self.client.qr_login()
        self.display_qr_code_ascii(qr_login)
        try:
            await qr_login.wait()
            print("\nLogin via QR OK")
            return True
        except SessionPasswordNeededError:
            password = input("2FA attivo. Password: ")
            await self.client.sign_in(password=password)
            print("\nLogin 2FA OK")
            return True
        except Exception as e:
            print(f"\nQR login fallito: {e}")
            return False

    async def phone_auth(self) -> bool:
        phone = input("Numero (es +39...): ").strip()
        await self.client.send_code_request(phone)
        code = input("Codice ricevuto: ").strip()
        try:
            await self.client.sign_in(phone, code)
            print("\nLogin via SMS OK")
            return True
        except SessionPasswordNeededError:
            password = input("2FA attivo. Password: ")
            await self.client.sign_in(password=password)
            print("\nLogin 2FA OK")
            return True
        except Exception as e:
            print(f"\nPhone login fallito: {e}")
            return False

    async def initialize_client(self) -> bool:
        if not all([self.state.get("api_id"), self.state.get("api_hash")]):
            print("\n=== API Telegram (my.telegram.org) ===")
            try:
                self.state["api_id"] = int(input("API ID: ").strip())
                self.state["api_hash"] = input("API Hash: ").strip()
                self.save_state()
            except ValueError:
                print("API ID non valido (numero).")
                return False

        self.client = TelegramClient("session", self.state["api_id"], self.state["api_hash"])

        try:
            await self.client.connect()
        except Exception as e:
            print(f"Failed to connect: {e}")
            print("Suggerimento: chiudi altri processi e riprova.")
            return False

        if not await self.client.is_user_authorized():
            print("\n=== Metodo login ===")
            print("[1] QR")
            print("[2] SMS")
            choice = input("Scelta (1/2): ").strip()
            ok = await (self.qr_code_auth() if choice != "2" else self.phone_auth())
            if not ok:
                await self.client.disconnect()
                return False
        else:
            print("Already authenticated.")

        return True

    async def list_channels(self) -> List[Dict[str, Any]]:
        print("\nList of channels/groups (account dialogs):")
        out = []
        i = 1
        async for dialog in self.client.iter_dialogs():
            ent = dialog.entity
            if dialog.id == 777000:
                continue
            if isinstance(ent, Channel) or isinstance(ent, Chat):
                channel_type = "Channel" if isinstance(ent, Channel) and ent.broadcast else "Group"
                username = getattr(ent, "username", None) or "no_username"
                print(f"[{i}] {dialog.title} (ID: {dialog.id}, Type: {channel_type}, Username: @{username})")
                out.append({"number": i, "title": dialog.title, "channel_id": str(dialog.id), "username": username, "type": channel_type})
                i += 1

        if out:
            with open("channels_list.csv", "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=["number", "title", "channel_id", "username", "type"])
                w.writeheader()
                w.writerows(out)
            print("\nSaved channels_list.csv")

        return out

    def view_saved_channels(self):
        if not self.state["channels"]:
            print("\n(Nessun canale salvato)")
            return
        print("\nCurrent channels:")
        for idx, (cid, meta) in enumerate(self.state["channels"].items(), 1):
            last_id = meta.get("last_message_id", 0)
            last_ts = meta.get("last_date_ts", 0)
            uname = meta.get("username", self.state.get("channel_names", {}).get(cid, "Unknown"))
            try:
                conn = self.get_db_connection(cid)
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) AS c FROM messages;")
                count = cur.fetchone()["c"]
                print(f"[{idx}] {uname} (ID: {cid}), Last ID: {last_id}, Last TS: {last_ts} ({ts_to_str(last_ts) if last_ts else 'N/A'}), Messages: {count}")
            except Exception:
                print(f"[{idx}] {uname} (ID: {cid}), Last ID: {last_id}")

    def parse_selection(self, selection: str, available: List[Dict[str, Any]] = None) -> List[str]:
        selection = (selection or "").strip()
        if not selection:
            return []

        saved_ids = list(self.state["channels"].keys())

        if selection.lower() == "all":
            if available:
                return [x["channel_id"] for x in available]
            return saved_ids

        items = [x.strip() for x in selection.split(",") if x.strip()]
        chosen: List[str] = []

        for it in items:
            if it.startswith("-") and it.lstrip("-").isdigit():
                chosen.append(it)
                continue
            try:
                n = int(it)
                if available and 1 <= n <= len(available):
                    chosen.append(available[n - 1]["channel_id"])
                elif 1 <= n <= len(saved_ids):
                    chosen.append(saved_ids[n - 1])
                else:
                    print(f"Numero fuori range: {n}")
            except ValueError:
                print(f"Input non valido: {it}")

        seen = set()
        out = []
        for x in chosen:
            if x not in seen:
                out.append(x)
                seen.add(x)
        return out

    def add_channels_from_list(self, channels_data: List[Dict[str, Any]], selection: str):
        ids = self.parse_selection(selection, available=channels_data)
        added = 0
        for cid in ids:
            info = next((c for c in channels_data if c["channel_id"] == cid), None)
            uname = (info["username"] if info else None) or "no_username"
            if cid not in self.state["channels"]:
                self.state["channels"][cid] = {"last_message_id": 0, "last_date_ts": 0, "username": uname}
                added += 1
        self.save_state()
        print(f"\nAdded {added} new channel(s).")

    async def _sleep_with_jitter(self, seconds: float):
        await asyncio.sleep(seconds + (0.05 * (1.0 + math.sin(time.time()))))

    async def _robust_iter_messages(self, entity, offset_id: int):
        last_ok = offset_id
        while True:
            try:
                async for msg in self.client.iter_messages(entity, offset_id=last_ok, reverse=True):
                    yield msg
                    last_ok = msg.id
                break
            except FloodWaitError as e:
                wait_s = int(getattr(e, "seconds", 5) or 5)
                LOGGER.warning(f"[FloodWait] sleep {wait_s}s")
                await self._sleep_with_jitter(wait_s)
            except (RpcCallFailError, TLTimeoutError, TimeoutError) as e:
                LOGGER.warning(f"[Retryable] {type(e).__name__}: {e} -> backoff 5s")
                await self._sleep_with_jitter(5)
            except Exception as e:
                LOGGER.warning(f"[IterError] {type(e).__name__}: {e} -> backoff 8s")
                await self._sleep_with_jitter(8)

    async def download_media(self, channel_id: str, message) -> Optional[str]:
        if not self.state.get("scrape_media", False):
            return None
        if not message.media or isinstance(message.media, MessageMediaWebPage):
            return None

        try:
            ch_dir = Path(channel_id)
            media_dir = ch_dir / "media"
            ensure_dir(media_dir)

            existing = list(media_dir.glob(f"{message.id}-*"))
            if existing:
                return str(existing[0])

            if isinstance(message.media, MessageMediaPhoto):
                original_name = getattr(message.file, "name", None) or "photo.jpg"
            elif isinstance(message.media, MessageMediaDocument):
                ext = getattr(message.file, "ext", None) or ".bin"
                original_name = getattr(message.file, "name", None) or f"document{ext}"
            else:
                return None

            base = Path(original_name).stem
            ext = Path(original_name).suffix or ".bin"
            filename = f"{message.id}-{slug(base)}{ext}"
            out_path = media_dir / filename

            for attempt in range(4):
                try:
                    p = await message.download_media(file=str(out_path))
                    if p and Path(p).exists():
                        return str(p)
                    return None
                except FloodWaitError as e:
                    wait_s = int(getattr(e, "seconds", 5) or 5)
                    await self._sleep_with_jitter(wait_s)
                except (RpcCallFailError, TLTimeoutError, TimeoutError):
                    await self._sleep_with_jitter(2 ** attempt)
                except Exception:
                    await self._sleep_with_jitter(2 ** attempt)

        except Exception:
            return None

        return None

    async def _resolve_entity(self, channel_id: str):
        if is_channel_id(channel_id):
            try:
                return await self.client.get_entity(int(channel_id))
            except Exception:
                pass
            try:
                return await self.client.get_entity(PeerChannel(int(channel_id)))
            except Exception:
                pass
        return await self.client.get_entity(channel_id)

    async def scrape_channel(self, channel_id: str):
        try:
            entity = await self._resolve_entity(channel_id)
        except Exception as e:
            LOGGER.warning(f"[Entity error] {channel_id}: {e}")
            return

        last_id, last_ts = self.get_channel_checkpoint(channel_id)
        start_offset = max(0, last_id - self.overlap_ids) if last_id > 0 else 0

        run_id = f"{channel_id}-{int(time.time())}"
        started_ts = int(time.time())
        floodwait_seconds = 0
        errors = 0

        LOGGER.info(f"Scraping {channel_id} from offset_id={start_offset} (last_id={last_id}) | media={'ON' if self.state.get('scrape_media') else 'OFF'}")

        batch: List[MessageData] = []
        media_queue: List[Any] = []
        processed = 0
        inserted_total = 0
        ignored_total = 0

        max_seen_id = last_id
        max_seen_ts = last_ts

        sem = asyncio.Semaphore(self.max_concurrent_downloads)

        async for message in self._robust_iter_messages(entity, offset_id=start_offset):
            try:
                if message.id is None:
                    continue
                mid = int(message.id)
                if mid <= last_id:
                    continue

                sender = None
                try:
                    sender = await message.get_sender()
                except Exception:
                    sender = None

                reactions_str = None
                try:
                    if message.reactions and getattr(message.reactions, "results", None):
                        parts = []
                        for rr in message.reactions.results:
                            emoji = getattr(rr.reaction, "emoticon", "") if rr.reaction else ""
                            count = getattr(rr, "count", None)
                            if emoji and count is not None:
                                parts.append(f"{emoji} {count}")
                        if parts:
                            reactions_str = " ".join(parts)
                except Exception:
                    reactions_str = None

                dt_ts = to_utc_ts(message.date)
                dt_str = ts_to_str(dt_ts)
                text = message.message or ""

                md = MessageData(
                    message_id=mid,
                    date=dt_str,
                    date_ts=dt_ts,
                    sender_id=getattr(message, "sender_id", None),
                    first_name=getattr(sender, "first_name", None) if isinstance(sender, User) else None,
                    last_name=getattr(sender, "last_name", None) if isinstance(sender, User) else None,
                    username=getattr(sender, "username", None) if isinstance(sender, User) else None,
                    message=text,
                    media_type=message.media.__class__.__name__ if message.media else None,
                    media_path=None,
                    reply_to=message.reply_to_msg_id if message.reply_to else None,
                    post_author=getattr(message, "post_author", None),
                    views=getattr(message, "views", None),
                    forwards=getattr(message, "forwards", None),
                    reactions=reactions_str
                )

                batch.append(md)

                if text:
                    self.insert_iocs_for_message(channel_id, mid, dt_ts, text)

                if self.state.get("scrape_media") and message.media and not isinstance(message.media, MessageMediaWebPage):
                    media_queue.append(message)

                processed += 1

                if mid > max_seen_id:
                    max_seen_id = mid
                    max_seen_ts = dt_ts

                if len(batch) >= self.batch_size:
                    ins, ign = self.batch_insert_messages(channel_id, batch)
                    inserted_total += ins
                    ignored_total += ign
                    batch.clear()
                    self.set_channel_checkpoint(channel_id, max_seen_id, max_seen_ts, flush=True)

                if processed % self.state_save_interval == 0:
                    self.set_channel_checkpoint(channel_id, max_seen_id, max_seen_ts, flush=True)
                    sys.stdout.write(f"\rprocessed={processed} max_id={max_seen_id} inserted={inserted_total}")
                    sys.stdout.flush()

            except FloodWaitError as e:
                errors += 1
                wait_s = int(getattr(e, "seconds", 5) or 5)
                floodwait_seconds += wait_s
                await self._sleep_with_jitter(wait_s)
            except Exception as e:
                errors += 1
                LOGGER.warning(f"[Message error] id={getattr(message,'id',None)}: {e}")

        if batch:
            ins, ign = self.batch_insert_messages(channel_id, batch)
            inserted_total += ins
            ignored_total += ign
            batch.clear()

        self.set_channel_checkpoint(channel_id, max_seen_id, max_seen_ts, flush=True)

        ended_ts = int(time.time())
        self.add_scrape_run(
            channel_id=channel_id,
            run_id=run_id,
            started_ts=started_ts,
            ended_ts=ended_ts,
            from_id=start_offset,
            to_id=max_seen_id,
            processed=processed,
            inserted=inserted_total,
            ignored=ignored_total,
            errors=errors,
            floodwait_seconds=floodwait_seconds,
            note="scrape_channel"
        )

        LOGGER.info(f"Done channel={channel_id} processed={processed} last_id={max_seen_id} inserted={inserted_total} ignored={ignored_total} errors={errors}")

        if media_queue and self.state.get("scrape_media"):
            LOGGER.info(f"Media to download: {len(media_queue)}")
            ok = 0
            done = 0

            async def one(m):
                async with sem:
                    return await self.download_media(channel_id, m)

            chunk = 12
            for i in range(0, len(media_queue), chunk):
                part = media_queue[i:i + chunk]
                tasks = [asyncio.create_task(one(m)) for m in part]
                for j, t in enumerate(tasks):
                    try:
                        p = await t
                        if p:
                            self.update_media_path(channel_id, part[j].id, p)
                            ok += 1
                    except Exception:
                        pass
                    done += 1
                    if done % 25 == 0:
                        sys.stdout.write(f"\rmedia {done}/{len(media_queue)} ok={ok}")
                        sys.stdout.flush()

            LOGGER.info(f"Media download complete: ok={ok}/{len(media_queue)}")

    async def scrape_selected(self, selection: Optional[str] = None):
        if not self.state["channels"]:
            print("Nessun canale salvato. Usa [L].")
            return
        self.view_saved_channels()
        if selection is None:
            print("\nScrape selection: 1,3,5 | ID (-100...) | all")
            selection = input("Enter selection: ").strip()
        chosen = self.parse_selection(selection)
        if not chosen:
            print("Nessuna selezione valida.")
            return
        print(f"\nStarting scrape of {len(chosen)} channel(s)")
        for i, cid in enumerate(chosen, 1):
            uname = self.state["channels"].get(cid, {}).get("username", "unknown")
            print(f"\n[{i}/{len(chosen)}] {uname} ({cid})")
            await self.scrape_channel(cid)
        print("\nScrape completed")

    async def continuous_scraping(self):
        if not self.state["channels"]:
            print("Nessun canale salvato.")
            return
        self.continuous_scraping_active = True
        interval = int(self.state.get("continuous_interval_sec", 90))
        print(f"\nContinuous scraping ON (interval ~{interval}s). Ctrl+C to stop.")
        try:
            while self.continuous_scraping_active:
                start = time.time()
                for cid in list(self.state["channels"].keys()):
                    if not self.continuous_scraping_active:
                        break
                    await self.scrape_channel(cid)
                elapsed = time.time() - start
                sleep_s = max(10, interval - elapsed)
                await self._sleep_with_jitter(sleep_s)
        except asyncio.CancelledError:
            pass
        except KeyboardInterrupt:
            pass
        finally:
            self.continuous_scraping_active = False
            print("\nContinuous scraping stopped")

    def export_csv_json(self, channel_id: str):
        conn = self.get_db_connection(channel_id)
        uname = self.state["channels"].get(channel_id, {}).get("username", "no_username")
        fname = f"{channel_id}_{slug(uname)}"

        out_dir = Path(channel_id)
        csv_path = out_dir / f"{fname}.csv"
        json_path = out_dir / f"{fname}.json"
        manifest_path = out_dir / f"{fname}.manifest.json"

        cur = conn.cursor()
        cur.execute("SELECT * FROM messages ORDER BY date_ts;")
        cols = [d[0] for d in cur.description]

        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(cols)
            while True:
                rows = cur.fetchmany(2000)
                if not rows:
                    break
                for r in rows:
                    w.writerow([r[c] for c in cols])

        cur2 = conn.cursor()
        cur2.execute("SELECT * FROM messages ORDER BY date_ts;")
        with open(json_path, "w", encoding="utf-8") as f:
            f.write("[\n")
            first = True
            while True:
                rows = cur2.fetchmany(1000)
                if not rows:
                    break
                for rr in rows:
                    if not first:
                        f.write(",\n")
                    first = False
                    obj = {c: rr[c] for c in cols}
                    json.dump(obj, f, ensure_ascii=False)
            f.write("\n]\n")

        manifest = {
            "generated_utc": now_utc_str(),
            "channel_id": channel_id,
            "username": uname,
            "csv": str(csv_path),
            "csv_sha256": sha256_file(csv_path),
            "json": str(json_path),
            "json_sha256": sha256_file(json_path),
        }
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

        print(f"Exported:\n - {csv_path}\n - {json_path}\n - {manifest_path}")

    async def export_menu(self):
        if not self.state["channels"]:
            print("Nessun canale salvato.")
            return
        self.view_saved_channels()
        print("\nExport selection: 1,3 | ID (-100...) | all")
        sel = input("Enter selection: ").strip()
        chosen = self.parse_selection(sel)
        if not chosen:
            print("Nessuna selezione valida.")
            return
        for cid in chosen:
            self.export_csv_json(cid)

    def open_media_folder_hint(self, channel_id: str):
        p = Path(channel_id) / "media"
        if p.exists():
            print(f"\nMedia folder: {p.resolve()}")
            print('Windows: explorer "." (dentro quella cartella)')
        else:
            print("\nNessuna cartella media trovata.")
            print("Suggerimento: attiva [M] e fai scrape.")

    def _load_ai_modules(self):
        try:
            import numpy as np
            import pandas as pd
            from sklearn.cluster import KMeans
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.neighbors import NearestNeighbors
            from sklearn.preprocessing import normalize
            from sklearn.metrics.pairwise import cosine_similarity
            from sklearn.cluster import DBSCAN
            from sentence_transformers import SentenceTransformer
            return np, pd, KMeans, TfidfVectorizer, NearestNeighbors, normalize, cosine_similarity, DBSCAN, SentenceTransformer
        except Exception as e:
            print(f"[!] AI modules missing: {e}")
            print("Installa: pip install pandas numpy scikit-learn sentence-transformers")
            return None

    def _fetch_messages_df(self, channel_ids: List[str], days: int = 60, limit_per_channel: int = 8000):
        mods = self._load_ai_modules()
        if not mods:
            return None
        np, pd, *_ = mods

        rows_all = []
        since_ts = int((utc_now() - timedelta(days=days)).timestamp())

        for cid in channel_ids:
            conn = self.get_db_connection(cid)
            cur = conn.cursor()
            cur.execute("""
                SELECT message_id, date, date_ts, sender_id, username, message, views, forwards, reactions, media_type, media_path
                FROM messages
                WHERE date_ts >= ?
                ORDER BY date_ts DESC
                LIMIT ?;
            """, (since_ts, limit_per_channel))
            for r in cur.fetchall():
                rows_all.append((cid, r["message_id"], r["date"], r["date_ts"], r["sender_id"], r["username"], r["message"],
                                 r["views"], r["forwards"], r["reactions"], r["media_type"], r["media_path"]))

        if not rows_all:
            return None

        df = pd.DataFrame(rows_all, columns=[
            "channel_id", "message_id", "date", "date_ts", "sender_id", "username", "message",
            "views", "forwards", "reactions", "media_type", "media_path"
        ])
        df["date_ts"] = df["date_ts"].astype(int)
        df["date"] = pd.to_datetime(df["date_ts"], unit="s", utc=True, errors="coerce")
        df = df.dropna(subset=["date"])
        df["message"] = df["message"].fillna("").astype(str)
        df["text_len"] = df["message"].str.len()

        df["has_url"] = df["message"].str.contains(r"http[s]?://|www\.", regex=True)
        df["has_cve"] = df["message"].str.contains(r"\bCVE-\d{4}-\d{4,7}\b", regex=True, case=False)
        df["has_ioc"] = df["message"].str.contains(
            r"\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[a-fA-F0-9]{32,64}\b",
            regex=True
        )
        df["has_ransom"] = df["message"].str.contains(r"\bransom|\bleak|\bextortion|\bdata breach|\bstealer|\baccess\b", case=False, regex=True)
        df["has_apt"] = df["message"].str.contains(r"\bAPT\b|\bTA\b|\bactor\b|\bMustang Panda\b", case=False, regex=True)
        return df

    def _triage_score(self, text: str) -> Tuple[int, List[str]]:
        t = (text or "")
        tl = t.lower()
        score = 0
        reasons = []

        if "cve-" in tl:
            score += 12
            reasons.append("CVE")
        if any(k in tl for k in ["breachforums", "exploit", "0day", "zero-day", "ransom", "leak", "extortion", "stealer"]):
            score += 10
            reasons.append("THREAT_KEYWORD")
        if any(k in tl for k in ["access for sale", "initial access", "admin panel", "rce", "lfi", "sqli", "xss", "panel", "credentials", "combo"]):
            score += 9
            reasons.append("ACCESS_TECH")

        if "http://" in tl or "https://" in tl or "www." in tl:
            score += 4
            reasons.append("URL")
        if any(k in tl for k in [".onion", "tor", "darkweb", "telegram.me", "t.me/"]):
            score += 4
            reasons.append("DARK_TG")

        if any(k in tl for k in ["advisory", "mitigation", "indicator", "ioc", "patch"]):
            score += 3
            reasons.append("DEFENSE_INFO")

        i = extract_iocs(t)
        if i["ipv4"] or i["domain"] or i["hash"] or i["email"] or i["onion"]:
            score += 4
            reasons.append("IOC_FOUND")

        if len(tl.strip()) < 40:
            score -= 2
            reasons.append("SHORT_TEXT")

        return max(0, score), reasons

    def _text_clean(self, s: str) -> str:
        s = (s or "")
        s = re.sub(r"\s+", " ", s).strip()
        return s

    def _make_embeddings_cached(self, df_subset):
        mods = self._load_ai_modules()
        if not mods:
            return None, None
        np, pd, _, _, _, _, _, _, SentenceTransformer = mods

        if df_subset is None or len(df_subset) == 0:
            return None, None

        dfx = df_subset.copy().reset_index(drop=True)
        for col in ("channel_id", "message_id", "clean"):
            if col not in dfx.columns:
                raise ValueError(f"Missing column in df_subset: {col}")

        texts = dfx["clean"].fillna("").astype(str).tolist()
        cids = dfx["channel_id"].astype(str).tolist()
        mids = dfx["message_id"].astype(int).tolist()

        model = SentenceTransformer(AI_MODEL_NAME)

        vecs = [None] * len(texts)
        missing_idx = []

        for idx in range(len(texts)):
            cid = cids[idx]
            mid = mids[idx]
            txt = texts[idx]
            th = hashlib.sha1(txt.encode("utf-8", errors="ignore")).hexdigest()

            try:
                conn = self.get_db_connection(cid)
                cur = conn.cursor()
                cur.execute("""
                    SELECT text_hash, dim, vec FROM embeddings_cache
                    WHERE channel_id=? AND message_id=?;
                """, (cid, int(mid)))
                row = cur.fetchone()

                if row and row["text_hash"] == th and row["vec"] is not None:
                    dim = int(row["dim"])
                    v = np.frombuffer(row["vec"], dtype=np.float32)
                    if v.size == dim and v.size > 0:
                        vecs[idx] = v
                        continue
            except Exception:
                pass

            missing_idx.append(idx)

        if missing_idx:
            missing_texts = [texts[i] for i in missing_idx]
            emb = model.encode(missing_texts, batch_size=64, show_progress_bar=True, normalize_embeddings=True)
            emb = np.asarray(emb, dtype=np.float32)

            if emb.ndim != 2 or emb.shape[0] != len(missing_idx):
                LOGGER.warning(f"[Embeddings] Unexpected shape {emb.shape}, expected ({len(missing_idx)}, dim). Recomputing all.")
                emb_all = model.encode(texts, batch_size=64, show_progress_bar=True, normalize_embeddings=True)
                emb_all = np.asarray(emb_all, dtype=np.float32)

                if emb_all.ndim != 2 or emb_all.shape[0] != len(texts):
                    raise RuntimeError(f"Embeddings recompute failed: got shape {emb_all.shape}")

                for idx in range(len(texts)):
                    vec = emb_all[idx]
                    vecs[idx] = vec
                    cid = cids[idx]
                    mid = mids[idx]
                    txt = texts[idx]
                    th = hashlib.sha1(txt.encode("utf-8", errors="ignore")).hexdigest()
                    try:
                        conn = self.get_db_connection(cid)
                        cur = conn.cursor()
                        cur.execute("BEGIN;")
                        cur.execute("""
                            INSERT OR REPLACE INTO embeddings_cache(channel_id, message_id, text_hash, dim, vec, created_ts)
                            VALUES (?, ?, ?, ?, ?, ?);
                        """, (cid, int(mid), th, int(vec.size), vec.tobytes(), int(time.time())))
                        conn.commit()
                    except Exception:
                        try:
                            conn.rollback()
                        except Exception:
                            pass
            else:
                for k, idx in enumerate(missing_idx):
                    vec = emb[k]
                    vecs[idx] = vec

                    cid = cids[idx]
                    mid = mids[idx]
                    txt = texts[idx]
                    th = hashlib.sha1(txt.encode("utf-8", errors="ignore")).hexdigest()

                    try:
                        conn = self.get_db_connection(cid)
                        cur = conn.cursor()
                        cur.execute("BEGIN;")
                        cur.execute("""
                            INSERT OR REPLACE INTO embeddings_cache(channel_id, message_id, text_hash, dim, vec, created_ts)
                            VALUES (?, ?, ?, ?, ?, ?);
                        """, (cid, int(mid), th, int(vec.size), vec.tobytes(), int(time.time())))
                        conn.commit()
                    except Exception:
                        try:
                            conn.rollback()
                        except Exception:
                            pass

        still_missing = [i for i, v in enumerate(vecs) if v is None]
        if still_missing:
            LOGGER.warning(f"[Embeddings] {len(still_missing)} vectors missing after cache+encode. Recomputing those.")
            need_texts = [texts[i] for i in still_missing]
            emb2 = model.encode(need_texts, batch_size=64, show_progress_bar=True, normalize_embeddings=True)
            emb2 = np.asarray(emb2, dtype=np.float32)
            if emb2.ndim != 2 or emb2.shape[0] != len(still_missing):
                raise RuntimeError(f"Embeddings partial recompute failed: got shape {emb2.shape}")
            for k, idx in enumerate(still_missing):
                vecs[idx] = emb2[k]

        E = np.vstack(vecs).astype(np.float32)
        return model, E

    def _dedup_semantic_knn(self, df):
        mods = self._load_ai_modules()
        if not mods:
            return None
        np, pd, _, _, NearestNeighbors, _, _, _, _ = mods

        df2 = df.sort_values("date", ascending=False).copy()
        df2["clean"] = df2["message"].apply(self._text_clean)
        df2 = df2[df2["clean"].str.len() >= 40].head(6000).reset_index(drop=True)

        if len(df2) < 3:
            return df2, pd.DataFrame([])

        _, E = self._make_embeddings_cached(df2[["channel_id", "message_id", "clean"]])
        if E is None:
            return None

        E = np.asarray(E, dtype=np.float32)
        n = int(min(E.shape[0], len(df2)))
        if n < 3:
            return df2, pd.DataFrame([])

        E = E[:n]
        df2 = df2.iloc[:n].reset_index(drop=True)

        k = int(min(max(2, DEDUP_KNN_K), n))
        nn = NearestNeighbors(n_neighbors=k, metric="cosine")
        nn.fit(E)
        dists, idxs = nn.kneighbors(E, return_distance=True)

        keep = []
        blocked = set()
        dup_rows = []

        for i in range(n):
            if i in blocked:
                continue
            keep.append(i)

            for dist, j in zip(dists[i][1:], idxs[i][1:]):
                j = int(j)
                sim = 1.0 - float(dist)
                if sim >= DEDUP_THRESHOLD:
                    if j not in blocked and j != i:
                        blocked.add(j)
                        a = df2.iloc[i]
                        b = df2.iloc[j]
                        dup_rows.append({
                            "sim": sim,
                            "channel_a": a["channel_id"],
                            "date_a": str(a["date"]),
                            "msgid_a": int(a["message_id"]),
                            "text_a": short(a["clean"], 180),
                            "channel_b": b["channel_id"],
                            "date_b": str(b["date"]),
                            "msgid_b": int(b["message_id"]),
                            "text_b": short(b["clean"], 180),
                        })

        kept_df = df2.iloc[keep].copy()
        dup_df = pd.DataFrame(dup_rows)
        return kept_df, dup_df

    def _cluster_topics(self, df):
        mods = self._load_ai_modules()
        if not mods:
            return None
        np, pd, KMeans, _, _, _, _, _, _ = mods

        df2 = df.sort_values("date", ascending=False).copy()
        df2["clean"] = df2["message"].apply(self._text_clean)
        df2 = df2[df2["clean"].str.len() >= 40].head(8000).reset_index(drop=True)

        if len(df2) < 8:
            return df2, pd.DataFrame([])

        _, E = self._make_embeddings_cached(df2[["channel_id", "message_id", "clean"]])
        if E is None:
            return None

        E = np.asarray(E, dtype=np.float32)
        n = int(min(E.shape[0], len(df2)))
        if n < 8:
            return df2, pd.DataFrame([])

        E = E[:n]
        df2 = df2.iloc[:n].reset_index(drop=True)

        k = min(KMEANS_K, max(3, int(math.sqrt(n) // 2)))
        k = min(k, n - 1)

        km = KMeans(n_clusters=k, random_state=42, n_init="auto")
        labels = km.fit_predict(E)
        if len(labels) != n:
            labels = labels[:n]
        df2["topic"] = labels

        def top_terms(texts, top=8):
            from collections import Counter
            c = Counter()
            for t in texts:
                for w in t.lower().split():
                    w = w.strip(".,:;!?()[]{}\"'“”‘’")
                    if len(w) < 4:
                        continue
                    if w in ("https", "http", "www", "post", "cura", "link", "oggi", "ieri"):
                        continue
                    c[w] += 1
            return ", ".join([x for x, _ in c.most_common(top)])

        topics = []
        for tid, g in df2.groupby("topic"):
            sample = g.head(6)
            topics.append({
                "topic": int(tid),
                "count": int(len(g)),
                "channels": ", ".join(sorted(set(g["channel_id"]))[:8]),
                "top_terms": top_terms(g["clean"].tolist(), top=10),
                "examples": "\n\n".join([
                    f"- {str(r.date)} | {r.channel_id} | {short(r.clean, 180)}"
                    for r in sample.itertuples()
                ])
            })

        topics_df = pd.DataFrame(topics).sort_values("count", ascending=False)
        return df2, topics_df

    def _detect_anomalies(self, df):
        mods = self._load_ai_modules()
        if not mods:
            return None
        np, pd, *_ = mods

        d = df.copy()
        d["hour"] = d["date"].dt.floor("h")

        agg = d.groupby(["channel_id", "hour"]).size().reset_index(name="count")

        out = []
        for cid, g in agg.groupby("channel_id"):
            x = g["count"].values.astype(float)
            if len(x) < 8:
                continue
            mu = x.mean()
            sd = x.std()
            if sd <= 1e-6:
                continue
            z = (x - mu) / sd
            g2 = g.copy()
            g2["z"] = z
            out.append(g2)

        res = pd.concat(out, ignore_index=True) if out else None
        if res is None:
            return None
        spikes = res[res["z"] >= ANOMALY_Z].sort_values("z", ascending=False)
        return spikes

    def _fetch_top_iocs(self, channel_ids: List[str], days: int = 60, topn: int = 30):
        mods = self._load_ai_modules()
        if not mods:
            return None
        np, pd, *_ = mods

        since_ts = int((utc_now() - timedelta(days=days)).timestamp())
        rows = []

        for cid in channel_ids:
            conn = self.get_db_connection(cid)
            cur = conn.cursor()
            cur.execute("""
                SELECT ioc_type, ioc_value, COUNT(*) as c, MAX(date_ts) as last_ts
                FROM iocs
                WHERE channel_id=? AND date_ts >= ?
                GROUP BY ioc_type, ioc_value
                ORDER BY c DESC
                LIMIT ?;
            """, (cid, since_ts, topn * 3))
            for r in cur.fetchall():
                rows.append((cid, r["ioc_type"], r["ioc_value"], int(r["c"]), int(r["last_ts"])))

        if not rows:
            return None
        df = pd.DataFrame(rows, columns=["channel_id", "ioc_type", "ioc_value", "count", "last_ts"])
        df["last_date"] = pd.to_datetime(df["last_ts"], unit="s", utc=True, errors="coerce")

        g = df.groupby(["ioc_type", "ioc_value"]).agg(count=("count", "sum"), last_ts=("last_ts", "max")).reset_index()
        g["last_date"] = pd.to_datetime(g["last_ts"], unit="s", utc=True, errors="coerce")
        g = g.sort_values(["count", "last_ts"], ascending=[False, False]).head(topn)
        return g

    def _incident_cards(self, df):
        mods = self._load_ai_modules()
        if not mods:
            return None
        np, pd, _, _, _, _, _, DBSCAN, _ = mods

        since = utc_now() - timedelta(days=CAMPAIGN_DAYS)
        d = df[df["date"] >= since].copy()
        d["clean"] = d["message"].apply(self._text_clean)
        d = d[d["clean"].str.len() >= 40].copy()

        d = d.sort_values(["triage_score", "date_ts"], ascending=[False, False]).head(CAMPAIGN_MAX_DOCS).copy()
        if len(d) < 20:
            return None

        _, E = self._make_embeddings_cached(d[["channel_id", "message_id", "clean"]])
        if E is None:
            return None

        db = DBSCAN(eps=CAMPAIGN_DBSCAN_EPS, min_samples=CAMPAIGN_MIN_SAMPLES, metric="cosine")
        labels = db.fit_predict(E)
        d["campaign"] = labels

        cards = []
        for lab, g in d.groupby("campaign"):
            if int(lab) == -1:
                continue
            g = g.sort_values("date_ts", ascending=False)
            title = short(g.iloc[0]["clean"], 90)
            chs = sorted(set(g["channel_id"].tolist()))
            cards.append({
                "campaign": int(lab),
                "count": int(len(g)),
                "channels": ", ".join(chs[:10]),
                "first_seen": str(pd.to_datetime(g["date_ts"].min(), unit="s", utc=True)),
                "last_seen": str(pd.to_datetime(g["date_ts"].max(), unit="s", utc=True)),
                "top_triage": int(g["triage_score"].max()),
                "title": title,
                "examples": "\n".join([f"- {str(r.date)} | {r.channel_id} | score={r.triage_score} | {short(r.clean, 160)}" for r in g.head(8).itertuples()])
            })

        if not cards:
            return None
        cards_df = pd.DataFrame(cards).sort_values(["count", "top_triage"], ascending=[False, False])
        return cards_df

    def _write_report_html(self, out_dir: Path, title: str, sections: List[Tuple[str, str]]):
        ensure_dir(out_dir)
        html_path = out_dir / "report_ai.html"
        parts = []
        parts.append(f"<html><head><meta charset='utf-8'><title>{title}</title>")
        parts.append("""
<style>
body{font-family:Arial;max-width:1200px;margin:24px auto;padding:0 16px;}
h1{margin:0 0 10px;}
.box{border:1px solid #ddd;border-radius:12px;padding:12px 14px;margin:14px 0;}
pre{white-space:pre-wrap;}
small{color:#666;}
table{border-collapse:collapse;width:100%;}
th,td{border:1px solid #ddd;padding:6px 8px;vertical-align:top;font-size:13px;}
th{background:#f6f6f6;}
.badge{display:inline-block;padding:2px 8px;border:1px solid #ddd;border-radius:999px;font-size:12px;margin-right:6px;}
</style>
        """.strip())
        parts.append("</head><body>")
        parts.append(f"<h1>{title}</h1>")
        parts.append(f"<div class='box'><b>Generato:</b> {now_utc_str()} | <b>AI:</b> {AI_MODEL_NAME} | <b>Defang report:</b> {self.state.get('defang_reports', True)}</div>")
        for h, content in sections:
            parts.append(f"<div class='box'><h2>{h}</h2>{content}</div>")
        parts.append("</body></html>")
        html_path.write_text("\n".join(parts), encoding="utf-8")
        return html_path

    def ai_analyze(self, selection: Optional[str] = None, days: int = 60):
        if not self.state["channels"]:
            print("Nessun canale salvato.")
            return

        self.view_saved_channels()
        if selection is None:
            print("\nAI selection: 1,3,5 | ID (-100...) | all")
            selection = input("Enter selection: ").strip()
        chosen = self.parse_selection(selection)
        if not chosen:
            print("Nessuna selezione valida.")
            return

        print("\nCarico messaggi dal DB…")
        df = self._fetch_messages_df(chosen, days=days, limit_per_channel=9000)
        if df is None or len(df) == 0:
            print("Nessun dato trovato (forse non hai ancora fatto scrape).")
            return

        print("Calcolo triage score…")
        scores = df["message"].apply(self._triage_score)
        df["triage_score"] = scores.apply(lambda x: x[0])
        df["triage_reasons"] = scores.apply(lambda x: ",".join(x[1]) if x[1] else "")

        print("Rilevo anomalie (spike) …")
        spikes = self._detect_anomalies(df)

        print("Topic clustering …")
        try:
            topic_res = self._cluster_topics(df)
        except Exception as e:
            LOGGER.warning(f"[Topic clustering failed] {e}")
            topic_res = None

        print("Dedup semantico (KNN) …")
        dedup_res = self._dedup_semantic_knn(df)

        print("Incident cards (campagne cross-channel) …")
        campaigns_df = self._incident_cards(df)

        print("Top IOCs …")
        top_iocs = self._fetch_top_iocs(chosen, days=days, topn=40)

        out_root = Path("ai_reports")
        ensure_dir(out_root)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = out_root / f"run_{stamp}"
        ensure_dir(out_dir)

        triage_df = df.sort_values(["triage_score", "date_ts"], ascending=[False, False]).head(TRIAGE_LIMIT).copy()
        triage_csv = out_dir / "triage_top.csv"
        triage_df_out = triage_df[["date_ts", "date", "channel_id", "message_id", "triage_score", "triage_reasons",
                                  "views", "forwards", "has_cve", "has_ioc", "has_url", "message", "media_path"]].copy()
        if self.state.get("defang_reports", True):
            triage_df_out["message"] = triage_df_out["message"].apply(defang_text)
        triage_df_out.to_csv(triage_csv, index=False, encoding="utf-8")

        spikes_csv = None
        if spikes is not None and len(spikes) > 0:
            spikes_csv = out_dir / "anomaly_spikes.csv"
            spikes.to_csv(spikes_csv, index=False, encoding="utf-8")

        topics_csv = None
        topics_overview_html = "<i>N/A</i>"
        examples_html = ""
        if topic_res is not None:
            df_topics, topics_df = topic_res
            topics_csv = out_dir / "topics_overview.csv"
            topics_df.to_csv(topics_csv, index=False, encoding="utf-8")

            rows = []
            for r in topics_df.head(20).itertuples():
                rows.append(f"<tr><td>{r.topic}</td><td>{r.count}</td><td>{r.top_terms}</td><td>{r.channels}</td></tr>")
            topics_overview_html = "<table><tr><th>Topic</th><th>Count</th><th>Top terms</th><th>Channels</th></tr>" + "".join(rows) + "</table>"

            ex_parts = []
            for r in topics_df.head(8).itertuples():
                ex = r.examples
                if self.state.get("defang_reports", True):
                    ex = defang_text(ex)
                ex_parts.append(f"<h3>Topic {r.topic} <small>(count={r.count})</small></h3><pre>{ex}</pre>")
            examples_html = "".join(ex_parts)

        dedup_csv = None
        if dedup_res is not None:
            kept_df, dup_df = dedup_res
            if dup_df is not None and len(dup_df) > 0:
                dedup_csv = out_dir / "duplicates_semantic.csv"
                dup_df.to_csv(dedup_csv, index=False, encoding="utf-8")

        campaigns_csv = None
        campaigns_html = "<i>N/A</i>"
        if campaigns_df is not None and len(campaigns_df) > 0:
            campaigns_csv = out_dir / "incident_cards.csv"
            campaigns_df.to_csv(campaigns_csv, index=False, encoding="utf-8")
            rows = []
            for r in campaigns_df.head(20).itertuples():
                ex = r.examples
                if self.state.get("defang_reports", True):
                    ex = defang_text(ex)
                rows.append(
                    f"<tr><td>{r.campaign}</td><td>{r.count}</td><td>{r.top_triage}</td>"
                    f"<td>{r.channels}</td><td><small>{r.first_seen}<br>{r.last_seen}</small></td>"
                    f"<td>{r.title}<br><pre>{ex}</pre></td></tr>"
                )
            campaigns_html = "<table><tr><th>ID</th><th>Count</th><th>Top score</th><th>Channels</th><th>Window</th><th>Examples</th></tr>" + "".join(rows) + "</table>"

        iocs_csv = None
        iocs_html = "<i>N/A</i>"
        if top_iocs is not None and len(top_iocs) > 0:
            iocs_csv = out_dir / "top_iocs.csv"
            top_iocs.to_csv(iocs_csv, index=False, encoding="utf-8")
            rows = []
            for r in top_iocs.head(40).itertuples():
                v = r.ioc_value
                if self.state.get("defang_reports", True) and r.ioc_type in ("url", "domain", "onion", "email", "ipv4"):
                    v = defang_text(v)
                rows.append(f"<tr><td>{r.ioc_type}</td><td>{v}</td><td>{r.count}</td><td><small>{r.last_date}</small></td></tr>")
            iocs_html = "<table><tr><th>Type</th><th>Value</th><th>Count</th><th>Last seen</th></tr>" + "".join(rows) + "</table>"

        def df_to_html_table(dfx, cols, n=25, defang_cols=None):
            if dfx is None or len(dfx) == 0:
                return "<i>N/A</i>"
            defang_cols = defang_cols or set()
            rows = []
            for r in dfx.head(n).itertuples():
                row = []
                for c in cols:
                    v = getattr(r, c)
                    sv = str(v)
                    if self.state.get("defang_reports", True) and c in defang_cols:
                        sv = defang_text(sv)
                    row.append(f"<td>{sv}</td>")
                rows.append("<tr>" + "".join(row) + "</tr>")
            head = "<tr>" + "".join([f"<th>{c}</th>" for c in cols]) + "</tr>"
            return "<table>" + head + "".join(rows) + "</table>"

        spikes_html = df_to_html_table(spikes, ["channel_id", "hour", "count", "z"], n=30) if spikes is not None else "<i>N/A</i>"

        triage_preview = triage_df.copy()
        triage_preview["msg"] = triage_preview["message"].apply(lambda s: short(defang_text(s) if self.state.get("defang_reports", True) else s, 140))
        triage_html = df_to_html_table(
            triage_preview,
            ["date", "channel_id", "message_id", "triage_score", "triage_reasons", "views", "forwards",
             "has_cve", "has_ioc", "has_url", "msg"],
            n=35
        )

        sections = []
        sections.append(("Selezione", f"<b>Canali:</b> {len(chosen)}<br><b>Finestra:</b> ultimi {days} giorni<br><b>Tot msg analizzati:</b> {len(df)}"))
        sections.append(("Triage (Top)", f"<p><span class='badge'>CSV</span> <b>{triage_csv}</b></p>{triage_html}"))
        sections.append(("Top IOCs", f"{('<p><span class=badge>CSV</span> <b>'+str(iocs_csv)+'</b></p>' if iocs_csv else '')}{iocs_html}"))
        sections.append(("Incident cards (campagne)", f"{('<p><span class=badge>CSV</span> <b>'+str(campaigns_csv)+'</b></p>' if campaigns_csv else '')}{campaigns_html}"))
        sections.append(("Anomalie (spike per ora)", f"{('<p><span class=badge>CSV</span> <b>'+str(spikes_csv)+'</b></p>' if spikes_csv else '')}{spikes_html}"))
        sections.append(("Topic overview", f"{('<p><span class=badge>CSV</span> <b>'+str(topics_csv)+'</b></p>' if topics_csv else '')}{topics_overview_html}"))
        if examples_html:
            sections.append(("Esempi per topic", examples_html))
        if dedup_csv:
            sections.append(("Duplicati semantici", f"<p><span class='badge'>CSV</span> <b>{dedup_csv}</b></p><p>Coppie near-duplicate (cosine ≥ {DEDUP_THRESHOLD}).</p>"))

        rep = self._write_report_html(out_dir, "Telegram AI Report (offline)telegram-opsint", sections)

        manifest = {
            "generated_utc": now_utc_str(),
            "selection": chosen,
            "days": days,
            "defang_reports": bool(self.state.get("defang_reports", True)),
            "files": {}
        }
        for fp in [triage_csv, spikes_csv, topics_csv, dedup_csv, campaigns_csv, iocs_csv, rep]:
            if fp:
                p = Path(fp)
                if p.exists():
                    manifest["files"][str(p)] = {"sha256": sha256_file(p), "size": p.stat().st_size}
        (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

        print("\nAI report creato:")
        print(f" - HTML: {rep}")
        print(f" - TRIAGE CSV: {triage_csv}")
        if topics_csv:
            print(f" - TOPICS CSV: {topics_csv}")
        if spikes_csv:
            print(f" - SPIKES CSV: {spikes_csv}")
        if dedup_csv:
            print(f" - DEDUP CSV: {dedup_csv}")
        if campaigns_csv:
            print(f" - INCIDENTS CSV: {campaigns_csv}")
        if iocs_csv:
            print(f" - TOP IOCs CSV: {iocs_csv}")
        print(f" - MANIFEST: {out_dir / 'manifest.json'}")
        print("\nApri l'HTML con doppio click oppure:")
        print(f'  explorer "{out_dir.resolve()}"')

    async def manage_menu(self):
        while True:
            print("\n" + "=" * 46)
            print("     telegram-opsint + AI")
            print("=" * 46)
            print("[S] Scrape channels")
            print("[C] Continuous scraping")
            print(f"[M] Media scraping: {'ON' if self.state.get('scrape_media') else 'OFF'}")
            print(f"[D] Defang reports: {'ON' if self.state.get('defang_reports', True) else 'OFF'}")
            print("[L] List & add channels")
            print("[R] Remove channels")
            print("[E] Export CSV/JSON (+ manifest)")
            print("[A] AI Analyze + Report (offline)")
            print("[G] Show media folder path")
            print("[O] Optimize DB (PRAGMA optimize)")
            print("[Q] Quit")
            print("=" * 46)

            choice = input("Enter your choice: ").strip().lower()

            try:
                if choice == "q":
                    print("Bye")
                    self.close_db_connections()
                    if self.client:
                        await self.client.disconnect()
                    return

                elif choice == "m":
                    self.state["scrape_media"] = not bool(self.state.get("scrape_media", False))
                    self.save_state()
                    print(f"Media scraping {'ON' if self.state['scrape_media'] else 'OFF'}")

                elif choice == "d":
                    self.state["defang_reports"] = not bool(self.state.get("defang_reports", True))
                    self.save_state()
                    print(f"Defang reports {'ON' if self.state['defang_reports'] else 'OFF'}")

                elif choice == "l":
                    data = await self.list_channels()
                    if not data:
                        continue
                    print("\nAdd selection: 1,3,5 | all | Enter to skip")
                    sel = input("Enter selection: ").strip()
                    if sel:
                        self.add_channels_from_list(data, sel)
                        self.view_saved_channels()

                elif choice == "s":
                    await self.scrape_selected()

                elif choice == "c":
                    await self.continuous_scraping()

                elif choice == "e":
                    await self.export_menu()

                elif choice == "a":
                    days_in = input("Quanti giorni (default 60): ").strip()
                    days_val = int(days_in) if days_in.isdigit() else 60
                    self.ai_analyze(days=days_val)

                elif choice == "g":
                    if not self.state["channels"]:
                        print("Nessun canale salvato.")
                        continue
                    self.view_saved_channels()
                    sel = input("Canale (numero o ID): ").strip()
                    chosen = self.parse_selection(sel)
                    if len(chosen) != 1:
                        print("Seleziona un solo canale.")
                        continue
                    self.open_media_folder_hint(chosen[0])

                elif choice == "o":
                    if not self.state["channels"]:
                        print("Nessun canale salvato.")
                        continue
                    for cid in self.state["channels"].keys():
                        conn = self.get_db_connection(cid)
                        try:
                            cur = conn.cursor()
                            cur.execute("PRAGMA optimize;")
                        except Exception:
                            pass
                    print("PRAGMA optimize eseguito su tutti i DB.")

                elif choice == "r":
                    if not self.state["channels"]:
                        print("Nessun canale da rimuovere.")
                        continue
                    self.view_saved_channels()
                    sel = input("Remove selection (1,2 | ID | all): ").strip()
                    chosen = self.parse_selection(sel)
                    if not chosen:
                        print("Nessuna selezione valida.")
                        continue
                    removed = 0
                    for cid in chosen:
                        if cid in self.state["channels"]:
                            del self.state["channels"][cid]
                            removed += 1
                    self.save_state()
                    print(f"Removed {removed} channel(s).")

                else:
                    print("Invalid option")

            except Exception as e:
                print(f"[!] Error: {e}")

    async def run(self, args=None):
        display_ascii_art()
        if await self.initialize_client():
            try:
                if args:
                    if args.list:
                        await self.list_channels()
                        return
                    if args.add:
                        data = await self.list_channels()
                        if data:
                            self.add_channels_from_list(data, args.add)
                        return
                    if args.scrape:
                        await self.scrape_selected(args.scrape)
                        return
                    if args.continuous:
                        await self.continuous_scraping()
                        return
                    if args.ai:
                        sel = args.selection or "all"
                        self.ai_analyze(selection=sel, days=args.days)
                        return

                await self.manage_menu()
            finally:
                self.close_db_connections()
                if self.client:
                    await self.client.disconnect()
        else:
            print("Failed to initialize client. Exiting.")


def parse_args():
    p = argparse.ArgumentParser(description="telegram-opsint + AI offline")
    p.add_argument("--list", action="store_true", help="List channels and save channels_list.csv")
    p.add_argument("--add", type=str, default=None, help="Add channels from list selection (e.g., '1,3,5' or 'all')")
    p.add_argument("--scrape", type=str, default=None, help="Scrape selection (e.g., 'all' or '1,2')")
    p.add_argument("--continuous", action="store_true", help="Continuous scraping loop")
    p.add_argument("--ai", action="store_true", help="Run AI analyze + report")
    p.add_argument("--days", type=int, default=60, help="Days window for AI")
    p.add_argument("--selection", type=str, default=None, help="Selection for AI (default all)")
    return p.parse_args()


async def main():
    args = parse_args()
    app = telegram-opsint()
    await app.run(args=args)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
