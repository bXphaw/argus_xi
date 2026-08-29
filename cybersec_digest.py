#!/usr/bin/env python3
"""
Cybersec RSS digest: fetch -> full text -> AI summary+IOCs -> ntfy push.

  - one Groq call per RUN (batched), not one per article -> biggest free-tier saver
  - Groq failures/429s fall back to a plain-text excerpt instead of dropping the article
  - trafilatura failures fall back to the RSS-provided summary
  - a deterministic regex pass always runs, merged with AI-extracted IOCs
  - an article is only marked "sent" after the ntfy push actually succeeds
  - sent_articles.json is pruned so it doesn't grow forever
  - NTFY_TOPIC should be a long random string (see chat) - never a guessable word
"""

import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone

import feedparser
import requests
import trafilatura

# ---- config ---------------------------------------------------------------

FEEDS = [
    "https://xkcd.com/rss.xml",
]

SENT_FILE = "sent_articles.json"
MAX_AGE_DAYS = 60  # prune dedup entries older than this

# llama-3.1-8b-instant has the most generous daily token budget on Groq's free
# tier, which matters since we send several long articles in one batched call.
# Swap to "llama-3.3-70b-versatile" for higher quality if your batches are
# small enough to stay under its lower daily token cap. Groq occasionally
# renames/retires models - check https://console.groq.com/docs/models
GROQ_MODEL = "openai/gpt-oss-120b"
GROQ_API_KEY = os.environ["GROQ_API_KEY"]

NTFY_TOPIC = os.environ["NTFY_TOPIC"]  # long random string, GitHub secret only
NTFY_URL = f"https://ntfy.sh/{NTFY_TOPIC}"

IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
}


# ---- state ------------------------------------------------------------------

def load_sent() -> dict:
    if not os.path.exists(SENT_FILE):
        return {}
    with open(SENT_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_sent(sent: dict) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(days=MAX_AGE_DAYS)
    pruned = {
        url: ts for url, ts in sent.items()
        if datetime.fromisoformat(ts) > cutoff
    }
    with open(SENT_FILE, "w", encoding="utf-8") as f:
        json.dump(pruned, f, indent=2)


# ---- extraction --------------------------------------------------------------

def get_full_text(url: str, rss_summary: str) -> str:
    try:
        downloaded = trafilatura.fetch_url(url)
        text = trafilatura.extract(downloaded) if downloaded else None
        if text and len(text) > 200:
            return text
    except Exception as e:
        print(f"  trafilatura failed for {url}: {e}", file=sys.stderr)
    return rss_summary or ""  # fallback: whatever RSS gave us, even if thin


def extract_iocs_regex(text: str) -> list[str]:
    found = set()
    for pattern in IOC_PATTERNS.values():
        found.update(pattern.findall(text))
    return sorted(found)


# ---- AI: one batched call per run, with retry + graceful failure -----------

def summarize_batch(articles: list[dict]) -> dict:
    """Returns {url: {"summary": str, "iocs": [...]}}. Empty dict if the whole
    batch fails - caller falls back to raw excerpts, nothing is lost."""
    if not articles:
        return {}

    numbered = "\n\n".join(
        f"[{i}] URL: {a['url']}\n{a['text'][:6000]}"
        for i, a in enumerate(articles)
    )
    prompt = (
        "Dla kazdego z ponizszych artykulow o cyberbezpieczenstwie zwroc "
        "2-3 zdaniowe podsumowanie po polsku oraz liste wskaznikow zagrozen "
        "(IP, domeny, hashe, CVE) jesli wystepuja. Odpowiedz WYLACZNIE w "
        'formacie JSON: {"0": {"summary": "...", "iocs": [...]}, "1": {...}}, '
        "bez zadnego dodatkowego tekstu, bez markdown.\n\n" + numbered
    )

    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    body = {
        "model": GROQ_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
    }

    for attempt in range(3):
        try:
            resp = requests.post(url, headers=headers, json=body, timeout=60)
            if resp.status_code == 429:
                wait = 5 * (2 ** attempt)
                print(f"  Groq rate-limited, retrying in {wait}s", file=sys.stderr)
                time.sleep(wait)
                continue
            resp.raise_for_status()
            raw = resp.json()["choices"][0]["message"]["content"]
            raw = raw.strip().removeprefix("```json").removesuffix("```").strip()
            parsed = json.loads(raw)
            return {articles[int(i)]["url"]: v for i, v in parsed.items()}
        except Exception as e:
            print(f"  Groq call failed (attempt {attempt + 1}): {e}", file=sys.stderr)
            time.sleep(3)

    return {}


# ---- notify -------------------------------------------------------------------

def send_ntfy(title: str, message: str, link: str) -> bool:
    try:
        r = requests.post(
            NTFY_URL,
            data=message.encode("utf-8"),
            headers={
                "Title": title.encode("utf-8"),
                "Click": link,
                "Tags": "warning,closed_lock_with_key",
            },
            timeout=15,
        )
        return r.status_code == 200
    except Exception as e:
        print(f"  ntfy push failed: {e}", file=sys.stderr)
        return False


# ---- main -----------------------------------------------------------------

def main():
    sent = load_sent()
    new_articles = []

    for feed_url in FEEDS:
        parsed = feedparser.parse(feed_url)
        for entry in parsed.entries:
            link = entry.get("link")
            if not link or link in sent:
                continue
            text = get_full_text(link, entry.get("summary", ""))
            new_articles.append({
                "url": link,
                "title": entry.get("title", "(no title)"),
                "text": text,
            })
            time.sleep(0.5)  # be polite to the source site

    if not new_articles:
        print("Nothing new this run.")
        return

    ai_results = summarize_batch(new_articles)  # {} if the whole batch failed

    for art in new_articles:
        ai = ai_results.get(art["url"])
        if ai:
            summary = ai["summary"]
            ai_iocs = ai.get("iocs", [])
        else:
            summary = art["text"][:400].strip() + "…"  # AI unavailable this run
            ai_iocs = []

        # deterministic backstop always runs, merged in regardless of AI success
        all_iocs = sorted(set(ai_iocs) | set(extract_iocs_regex(art["text"])))

        body = summary
        if all_iocs:
            body += "\n\nIOCs: " + ", ".join(all_iocs[:15])

        if send_ntfy(art["title"], body, art["url"]):
            sent[art["url"]] = datetime.now(timezone.utc).isoformat()
        else:
            print(f"  Will retry next run: {art['url']}", file=sys.stderr)

    save_sent(sent)


if __name__ == "__main__":
    main()

