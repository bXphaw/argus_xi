#!/usr/bin/env python3
"""
Cybersec RSS digest: fetch -> full text -> AI triage+summary+IOCs -> ntfy push
                      -> daily categorized email digest.

  - up to MAX_ARTICLES_PER_RUN new articles processed per run, picked fairly
    across feeds (round-robin); leftovers are picked up automatically next hour
  - likely duplicate stories (same event covered by multiple feeds) are
    detected by title similarity and skipped before ever reaching the AI
  - articles go to Groq in small chunks; a failed chunk fails OPEN (notifies
    unfiltered) rather than losing articles
  - the AI classifies each article into a category + severity; only matching
    categories get notified, everything else is silently marked seen
  - severity drives the ntfy notification priority (critical = urgent/bypasses
    DND, low = quiet)
  - every notified article is also queued for a single daily digest email,
    grouped by category, sent once per UTC day (not per-article - no spam)
  - trafilatura failures fall back to the RSS summary; a regex IOC pass
    always runs as a backstop to the AI's own extraction
  - sent_articles.json and pending_digest.json are the two persisted state
    files, both pruned/cleared appropriately so they don't grow forever
"""

import difflib
import json
import os
import re
import smtplib
import socket
import sys
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

import feedparser
import requests
import trafilatura

socket.setdefaulttimeout(15)

# ---- config ---------------------------------------------------------------

FEEDS = [
    "https://asec.ahnlab.com/en/feed/",
    "https://www.bitdefender.com/nuxt/api/en-us/rss/labs/",
    "https://www.bleepingcomputer.com/feed/",
    "https://research.checkpoint.com/feed/",
    "https://blog.talosintelligence.com/rss/",
    "https://www.duskrise.com/feed/",
    "https://cofense.com/feed",
    "https://www.crowdstrike.com/en-us/blog/feed",
    "https://cybersecuritynews.com/feed/",
    "https://www.cybereason.com/blog/rss.xml",
    "https://cyble.com/feed/",
    "https://www.darkreading.com/rss.xml",
    "https://www.darktrace.com/blog/rss.xml",
    "https://blog.eclecticiq.com/rss.xml",
    "https://www.forescout.com/feed/",
    "https://www.fortinet.com/rss-feeds",
    "https://gbhackers.com/feed/",
    "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/",
    "https://gosecure.ai/feed/",
    "https://www.group-ib.com/feed/blogfeed/",
    "https://www.helpnetsecurity.com/view/news/feed/",
    "https://threatresearch.ext.hp.com/feed/",
    "https://blogs.infoblox.com/category/threat-intelligence/feed/",
    "https://intezer.com/feed/",
    "https://krebsonsecurity.com/feed/",
    "https://lab52.io/blog/feed/",
    "https://levelblue.com/site/blog-all-rss",
    "https://www.malwarebytes.com/blog/feed/index.xml",
    "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/feed/",
    "https://www.microsoft.com/en-us/security/blog/feed/",
    "https://moonlock.com/feed",
    "https://www.morphisec.com/feed/?post_type=blog",
    "https://unit42.paloaltonetworks.com/feed/?v=2",
    "https://permiso.io/blog/rss.xml",
    "https://www.phishlabs.com/feed",
    "https://blog.qualys.com/feed",
    "https://www.rapid7.com/rss.xml",
    "https://www.recordedfuture.com/feed",
    "https://rewterz.com/feed",
    "https://securelist.com/feed/",
    "https://securityaffairs.com/feed",
    "https://www.securityjoes.com/blog-feed.xml",
    "https://feeds.feedburner.com/securityweek",
    "https://blog.sekoia.io/feed/",
    "https://www.sentinelone.com/labs/feed/",
    "https://www.silentpush.com/feed/",
    "https://socradar.io/feed/",
    "https://news.sophos.com/en-us/category/threat-research/feed/",
    "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/rss.xml",
    "https://sed-cms.broadcom.com/rss/v1/blogs/rss.xml",
    "https://thedfirreport.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.intego.com/mac-security-blog/feed/",
    "https://www.theregister.com/security/headlines.rss",
    "https://blog.google/threat-analysis-group/rss/",
    "https://threatmon.io/feed/",
    "http://feeds.trendmicro.com/TrendMicroSimplySecurity",
    "https://www.volexity.com/feed/",
    "https://www.welivesecurity.com/en/rss/feed/",
    "https://www.wiz.io/api/feed/cloud-threat-landscape/rss.xml",
    "https://www.zscaler.com/blogs/feeds/security-research",
]

SENT_FILE = "sent_articles.json"
DIGEST_FILE = "pending_digest.json"
MAX_AGE_DAYS = 60
CHUNK_SIZE = 5
MAX_ARTICLES_PER_RUN = 30
DEDUP_WINDOW_HOURS = 72       # how far back to check for duplicate stories
DEDUP_SIMILARITY_THRESHOLD = 0.75  # 0-1, title similarity ratio
DIGEST_HOUR = 7               # UTC hour after which the daily digest fires (once/day)

GROQ_MODEL = "openai/gpt-oss-120b"
GROQ_API_KEY = os.environ["GROQ_API_KEY"]

NTFY_TOPIC = os.environ["NTFY_TOPIC"]
NTFY_URL = f"https://ntfy.sh/{NTFY_TOPIC}"

# Gmail defaults (SSL on 465). For Outlook/Office365 use smtp.office365.com:587
# with server.starttls() instead of SMTP_SSL - ask if you need that variant.
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
EMAIL_ADDRESS = os.environ["EMAIL_ADDRESS"]
EMAIL_APP_PASSWORD = os.environ["EMAIL_APP_PASSWORD"]

IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
}

CATEGORIES = {
    "poland": (
        "Cyberattacks, data leaks, ransomware, APT activity, or threat-actor "
        "activity connected to Poland - targeting Polish organizations or "
        "citizens, or attributed to Poland-linked actors.",
        "🇵🇱 Poland",
    ),
    "apt_campaign": (
        "Active APT campaign or operation activity anywhere in the world - "
        "an observed, ongoing campaign. Do NOT use this for general "
        "background/profile pieces about a threat actor with no new activity.",
        "APT Campaign",
    ),
    "malware_windows": ("Newly discovered malware targeting Windows.", "Malware · Windows"),
    "malware_android": ("Newly discovered malware targeting Android.", "Malware · Android"),
    "malware_macos": ("Newly discovered malware targeting macOS.", "Malware · macOS"),
    "malware_linux": ("Newly discovered malware targeting Linux.", "Malware · Linux"),
    "malware_other": (
        "Newly discovered malware targeting other platforms (iOS, IoT, routers, cross-platform).",
        "Malware · Other",
    ),
    "new_technique": (
        "A novel attack method, exploitation technique, or social-engineering "
        "approach, not tied to a single specific malware family.",
        "New Technique",
    ),
    "major_vuln": (
        "A newly disclosed or actively-exploited high-impact vulnerability (CVE).",
        "Major Vuln",
    ),
    "data_breach": (
        "A notable large-scale data breach not already covered by the Poland category.",
        "Data Breach",
    ),
}

SEVERITY_PRIORITY = {
    "critical": "urgent",
    "high": "high",
    "medium": "default",
    "low": "low",
}


# ---- state: seen articles --------------------------------------------------

def load_sent() -> dict:
    if not os.path.exists(SENT_FILE):
        return {}
    with open(SENT_FILE, "r", encoding="utf-8") as f:
        raw = json.load(f)
    # migrate old format (url -> iso string) to new format (url -> {ts, title})
    migrated = {}
    for url, v in raw.items():
        migrated[url] = {"ts": v, "title": None} if isinstance(v, str) else v
    return migrated


def save_sent(sent: dict) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(days=MAX_AGE_DAYS)
    pruned = {url: v for url, v in sent.items() if datetime.fromisoformat(v["ts"]) > cutoff}
    with open(SENT_FILE, "w", encoding="utf-8") as f:
        json.dump(pruned, f, indent=2)


def mark_seen(sent: dict, url: str, title: str) -> None:
    sent[url] = {"ts": datetime.now(timezone.utc).isoformat(), "title": title}


def recent_titles(sent: dict, hours: int) -> list[str]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    out = []
    for v in sent.values():
        try:
            if v.get("title") and datetime.fromisoformat(v["ts"]) > cutoff:
                out.append(v["title"])
        except Exception:
            continue
    return out


def is_duplicate_title(title: str, recent: list[str]) -> bool:
    norm = title.lower().strip()
    for other in recent:
        if difflib.SequenceMatcher(None, norm, other.lower().strip()).ratio() >= DEDUP_SIMILARITY_THRESHOLD:
            return True
    return False


# ---- state: pending digest --------------------------------------------------

def load_digest_state() -> dict:
    if not os.path.exists(DIGEST_FILE):
        return {"items": [], "last_sent_date": None}
    with open(DIGEST_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_digest_state(state: dict) -> None:
    with open(DIGEST_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def send_digest_email(items: list[dict]) -> bool:
    grouped = {}
    for item in items:
        grouped.setdefault(item["category"], []).append(item)

    lines = []
    for cat_key, arts in grouped.items():
        label = CATEGORIES.get(cat_key, (None, cat_key))[1]
        lines.append(f"\n{label} ({len(arts)})")
        for a in arts:
            lines.append(f"  {a['title']}")
            lines.append(f"  -> {a['url']}")

    today = datetime.now(timezone.utc).strftime("%b %d, %Y")
    msg = EmailMessage()
    msg["Subject"] = f"Cybersec Digest - {today} ({len(items)} articles)"
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = EMAIL_ADDRESS
    msg.set_content("\n".join(lines))

    try:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=30) as server:
            server.login(EMAIL_ADDRESS, EMAIL_APP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"  digest email failed: {e}", file=sys.stderr)
        return False


def maybe_send_digest(state: dict) -> None:
    if not state["items"]:
        return
    now = datetime.now(timezone.utc)
    today_str = now.date().isoformat()
    if now.hour >= DIGEST_HOUR and state.get("last_sent_date") != today_str:
        if send_digest_email(state["items"]):
            state["items"] = []
            state["last_sent_date"] = today_str


# ---- fair selection across feeds -------------------------------------------

def gather_new_entries(sent: dict) -> list:
    per_feed = []
    for feed_url in FEEDS:
        try:
            parsed = feedparser.parse(feed_url)
            feed_new = [e for e in parsed.entries if e.get("link") and e.get("link") not in sent]
        except Exception as e:
            print(f"  feed failed, skipping: {feed_url} ({e})", file=sys.stderr)
            feed_new = []
        per_feed.append(feed_new)
    return per_feed


def round_robin_select(per_feed: list, cap: int) -> list:
    selected = []
    while len(selected) < cap and any(per_feed):
        for feed_entries in per_feed:
            if not feed_entries:
                continue
            selected.append(feed_entries.pop(0))
            if len(selected) >= cap:
                break
    return selected


# ---- extraction --------------------------------------------------------------

def get_full_text(url: str, rss_summary: str) -> str:
    try:
        downloaded = trafilatura.fetch_url(url)
        text = trafilatura.extract(downloaded) if downloaded else None
        if text and len(text) > 200:
            return text
    except Exception as e:
        print(f"  trafilatura failed for {url}: {e}", file=sys.stderr)
    return rss_summary or ""


def clean_excerpt(text: str, max_len: int = 400) -> str:
    """Truncates at a sentence boundary if one is reasonably close to the
    limit, otherwise at a word boundary - never mid-word."""
    text = text.strip()
    if len(text) <= max_len:
        return text
    truncated = text[:max_len]
    last_break = max(truncated.rfind(". "), truncated.rfind("! "), truncated.rfind("? "))
    if last_break > max_len * 0.5:
        return truncated[: last_break + 1]
    last_space = truncated.rfind(" ")
    return (truncated[:last_space] if last_space > 0 else truncated) + "…"


def extract_iocs_regex(text: str) -> list[str]:
    found = set()
    for pattern in IOC_PATTERNS.values():
        found.update(pattern.findall(text))
    return sorted(found)


# ---- AI: chunked calls, retry, graceful per-chunk failure ------------------

def build_prompt(chunk: list[dict]) -> str:
    cat_lines = "\n".join(f"- {key}: {desc}" for key, (desc, _label) in CATEGORIES.items())
    numbered = "\n\n".join(f"[{i}] URL: {a['url']}\n{a['text'][:6000]}" for i, a in enumerate(chunk))
    return (
        "You are a cybersecurity news triage assistant. For each article below, "
        "decide whether it matches ANY of these categories:\n"
        f"{cat_lines}\n\n"
        "If an article matches none of these, mark it not relevant - general "
        "product news, listicles, opinion pieces, and non-security stories "
        "should be marked not relevant.\n\n"
        "For relevant articles only:\n"
        "- write a 2-3 sentence summary IN ENGLISH\n"
        "- list any threat indicators mentioned (IPs, domains, hashes, CVEs)\n"
        "- rate severity as one of: critical (actively exploited / widespread, "
        "immediate danger), high, medium, or low\n\n"
        "Respond ONLY with JSON in this exact shape, nothing else, no markdown, "
        "no commentary:\n"
        '{"0": {"relevant": true, "category": "malware_windows", "severity": "high", '
        '"summary": "...", "iocs": ["..."]}, "1": {"relevant": false}}\n\n'
        f"{numbered}"
    )


def summarize_chunk(chunk: list[dict]) -> dict:
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    body = {
        "model": GROQ_MODEL,
        "messages": [{"role": "user", "content": build_prompt(chunk)}],
        "temperature": 0.3,
        "reasoning_effort": "low",
    }

    for attempt in range(3):
        try:
            resp = requests.post(url, headers=headers, json=body, timeout=60)
            if resp.status_code == 429:
                wait = 5 * (2 ** attempt)
                print(f"  Groq rate-limited, retrying in {wait}s", file=sys.stderr)
                time.sleep(wait)
                continue
            if resp.status_code >= 400:
                print(f"  Groq error {resp.status_code}: {resp.text[:500]}", file=sys.stderr)
            resp.raise_for_status()
            raw = resp.json()["choices"][0]["message"]["content"]
            raw = raw.strip().removeprefix("```json").removesuffix("```").strip()
            parsed = json.loads(raw)
            return {chunk[int(i)]["url"]: v for i, v in parsed.items()}
        except Exception as e:
            print(f"  Groq call failed (attempt {attempt + 1}): {e}", file=sys.stderr)
            time.sleep(3)

    return {}


def summarize_all(articles: list[dict]) -> tuple[dict, set]:
    results = {}
    failed_urls = set()
    for i in range(0, len(articles), CHUNK_SIZE):
        chunk = articles[i:i + CHUNK_SIZE]
        chunk_results = summarize_chunk(chunk)
        if chunk_results:
            results.update(chunk_results)
        else:
            failed_urls.update(a["url"] for a in chunk)
    return results, failed_urls


# ---- notify -------------------------------------------------------------------

def send_ntfy(title: str, message: str, link: str, priority: str = "default") -> bool:
    try:
        r = requests.post(
            NTFY_URL,
            data=message.encode("utf-8"),
            headers={
                "Title": title.encode("utf-8"),
                "Click": link,
                "Tags": "warning,closed_lock_with_key",
                "Priority": priority,
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
    digest_state = load_digest_state()

    per_feed = gather_new_entries(sent)
    total_new = sum(len(f) for f in per_feed)
    candidates = round_robin_select(per_feed, MAX_ARTICLES_PER_RUN)

    if total_new > len(candidates):
        print(
            f"  {total_new} new articles found across all feeds, processing "
            f"{len(candidates)} this run - the rest will be picked up in "
            f"following hours.",
            file=sys.stderr,
        )

    recent = recent_titles(sent, DEDUP_WINDOW_HOURS)
    new_articles = []
    for entry in candidates:
        link = entry.get("link")
        title = entry.get("title", "(no title)")
        if is_duplicate_title(title, recent):
            mark_seen(sent, link, title)
            print(f"  Skipping likely duplicate: {title}", file=sys.stderr)
            continue
        text = get_full_text(link, entry.get("summary", ""))
        new_articles.append({"url": link, "title": title, "text": text})
        recent.append(title)
        time.sleep(0.5)

    if new_articles:
        ai_results, failed_urls = summarize_all(new_articles)

        for art in new_articles:
            if art["url"] in failed_urls:
                summary = clean_excerpt(art["text"], 400)
                label = "Unfiltered"
                ai_iocs, cat_key, priority = [], None, "default"
            else:
                ai = ai_results.get(art["url"])
                if not ai or not ai.get("relevant"):
                    mark_seen(sent, art["url"], art["title"])
                    continue
                summary = ai.get("summary", "")
                ai_iocs = ai.get("iocs", [])
                cat_key = ai.get("category")
                label = CATEGORIES.get(cat_key, (None, cat_key or "Flagged"))[1]
                priority = SEVERITY_PRIORITY.get(ai.get("severity"), "default")

            all_iocs = sorted(set(ai_iocs) | set(extract_iocs_regex(art["text"])))
            title_line = f"[{label}] {art['title']}"
            body = summary
            if all_iocs:
                body += "\n\nIOCs: " + ", ".join(all_iocs[:15])

            if send_ntfy(title_line, body, art["url"], priority):
                mark_seen(sent, art["url"], art["title"])
                if cat_key:
                    digest_state["items"].append(
                        {"category": cat_key, "title": art["title"], "url": art["url"]}
                    )
            else:
                print(f"  Will retry next run: {art['url']}", file=sys.stderr)
    else:
        print("Nothing new this run.")

    save_sent(sent)
    maybe_send_digest(digest_state)
    save_digest_state(digest_state)


if __name__ == "__main__":
    main()
