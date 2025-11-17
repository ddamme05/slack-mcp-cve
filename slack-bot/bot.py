#!/usr/bin/env python3
"""
Slack CVE Bot - Phase 2
Handles Slack slash commands and pushes jobs to Redis queue
"""
import os
import json
import logging
import time
import re
from collections import defaultdict, deque
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
import redis

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Slack app
app = App(
    token=os.environ.get("SLACK_BOT_TOKEN"),
    signing_secret=os.environ.get("SLACK_SIGNING_SECRET")
)

# Redis connection
redis_url = os.environ.get("REDIS_URL", "redis://redis:6379")
redis_client = redis.from_url(redis_url, decode_responses=True)

user_requests = defaultdict(lambda: deque(maxlen=10))

@app.command("/cve-search")
def handle_cve_search(ack, command, respond):
    """
    Handle /cve-search slash command
    Accepts CVE ID (e.g., CVE-2021-44228) or keywords (e.g., apache log4j)
    Optional flags: --type poc|fix|discussion|all
    """
    ack()

    user_id = command.get("user_id")
    now = time.time()

    user_requests[user_id].append(now)
    recent_requests = [t for t in user_requests[user_id] if now - t < 60]

    if len(recent_requests) > 5:
        respond({
            "text": "⚠️ Rate limit exceeded. You can make up to 5 requests per minute.\n"
                   "Please wait a moment before searching again.",
            "response_type": "ephemeral"
        })
        logger.warning(f"Rate limit exceeded for user {user_id}")
        return

    text = command.get("text", "").strip()
    response_url = command.get("response_url")

    if not text:
        respond({
            "text": "⚠️ Please provide a CVE ID or search keyword.\n"
                   "Examples:\n"
                   "• `/cve-search CVE-2021-44228`\n"
                   "• `/cve-search apache log4j`\n"
                   "• `/cve-search CVE-2021-44228 --type poc`\n\n"
                   "Type `/cve-help` for more info!",
            "response_type": "ephemeral"
        })
        return

    search_type = "all"
    query = text

    if "--type" in text:
        parts = text.split("--type")
        query = parts[0].strip()
        if len(parts) > 1:
            type_parts = parts[1].strip().split()
            if not type_parts:
                respond({
                    "text": "⚠️ Missing value for `--type` flag\n"
                           "Valid types: `poc`, `fix`, `advisory`, `all`\n\n"
                           "Example: `/cve-search CVE-2021-44228 --type poc`",
                    "response_type": "ephemeral"
                })
                return
            type_value = type_parts[0].lower()
            if type_value in ["poc", "fix", "advisory", "all"]:
                search_type = type_value
            else:
                respond({
                    "text": f"⚠️ Invalid search type: `{type_value}`\n"
                           "Valid types: `poc`, `fix`, `advisory`, `all`",
                    "response_type": "ephemeral"
                })
                return

    type_msg = f" (type: {search_type})" if search_type != "all" else ""
    respond({
        "text": f"🔍 Searching for: `{query}`{type_msg}\n"
               "⏳ Please wait, this may take a few seconds...",
        "response_type": "ephemeral"
    })

    job_data = {
        "query": query,
        "search_type": search_type,
        "user_id": user_id,
        "response_url": response_url,
        "timestamp": time.time()
    }

    try:
        redis_client.lpush("mcp_jobs", json.dumps(job_data))
        logger.info(f"Job queued for user {user_id}: {query}")

    except Exception as e:
        logger.error(f"Failed to queue job: {e}")
        respond({
            "text": f"❌ Failed to queue search request: {str(e)}",
            "response_type": "ephemeral"
        })

@app.event("app_mention")
def handle_mention(event, say, respond):
    """Handle @mentions with optional commands

    Supports:
    - @bot → Shows help (default)
    - @bot help → Shows help
    - @bot CVE-2021-44228 → CVE lookup
    - @bot apache log4j → Keyword search
    - @bot CVE-2021-44228 --type poc → Filtered lookup
    """
    user = event.get("user")
    text = event.get("text", "")

    now = time.time()
    user_requests[user].append(now)
    recent_requests = [t for t in user_requests[user] if now - t < 60]

    if len(recent_requests) > 5:
        say(
            text=f"⚠️ <@{user}> Rate limit exceeded. You can make up to 5 requests per minute.\n"
                 "Please wait a moment before searching again.",
            thread_ts=event.get("ts")
        )
        logger.warning(f"Rate limit exceeded for user {user}")
        return

    query = text.split(">", 1)[-1].strip()

    if not query or query.lower() in ["help", "?"]:
        say(
            text=f"Hi <@{user}>! 👋\n\n"
                 "*I can help you search for CVE information!*\n\n"
                 "*Quick Commands:*\n"
                 "• @me CVE-2021-44228\n"
                 "• @me apache log4j\n"
                 "• @me CVE-ID --type poc\n\n"
                 "*Available Commands:*\n"
                 "• `/cve-search CVE-2021-44228` - Look up a specific CVE\n"
                 "• `/cve-search apache log4j` - Search by keyword\n"
                 "• `/cve-search CVE-ID --type poc` - Filter by reference type\n\n"
                 "*Filter Types:*\n"
                 "• `--type poc` - Show exploits only\n"
                 "• `--type fix` - Show patches/fixes only\n"
                 "• `--type advisory` - Show advisories only\n\n"
                 "Type `/cve-help` for detailed documentation!",
            thread_ts=event.get("ts")
        )
        return

    say(
        text="🔍 Searching for CVE information...",
        thread_ts=event.get("ts")
    )

    search_type = "all"
    if "--type" in query:
        parts = query.split("--type")
        query_text = parts[0].strip()
        if len(parts) > 1:
            type_parts = parts[1].strip().split()
            if not type_parts:  # Handle empty --type flag
                say(
                    text="⚠️ Missing value for `--type` flag\n"
                         "Valid types: `poc`, `fix`, `advisory`, `all`\n\n"
                         "Example: `@me CVE-2021-44228 --type poc`",
                    thread_ts=event.get("ts")
                )
                return
            search_type_str = type_parts[0].lower()
            search_type = search_type_str if search_type_str in ["poc", "fix", "advisory", "all"] else "all"
        else:
            search_type = "all"
    else:
        query_text = query

    job_data = {
        "query": query_text,
        "user_id": user,
        "channel_id": event.get("channel"),
        "thread_ts": event.get("ts"),
        "search_type": search_type,
        "timestamp": time.time()
    }

    try:
        redis_client.lpush("mcp_jobs", json.dumps(job_data))
    except Exception as e:
        say(
            text=f"❌ Error queuing your request: {str(e)}",
            thread_ts=event.get("ts")
        )

@app.event("message")
def handle_message_events(body, logger):
    """Catch-all for message events"""
    logger.debug(f"Message event: {body}")

@app.action(re.compile(r"^view_details_.*"))
def handle_details_button(ack, body, respond):
    """Handle Details button clicks from CVE list search results"""
    ack()
    
    action_id = body["actions"][0]["action_id"]
    cve_id = action_id.replace("view_details_", "")
    
    user_id = body["user"]["id"]
    response_url = body["response_url"]
    
    now = time.time()
    user_requests[user_id].append(now)
    recent_requests = [t for t in user_requests[user_id] if now - t < 60]
    
    if len(recent_requests) > 5:
        respond({
            "response_type": "ephemeral",
            "text": "⚠️ Rate limit exceeded. You can make up to 5 requests per minute."
        })
        return
    
    job_data = {
        "query": cve_id,
        "search_type": "all",
        "user_id": user_id,
        "response_url": response_url,
        "timestamp": time.time()
    }
    
    try:
        redis_client.lpush("mcp_jobs", json.dumps(job_data))
        logger.info(f"Details request queued for user {user_id}: {cve_id}")
    except Exception as e:
        logger.error(f"Failed to queue details request: {e}")
        respond({
            "text": f"❌ Failed to load details: {str(e)}",
            "response_type": "ephemeral"
        })

@app.action(re.compile(r"^(?!view_details_).*"))
def handle_url_buttons(ack):
    """Acknowledge URL button clicks (View on NVD, Search GitHub, Check Exploits)"""
    ack()

@app.command("/cve-help")
def handle_help(ack, respond):
    """Provide help and usage information"""
    ack()
    respond({
        "text": """📘 **CVE Search Bot - Command Reference**

**Lookup specific CVE**:
`/cve-search CVE-2021-44228` - Show ALL info (default)

**Search by keyword**:
`/cve-search apache log4j` - Find CVEs by keyword
`/cve-search kubernetes rce` - Search across all CVE descriptions

**Filter results** (--type flag):
`/cve-search CVE-2021-44228 --type poc` - Show ONLY exploits/PoCs
`/cve-search CVE-2021-44228 --type fix` - Show ONLY patches/fixes
`/cve-search CVE-2021-44228 --type advisory` - Show ONLY security advisories
`/cve-search CVE-2021-44228 --type all` - Show everything (default)

**How filtering works**:
• Filters BOTH NVD references AND GitHub repos
• `--type poc` → Only shows 🚨 Exploit links and PoC repos
• `--type fix` → Only shows 🔧 Patch/Fix links and patch repos
• `--type advisory` → Only shows 📰 Security advisory links

**What you'll see**:
• 🚨 **Exploits & PoCs** - Public exploits (immediate threat!)
• 🔧 **Patches & Fixes** - Vendor patches and mitigations
• 📰 **Advisories** - Security advisories and discussions
• 🐙 **GitHub Resources** - Relevant repos and tools

**Tips**:
• Start with `--type all` to see everything
• Use `--type poc` to check if exploits exist (urgent!)
• Use `--type fix` to find patches quickly
• Keywords search all CVE descriptions

Need help? Reach out to your security team!
        """,
        "response_type": "ephemeral"
    })

def main():
    """Start the Slack bot in Socket Mode"""
    app_token = os.environ.get("SLACK_APP_TOKEN")

    if not app_token:
        logger.error("SLACK_APP_TOKEN not found in environment")
        raise ValueError("SLACK_APP_TOKEN is required")

    if not os.environ.get("SLACK_BOT_TOKEN"):
        logger.error("SLACK_BOT_TOKEN not found in environment")
        raise ValueError("SLACK_BOT_TOKEN is required")

    try:
        redis_client.ping()
        logger.info("✅ Connected to Redis")
    except Exception as e:
        logger.error(f"❌ Failed to connect to Redis: {e}")
        raise

    logger.info("🚀 Starting Slack CVE Bot (Socket Mode)...")

    handler = SocketModeHandler(app, app_token)
    handler.start()

if __name__ == "__main__":
    main()
