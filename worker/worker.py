import os
import json
import time
import re
import redis
import httpx
import asyncio
from contextlib import nullcontext
from fastmcp import Client
from dotenv import load_dotenv
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from blocks import format_cve_blocks, format_cve_list_blocks, format_error_blocks

try:
    from langfuse import Langfuse
except ImportError:
    Langfuse = None

load_dotenv()

USE_BLOCKS = os.environ.get("USE_BLOCKS", "true").lower() == "true"
TRACE_LOGS_ENABLED = os.environ.get("TRACE_LOGS_ENABLED", "false").lower() == "true"
TRACE_INCLUDE_QUERY = os.environ.get("TRACE_INCLUDE_QUERY", "false").lower() == "true"
LANGFUSE_ENABLED = os.environ.get("LANGFUSE_ENABLED", "false").lower() == "true"
TEST_MODE_VERBOSE = os.environ.get("TEST_MODE_VERBOSE", "false").lower() == "true"
slack_client = None
if os.environ.get("SLACK_BOT_TOKEN"):
    slack_client = WebClient(token=os.environ.get("SLACK_BOT_TOKEN"))
    print("✅ Slack Web API client initialized", flush=True)

if USE_BLOCKS:
    print("✅ Slack Block Kit enabled", flush=True)
else:
    print("ℹ️ Slack Block Kit disabled (using text formatting)", flush=True)


class NoOpObservation:
    """No-op observation used when Langfuse tracing is disabled."""

    def update(self, **kwargs):
        return None

    def start_as_current_observation(self, **kwargs):
        return nullcontext(NoOpObservation())


def initialize_langfuse():
    """Initialize Langfuse only when explicitly enabled and configured."""
    if not LANGFUSE_ENABLED:
        return None

    if Langfuse is None:
        print("⚠️ Langfuse tracing enabled but langfuse package is not installed", flush=True)
        return None

    if not os.environ.get("LANGFUSE_PUBLIC_KEY") or not os.environ.get("LANGFUSE_SECRET_KEY"):
        print("⚠️ Langfuse tracing enabled but credentials are missing", flush=True)
        return None

    try:
        client = Langfuse()
        print("✅ Langfuse tracing enabled", flush=True)
        return client
    except Exception as e:
        print(f"⚠️ Langfuse initialization failed: {e}", flush=True)
        return None

def connect_redis_with_retry(max_retries=5):
    """Connect to Redis with exponential backoff

    Handles Docker Compose startup race conditions where worker
    starts before Redis is ready.

    Args:
        max_retries: Maximum connection attempts (default 5)

    Returns:
        redis.Redis: Connected Redis client

    Raises:
        Exception: If all retry attempts fail
    """
    for attempt in range(max_retries):
        try:
            client = redis.Redis.from_url(
                os.environ.get("REDIS_URL", "redis://localhost:6379"),
                decode_responses=True
            )
            # Test connection
            client.ping()
            print(f"✅ Connected to Redis (attempt {attempt + 1})", flush=True)
            return client
        except Exception as e:
            wait_time = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s, 8s, 16s
            print(f"❌ Redis connection failed (attempt {attempt + 1}/{max_retries}): {e}", flush=True)

            if attempt < max_retries - 1:
                print(f"   Retrying in {wait_time}s...", flush=True)
                time.sleep(wait_time)
            else:
                print(f"💀 Redis connection failed after {max_retries} attempts. Exiting.", flush=True)
                raise

redis_client = connect_redis_with_retry()
langfuse_client = initialize_langfuse()

async def call_mcp_tool_async(tool_name: str, arguments: dict) -> dict:
    """Call MCP server tool via FastMCP Client with Streamable HTTP"""
    try:
        mcp_url = os.environ.get('MCP_SERVER_URL', 'http://mcp-server:8080')

        async with Client(f"{mcp_url}/mcp") as client:
            result = await client.call_tool(tool_name, arguments)
            if result and result.content:
                if isinstance(result.content, list) and len(result.content) > 0:
                    content_item = result.content[0]
                    if hasattr(content_item, 'text'):
                        return json.loads(content_item.text)

                return {"error": "No content returned from tool"}

    except Exception as e:
        return {"error": str(e)}

def call_mcp_tool(tool_name: str, arguments: dict) -> dict:
    """Synchronous wrapper for async MCP tool call"""
    return asyncio.run(call_mcp_tool_async(tool_name, arguments))


def get_job_id(job_data: dict) -> str:
    """Return queue correlation ID, with fallback for legacy jobs."""
    return job_data.get("job_id", "legacy-no-job-id")


def get_job_origin(job_data: dict) -> str:
    """Return queue origin, with fallback for legacy jobs."""
    return job_data.get("origin", "unknown-origin")


def get_langfuse_metadata(job_data: dict) -> dict:
    """Return non-sensitive metadata for Langfuse observations."""
    return {
        "job_id": get_job_id(job_data),
        "origin": get_job_origin(job_data),
    }


def build_delivery_payload(report: str, blocks: list | None) -> tuple[dict, str]:
    """Build Slack delivery payload and report mode for logging/tracing."""
    payload = {"text": report}
    mode = "text"
    if USE_BLOCKS and blocks:
        payload["blocks"] = blocks
        mode = "blocks"
    return payload, mode


def deliver_response(job_data: dict, report: str, blocks: list | None, job_prefix: str) -> dict:
    """Send a formatted worker response back to Slack."""
    payload, mode = build_delivery_payload(report, blocks)

    if job_data.get("response_url"):
        try:
            response = httpx.post(
                job_data["response_url"],
                json=payload,
                timeout=5.0
            )
            response.raise_for_status()
            print(f"✅ {job_prefix} Job completed and sent to Slack (webhook, {mode})", flush=True)
            return {"delivered": True, "delivery_method": "webhook", "mode": mode}
        except Exception as webhook_error:
            print(f"❌ {job_prefix} Failed to send to Slack webhook: {webhook_error}", flush=True)
            return {
                "delivered": False,
                "delivery_method": "webhook",
                "mode": mode,
                "error": str(webhook_error),
            }

    if job_data.get("channel_id") and slack_client:
        try:
            kwargs = {
                "channel": job_data["channel_id"],
                "thread_ts": job_data.get("thread_ts"),
                **payload,
            }
            slack_client.chat_postMessage(**kwargs)
            print(f"✅ {job_prefix} Job completed and sent to Slack (Web API, {mode})", flush=True)
            return {"delivered": True, "delivery_method": "web_api", "mode": mode}
        except SlackApiError as slack_error:
            error_message = slack_error.response["error"]
            print(f"❌ {job_prefix} Failed to send to Slack Web API: {error_message}", flush=True)
            return {
                "delivered": False,
                "delivery_method": "web_api",
                "mode": mode,
                "error": error_message,
            }
        except Exception as e:
            print(f"❌ {job_prefix} Failed to send to Slack Web API: {e}", flush=True)
            return {
                "delivered": False,
                "delivery_method": "web_api",
                "mode": mode,
                "error": str(e),
            }

    print(f"⚠️ {job_prefix} Job missing delivery method (no response_url or channel_id)", flush=True)
    return {
        "delivered": False,
        "delivery_method": "missing",
        "mode": mode,
        "error": "missing_delivery_method",
    }


def summarize_tool_result(tool_name: str, result: dict) -> dict:
    """Summarize tool output into trace-friendly metadata."""
    summary = {
        "tool_name": tool_name,
        "error": result.get("error"),
    }

    if tool_name == "lookup_cve_details":
        summary.update({
            "cve_id": result.get("cve_id"),
            "severity": result.get("severity"),
            "cvss_score": result.get("cvss_score"),
            "is_kev": result.get("is_kev"),
            "reference_count": len(result.get("references", [])),
        })
    elif tool_name == "search_github_cve_repos":
        summary.update({
            "cve_id": result.get("cve_id"),
            "total_found": result.get("total_found", 0),
            "repo_count": len(result.get("repositories", [])),
            "search_type": result.get("search_type"),
        })
    elif tool_name == "check_cisa_kev_details":
        summary.update({
            "cve_id": result.get("cve_id"),
            "is_kev": result.get("is_kev"),
            "date_added": result.get("date_added"),
            "known_ransomware_use": result.get("known_ransomware_use"),
        })
    elif tool_name == "search_cve_by_keyword":
        summary.update({
            "keyword": result.get("keyword"),
            "total_results": result.get("total_results", 0),
            "result_count": len(result.get("cves", [])),
        })

    return {key: value for key, value in summary.items() if value is not None}


def emit_trace_event(job_data: dict, event_type: str, **fields) -> None:
    """Emit structured trace-like logs for later platform integration."""
    if not TRACE_LOGS_ENABLED:
        return

    event = {
        "event": "worker_trace",
        "event_type": event_type,
        "job_id": get_job_id(job_data),
        "origin": get_job_origin(job_data),
        "search_type": job_data.get("search_type", "all"),
        "timestamp": round(time.time(), 3),
    }
    if TRACE_INCLUDE_QUERY:
        event["query"] = job_data.get("query")
    event.update(fields)
    print(f"🔎 TRACE {json.dumps(event, sort_keys=True)}", flush=True)


def start_job_observation(job_data: dict):
    """Create a top-level Langfuse observation for a worker job when enabled."""
    if not langfuse_client:
        return nullcontext(NoOpObservation())

    return langfuse_client.start_as_current_observation(
        name="cve-research",
        as_type="span",
        trace_context={"trace_id": langfuse_client.create_trace_id(seed=get_job_id(job_data))},
        input={
            "query": job_data.get("query"),
            "search_type": job_data.get("search_type", "all"),
        },
        metadata=get_langfuse_metadata(job_data),
    )


def call_mcp_tool_with_observation(job_data: dict, parent_observation, tool_name: str, arguments: dict) -> dict:
    """Call an MCP tool and mirror the result into Langfuse when enabled."""
    with parent_observation.start_as_current_observation(
        name=tool_name,
        as_type="tool",
        input=arguments,
        metadata=get_langfuse_metadata(job_data),
    ) as tool_observation:
        result = call_mcp_tool(tool_name, arguments)
        tool_observation.update(output=summarize_tool_result(tool_name, result))

    emit_trace_event(
        job_data,
        "tool_completed",
        **summarize_tool_result(tool_name, result)
    )
    return result

def format_cve_report(nvd_data: dict, github_data: dict, search_type: str = "all") -> str:
    """Format single CVE details for Slack, optionally filtered by search_type"""

    if "error" in nvd_data:
        error_msg = nvd_data['error']
        cve_id = nvd_data.get('cve_id', 'UNKNOWN')

        # Provide helpful error message for "not found"
        if "not found" in error_msg.lower():
            return f"""❌ *CVE Not Found*: {cve_id}

This CVE ID doesn't exist in the NVD database yet. Possible reasons:
• CVE reserved but details not published yet
• Typo in CVE ID (check year and number)
• Very recent CVE (NVD updates every ~2 hours)

*What to try*:
• Check CVE format: `CVE-YYYY-NNNNN` (e.g., CVE-2021-44228)
• Search by keyword: `/cve-search apache log4j`
• Visit NVD directly: https://nvd.nist.gov/vuln/detail/{cve_id}"""

        return f"❌ *CVE Lookup Failed*: {error_msg}"

    severity_emojis = {
        'CRITICAL': '🔴', 'HIGH': '🟠',
        'MEDIUM': '🟡', 'LOW': '🟢', 'UNKNOWN': '⚪'
    }

    severity = nvd_data.get('severity', 'Unknown').upper()
    emoji = severity_emojis.get(severity, '⚪')
    cve_id = nvd_data.get('cve_id', 'UNKNOWN')

    is_kev = nvd_data.get('is_kev', False)

    description = nvd_data.get('description', 'No description available')
    if description:
        desc_text = description[:300] + ("..." if len(description) > 300 else "")
    else:
        desc_text = "No description available"

    severity_header = f"{emoji} *{severity}*: {cve_id}"
    if is_kev:
        severity_header += " 🚨 *ACTIVELY EXPLOITED (CISA KEV)*"

    report = [
        severity_header,
        "",
        "📋 *Summary*",
        desc_text,
        "",
        "📊 *Details*",
        f"• CVSS Score: {nvd_data['cvss_score']}",
    ]

    if nvd_data.get('cwe'):
        report.append(f"• Weakness: {', '.join(nvd_data['cwe'])}")

    report.extend([
        f"• Published: {nvd_data['published_date'][:10]}",
        f"• Last Modified: {nvd_data['last_modified'][:10]}",
    ])

    if is_kev:
        try:
            kev_details = call_mcp_tool("check_cisa_kev_details", {"cve_id": cve_id})

            if not kev_details.get('error') and kev_details.get('is_kev'):
                report.append("")
                report.append("⚠️ *CISA KEV Details*")
                report.append(f"• Added to KEV: {kev_details.get('date_added', 'Unknown')}")
                report.append(f"• Remediation Due: {kev_details.get('due_date', 'Unknown')}")

                ransomware_use = kev_details.get('known_ransomware_use', 'Unknown')
                report.append(f"• Ransomware Use: {ransomware_use}")

                if kev_details.get('required_action'):
                    action = kev_details['required_action']
                    if len(action) > 100:
                        action = action[:97] + "..."
                    report.append(f"• Action Required: {action}")
        except Exception as e:
            print(f"Warning: Failed to fetch CISA KEV details: {e}", flush=True)

    if nvd_data.get('references'):
        all_refs = nvd_data['references']
        refs = all_refs.copy()

        if search_type == "poc":
            refs = [r for r in refs if "poc" in r.get('categories', [])]
        elif search_type == "fix":
            refs = [r for r in refs if "fix" in r.get('categories', [])]
        elif search_type == "advisory":
            refs = [r for r in refs if "advisory" in r.get('categories', [])]
        if refs:
            report.append("")
            type_label = {
                "poc": "🚨 *Exploits & PoCs*",
                "fix": "🔧 *Patches & Fixes*",
                "advisory": "📰 *Security Advisories*",
                "all": "🔗 *References*"
            }.get(search_type, "🔗 *References*")
            report.append(type_label)
            for ref in refs:
                if not ref.get('nvd_tagged', True):
                    report.append(f"• {ref['type']} (auto-classified): {ref['url']}")
                else:
                    report.append(f"• {ref['type']}: {ref['url']}")
        elif search_type != "all":
            untagged_count = sum(1 for r in all_refs if not r.get('nvd_tagged', True))
            if untagged_count > 0:
                report.append("")
                report.append(f"⚠️ *NVD Data Quality Issue*")
                report.append(f"This CVE has {len(all_refs)} reference(s), but some weren't tagged by NVD.")
                report.append(f"Heuristic classification applied. View all: https://nvd.nist.gov/vuln/detail/{cve_id}")
            else:
                report.append("")
                report.append(f"ℹ️ No {search_type} resources found in NVD references")

    if github_data and not github_data.get('error'):
        repos = github_data.get('repositories', [])
        if repos:
            report.append("")
            type_label = {
                "poc": "🐙 *GitHub Exploits & PoCs*",
                "fix": "🐙 *GitHub Patches & Fixes*",
                "advisory": "🐙 *GitHub Security Advisories*",
                "all": "🐙 *GitHub Resources*"
            }.get(search_type, "🐙 *GitHub Resources*")
            report.append(f"{type_label} ({github_data.get('total_found', 0)} total)")
            for repo in repos[:5]:
                name = repo['name']
                report.append(f"• {name} ({repo['stars']} ⭐)")
                report.append(f"  {repo['url']}")
        elif search_type != "all":
            report.append("")
            report.append(f"ℹ️ No {search_type} repositories found on GitHub")

    report.append("")
    report.append("⚠️ *Risk Assessment*")

    cvss_raw = nvd_data.get('cvss_score', 0)
    try:
        cvss = float(cvss_raw) if cvss_raw != 'N/A' else 0
    except (ValueError, TypeError):
        cvss = 0

    if cvss >= 9.0:
        report.append("🚨 Critical severity. Immediate patching required.")
    elif cvss >= 7.0:
        report.append("⚠️ High severity. Prioritize patching.")
    elif cvss >= 4.0:
        report.append("⚡ Medium severity. Schedule patching.")
    else:
        report.append("✅ Low severity. Update when convenient.")

    report.append("")
    report.append(f"🔍 Full details: https://nvd.nist.gov/vuln/detail/{cve_id}")

    return "\n".join(report)

def format_cve_list(cve_data: dict) -> str:
    """Format keyword search results for Slack"""

    if "error" in cve_data:
        return f"❌ *Search Failed*: {cve_data['error']}"

    keyword = cve_data.get('keyword', 'unknown')
    total = cve_data.get('total_results', 0)
    cves = cve_data.get('cves', [])

    if total == 0:
        return f"🔍 No CVEs found for keyword: `{keyword}`"

    lines = [
        f"🔍 *CVE Search Results*: `{keyword}`",
        f"Found {total} CVEs (showing top {min(10, len(cves))}):",
        ""
    ]

    for cve in cves[:10]:
        severity = cve.get('severity', 'UNKNOWN').upper()
        emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(severity, '⚪')
        cve_id = cve.get('cve_id', 'N/A')
        cvss = cve.get('cvss_score', 'N/A')
        desc = cve.get('description', '')[:100]

        lines.append(f"{emoji} *{cve_id}* (CVSS: {cvss})")
        lines.append(f"   {desc}...")
        lines.append("")

    lines.append(f"💡 Use `/cve-search {cves[0]['cve_id']}` for detailed info")

    return "\n".join(lines)

def main():
    """Main worker loop with CVE vs keyword dispatch"""
    print("🚀 Worker started, waiting for jobs...", flush=True)

    while True:
        try:
            result = redis_client.brpop("mcp_jobs", timeout=5)

            if result:
                _, job_json = result

                try:
                    job_data = json.loads(job_json)
                except json.JSONDecodeError as e:
                    print(f"❌ Malformed JSON in job: {e}", flush=True)
                    continue

                job_id = get_job_id(job_data)
                job_origin = get_job_origin(job_data)
                job_prefix = f"[job:{job_id}][origin:{job_origin}]"
                query = job_data.get("query", "").strip()
                if not query:
                    print(f"❌ {job_prefix} Job missing or empty 'query' field: {job_data}", flush=True)
                    continue

                job_timestamp = job_data.get("timestamp", time.time())
                job_age = time.time() - job_timestamp
                if job_age > 3600:
                    print(f"⚠️ {job_prefix} Skipping stale job (age: {job_age:.0f}s)", flush=True)
                    continue

                test_mode = os.environ.get("TEST_MODE", "true").lower() == "true"
                if not test_mode:
                    has_webhook = bool(job_data.get("response_url"))
                    has_channel = bool(job_data.get("channel_id"))

                    if not has_webhook and not has_channel:
                        print(f"❌ {job_prefix} Job missing delivery method (no response_url or channel_id)", flush=True)
                        continue

                    if has_channel and not slack_client:
                        print(f"❌ {job_prefix} Job requires Slack Web API but SLACK_BOT_TOKEN not set", flush=True)
                        continue

                print(f"📥 {job_prefix} Processing job: {query}", flush=True)

                search_type = job_data.get("search_type", "all")
                emit_trace_event(job_data, "job_started")

                with start_job_observation(job_data) as job_observation:
                    if re.match(r'^CVE-\d{4}-\d{4,}$', query.upper()):
                        print(f"  → {job_prefix} Detected CVE ID query (type: {search_type})", flush=True)
                        nvd_data = call_mcp_tool_with_observation(
                            job_data,
                            job_observation,
                            "lookup_cve_details",
                            {"cve_id": query},
                        )
                        github_data = call_mcp_tool_with_observation(
                            job_data,
                            job_observation,
                            "search_github_cve_repos",
                            {
                                "cve_id": query,
                                "search_type": search_type
                            },
                        )
                        print(
                            f"  → {job_prefix} GitHub data received "
                            f"(total_found={github_data.get('total_found', 0)}, "
                            f"repo_count={len(github_data.get('repositories', []))})",
                            flush=True,
                        )

                        kev_data = None
                        if nvd_data.get("is_kev") and not nvd_data.get("error"):
                            kev_data = call_mcp_tool_with_observation(
                                job_data,
                                job_observation,
                                "check_cisa_kev_details",
                                {"cve_id": query},
                            )

                        report = format_cve_report(nvd_data, github_data, search_type)
                        blocks = format_cve_blocks(nvd_data, github_data, kev_data, search_type) if USE_BLOCKS else None
                    else:
                        print(f"  → {job_prefix} Detected keyword query", flush=True)
                        cve_data = call_mcp_tool_with_observation(
                            job_data,
                            job_observation,
                            "search_cve_by_keyword",
                            {"keyword": query},
                        )
                        report = format_cve_list(cve_data)
                        blocks = format_cve_list_blocks(cve_data) if USE_BLOCKS else None

                    emit_trace_event(
                        job_data,
                        "report_built",
                        has_blocks=bool(blocks),
                        report_length=len(report),
                        test_mode=test_mode,
                    )

                    if test_mode:
                        print(
                            f"✅ {job_prefix} Job completed in test mode "
                            f"(report_length={len(report)}, has_blocks={bool(blocks)})",
                            flush=True,
                        )
                        if TEST_MODE_VERBOSE:
                            print(f"📝 {job_prefix} Test mode report:\n{report}\n", flush=True)
                        if USE_BLOCKS and blocks:
                            print(f"📦 {job_prefix} Block count: {len(blocks)} blocks\n", flush=True)
                        delivery_result = {
                            "delivered": False,
                            "delivery_method": "test_mode",
                            "has_blocks": bool(blocks),
                        }
                    else:
                        with job_observation.start_as_current_observation(
                            name="deliver_response",
                            as_type="tool",
                            input={
                                "has_response_url": bool(job_data.get("response_url")),
                                "has_channel_id": bool(job_data.get("channel_id")),
                            },
                            metadata=get_langfuse_metadata(job_data),
                        ) as delivery_observation:
                            delivery_result = deliver_response(job_data, report, blocks, job_prefix)
                            delivery_observation.update(output=delivery_result)

                    job_observation.update(
                        output={
                            "report_length": len(report),
                            "has_blocks": bool(blocks),
                            **delivery_result,
                        }
                    )
                    emit_trace_event(job_data, "job_completed", **delivery_result)

        except Exception as e:
            print(f"❌ Worker error: {e}", flush=True)
            time.sleep(1)

if __name__ == "__main__":
    main()
