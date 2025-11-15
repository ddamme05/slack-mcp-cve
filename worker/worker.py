import os
import json
import time
import re
import redis
import httpx
import asyncio
from fastmcp import Client
from dotenv import load_dotenv

load_dotenv()

redis_client = redis.Redis.from_url(
    os.environ.get("REDIS_URL", "redis://localhost:6379"),
    decode_responses=True
)

async def call_mcp_tool_async(tool_name: str, arguments: dict) -> dict:
    """Call MCP server tool via FastMCP Client with Streamable HTTP"""
    try:
        mcp_url = os.environ.get('MCP_SERVER_URL', 'http://mcp-server:8080')

        async with Client(f"{mcp_url}/mcp") as client:
            # Call the tool
            result = await client.call_tool(tool_name, arguments)

            # Extract the result content
            if result and result.content:
                # MCP returns list of content items
                if isinstance(result.content, list) and len(result.content) > 0:
                    content_item = result.content[0]
                    if hasattr(content_item, 'text'):
                        # Parse JSON response from tool
                        return json.loads(content_item.text)

                return {"error": "No content returned from tool"}

    except Exception as e:
        return {"error": str(e)}

def call_mcp_tool(tool_name: str, arguments: dict) -> dict:
    """Synchronous wrapper for async MCP tool call"""
    return asyncio.run(call_mcp_tool_async(tool_name, arguments))

def format_cve_report(nvd_data: dict, github_data: dict) -> str:
    """Format single CVE details for Slack"""

    if "error" in nvd_data:
        return f"❌ **CVE Lookup Failed**: {nvd_data['error']}"

    severity_emojis = {
        'CRITICAL': '🔴', 'HIGH': '🟠',
        'MEDIUM': '🟡', 'LOW': '🟢', 'UNKNOWN': '⚪'
    }

    severity = nvd_data.get('severity', 'Unknown').upper()
    emoji = severity_emojis.get(severity, '⚪')
    cve_id = nvd_data.get('cve_id', 'UNKNOWN')

    # Bug Fix 4: Handle missing or None description
    description = nvd_data.get('description', 'No description available')
    if description:
        desc_text = description[:300] + ("..." if len(description) > 300 else "")
    else:
        desc_text = "No description available"

    report = [
        f"{emoji} **{severity}**: {cve_id}",
        "",
        "📋 **Summary**",
        desc_text,
        "",
        "📊 **Details**",
        f"• CVSS Score: {nvd_data['cvss_score']}",
        f"• Published: {nvd_data['published_date'][:10]}",
        f"• Last Modified: {nvd_data['last_modified'][:10]}",
    ]

    # Add references with type labels
    if nvd_data.get('references'):
        report.append("")
        report.append("🔗 **References**")
        for ref in nvd_data['references']:
            report.append(f"• {ref['type']}: {ref['url']}")

    # Add GitHub repos
    if github_data and not github_data.get('error'):
        repos = github_data.get('repositories', [])
        if repos:
            report.append("")
            report.append(f"🐙 **GitHub Resources** ({github_data.get('total_found', 0)} total)")
            for repo in repos[:5]:
                name = repo['name']
                # Highlight Trail of Bits repos
                if 'trailofbits' in name.lower():
                    name = f"**{name}** ⭐ Trail of Bits!"
                report.append(f"• {name} ({repo['stars']} ⭐)")
                report.append(f"  {repo['url']}")

    # Add risk assessment
    report.append("")
    report.append("⚠️ **Risk Assessment**")

    # Bug Fix 5: Handle non-numeric CVSS scores
    cvss_raw = nvd_data.get('cvss_score', 0)
    try:
        cvss = float(cvss_raw) if cvss_raw != 'N/A' else 0
    except (ValueError, TypeError):
        cvss = 0  # Treat non-numeric as unknown

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
        return f"❌ **Search Failed**: {cve_data['error']}"

    keyword = cve_data.get('keyword', 'unknown')
    total = cve_data.get('total_results', 0)
    cves = cve_data.get('cves', [])

    if total == 0:
        return f"🔍 No CVEs found for keyword: `{keyword}`"

    lines = [
        f"🔍 **CVE Search Results**: `{keyword}`",
        f"Found {total} CVEs (showing top {min(10, len(cves))}):",
        ""
    ]

    for cve in cves[:10]:
        severity = cve.get('severity', 'UNKNOWN').upper()
        emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(severity, '⚪')
        cve_id = cve.get('cve_id', 'N/A')
        cvss = cve.get('cvss_score', 'N/A')
        desc = cve.get('description', '')[:100]

        lines.append(f"{emoji} **{cve_id}** (CVSS: {cvss})")
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

                # Bug Fix 1: Handle malformed JSON
                try:
                    job_data = json.loads(job_json)
                except json.JSONDecodeError as e:
                    print(f"❌ Malformed JSON in job: {e}", flush=True)
                    continue

                # Bug Fix 2: Validate query field exists and is not empty
                query = job_data.get("query", "").strip()
                if not query:
                    print(f"❌ Job missing or empty 'query' field: {job_data}", flush=True)
                    continue

                # Bug Fix 3: Validate response_url in production mode
                test_mode = os.environ.get("TEST_MODE", "true").lower() == "true"
                if not test_mode:
                    response_url = job_data.get("response_url")
                    if not response_url:
                        print(f"❌ Job missing 'response_url' (TEST_MODE=false)", flush=True)
                        continue

                print(f"📥 Processing job: {query}", flush=True)

                # Distinguish CVE ID vs keyword query
                if re.match(r'^CVE-\d{4}-\d{4,}$', query.upper()):
                    # Specific CVE lookup
                    print(f"  → Detected CVE ID query", flush=True)
                    nvd_data = call_mcp_tool("lookup_cve_details", {"cve_id": query})
                    github_data = call_mcp_tool("search_github_cve_repos", {"cve_id": query})
                    report = format_cve_report(nvd_data, github_data)
                else:
                    # Keyword search
                    print(f"  → Detected keyword query", flush=True)
                    cve_data = call_mcp_tool("search_cve_by_keyword", {"keyword": query})
                    report = format_cve_list(cve_data)

                # Send output based on TEST_MODE (already validated above)
                if test_mode:
                    # Phase 1: Console output for testing
                    print(f"✅ Job completed. Report:\n{report}\n", flush=True)
                else:
                    # Phase 2: Send to Slack webhook
                    try:
                        response = httpx.post(
                            job_data["response_url"],
                            json={"text": report},
                            timeout=5.0
                        )
                        response.raise_for_status()
                        print(f"✅ Job completed and sent to Slack", flush=True)
                    except Exception as webhook_error:
                        print(f"❌ Failed to send to Slack: {webhook_error}", flush=True)

        except Exception as e:
            print(f"❌ Worker error: {e}", flush=True)
            time.sleep(1)

if __name__ == "__main__":
    main()
