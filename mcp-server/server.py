from fastmcp import FastMCP
import httpx
from typing import Dict, Optional
import re
import os
import json
import asyncio
from collections import deque
from datetime import datetime, timedelta
from heuristics import (
    classify_reference_tags,
    categorize_reference,
    get_reference_priority_label,
    normalize_url_for_dedup,
    is_broken_link
)

mcp = FastMCP("CVE Research MCP", version="1.0.0")

# Load API keys from environment
NVD_API_KEY = os.getenv("NVD_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

# Log token status on startup
if GITHUB_TOKEN:
    token_preview = GITHUB_TOKEN[:7] + "..." + GITHUB_TOKEN[-4:] if len(GITHUB_TOKEN) > 11 else "***"
    print(f"✅ GitHub token loaded: {token_preview}", flush=True)
    print(f"   Rate limit: 5000 requests/hour", flush=True)
else:
    print(f"⚠️ No GitHub token - using unauthenticated API (60 requests/hour)", flush=True)

# Simple async rate limiter
class RateLimiter:
    """Simple token bucket rate limiter"""
    def __init__(self, max_requests: int, time_window: int):
        self.max_requests = max_requests
        self.time_window = time_window  # seconds
        self.requests = deque()
        self.lock = asyncio.Lock()

    async def acquire(self):
        """Wait until a request can be made"""
        async with self.lock:
            now = datetime.now()

            while self.requests and (now - self.requests[0]) > timedelta(seconds=self.time_window):
                self.requests.popleft()

            if len(self.requests) >= self.max_requests:
                sleep_time = (self.requests[0] + timedelta(seconds=self.time_window) - now).total_seconds()
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
                    return await self.acquire()

            self.requests.append(now)

# Initialize rate limiters based on API key presence
# NVD: 5 req/30s without key, 50 req/30s with key
nvd_rate_limiter = RateLimiter(
    max_requests=50 if NVD_API_KEY else 5,
    time_window=30
)

# GitHub: 60 req/hour without token, 5000 req/hour with token
github_rate_limiter = RateLimiter(
    max_requests=5000 if GITHUB_TOKEN else 60,
    time_window=3600
)

@mcp.tool()
async def lookup_cve_details(cve_id: str) -> Dict:
    """Look up CVE from NIST NVD"""

    if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id.upper()):
        return {"error": f"Invalid CVE format: {cve_id}"}

    cve_id = cve_id.upper()

    await nvd_rate_limiter.acquire()

    async with httpx.AsyncClient() as client:
        try:
            headers = {"User-Agent": "Security-CVE-Bot"}
            if NVD_API_KEY:
                headers["apiKey"] = NVD_API_KEY

            response = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve_id},
                headers=headers,
                timeout=10.0
            )
            response.raise_for_status()
            data = response.json()

            if not data.get("vulnerabilities"):
                return {"error": f"CVE {cve_id} not found"}

            vuln = data["vulnerabilities"][0]["cve"]

            descriptions = vuln.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d["lang"] == "en"),
                "No description available"
            )

            cvss_score = "N/A"
            severity = "Unknown"
            metrics = vuln.get("metrics", {})

            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore", "N/A")
                severity = cvss_data.get("baseSeverity", "Unknown")

            references = []
            seen_urls = set()  # Track URLs to prevent duplicates
            for ref in vuln.get("references", []):
                url = ref.get("url", "")
                source = ref.get("source", "")
                
                if not url or url.strip() == "":
                    continue
                
                nvd_tags = ref.get("tags", [])
                
                if is_broken_link(nvd_tags):
                    continue
                
                tags, nvd_tagged = classify_reference_tags(
                    url=url,
                    source=source,
                    original_tags=nvd_tags
                )
                
                categories = categorize_reference(tags)
                primary_label, priority = get_reference_priority_label(tags)
                normalized_url = normalize_url_for_dedup(url)
                
                if normalized_url in seen_urls:
                    continue
                
                seen_urls.add(normalized_url)

                references.append({
                    "url": url,  # Keep original URL (not normalized) for display
                    "source": source,
                    "type": primary_label,
                    "priority": priority,
                    "categories": categories,
                    "tags": tags,
                    "nvd_tagged": nvd_tagged
                })

            is_kev = False
            for ref in references:
                source = ref.get("source", "").lower()
                tags = ref.get("tags", [])
                url = ref.get("url", "").lower()
                if "cisa" in source or "cisa" in url or "US Government Resource" in tags:
                    is_kev = True
                    break

            cwe_list = []
            weaknesses = vuln.get("weaknesses", [])
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    cwe_id = desc.get("value", "")
                    if cwe_id.startswith("CWE-"):
                        cwe_list.append(cwe_id)
            cwe_list = list(dict.fromkeys(cwe_list))[:3]

            return {
                "cve_id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "severity": severity,
                "published_date": vuln.get("published", "Unknown"),
                "last_modified": vuln.get("lastModified", "Unknown"),
                "references": references,
                "cwe": cwe_list,
                "is_kev": is_kev
            }

        except Exception as e:
            return {"error": f"NVD API error: {str(e)}"}

@mcp.tool()
async def check_cisa_kev_details(cve_id: str) -> Dict:
    """Check if CVE is in CISA Known Exploited Vulnerabilities catalog and get metadata"""

    if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id.upper()):
        return {"error": "Invalid CVE format"}

    cve_id = cve_id.upper()

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                timeout=10.0
            )
            response.raise_for_status()
            kev_data = response.json()

            for vuln in kev_data.get("vulnerabilities", []):
                if vuln.get("cveID") == cve_id:
                    return {
                        "is_kev": True,
                        "cve_id": cve_id,
                        "vulnerability_name": vuln.get("vulnerabilityName", "Unknown"),
                        "date_added": vuln.get("dateAdded", "Unknown"),
                        "due_date": vuln.get("dueDate", "Unknown"),
                        "known_ransomware_use": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                        "short_description": vuln.get("shortDescription", ""),
                        "required_action": vuln.get("requiredAction", "Apply updates per vendor instructions")
                    }

            return {
                "is_kev": False,
                "cve_id": cve_id,
                "message": "CVE not in CISA KEV catalog"
            }

        except Exception as e:
            return {"error": f"CISA KEV API error: {str(e)}"}

@mcp.tool()
async def search_github_cve_repos(cve_id: str, search_type: str = "all") -> Dict:
    """Search GitHub for repos mentioning CVE"""

    if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id.upper()):
        return {"error": "Invalid CVE format"}

    cve_id = cve_id.upper()

    if search_type == "poc":
        query = f'{cve_id} poc OR {cve_id} exploit OR {cve_id} "proof of concept"'
    elif search_type == "fix":
        query = f'{cve_id} fix OR {cve_id} patch OR {cve_id} mitigation'
    elif search_type == "advisory":
        query = f'{cve_id} vulnerability OR {cve_id} security OR {cve_id} advisory'
    else:
        query = f'{cve_id}'

    await github_rate_limiter.acquire()

    async with httpx.AsyncClient() as client:
        try:
            headers = {
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "Security-CVE-Bot"
            }
            if GITHUB_TOKEN:
                headers["Authorization"] = f"token {GITHUB_TOKEN}"

            response = await client.get(
                "https://api.github.com/search/repositories",
                params={"q": query, "per_page": 5, "sort": "stars"},
                headers=headers,
                timeout=10.0
            )
            response.raise_for_status()

            data = response.json()
            total_count = data.get("total_count", 0)
            items = data.get("items", [])

            repos = []
            for repo in items:
                repos.append({
                    "name": repo["full_name"],
                    "description": repo.get("description", "")[:150],
                    "stars": repo["stargazers_count"],
                    "url": repo["html_url"],
                    "updated": repo["updated_at"]
                })

            return {
                "cve_id": cve_id,
                "search_type": search_type,
                "total_found": total_count,
                "repositories": repos
            }

        except Exception as e:
            return {"error": f"GitHub search failed: {str(e)}"}

@mcp.tool()
async def search_cve_by_keyword(keyword: str, year: Optional[str] = None) -> Dict:
    """Search NVD for CVEs by keyword"""

    params = {"keywordSearch": keyword, "resultsPerPage": 10}

    if year:
        params["pubStartDate"] = f"{year}-01-01T00:00:00.000"
        params["pubEndDate"] = f"{year}-12-31T23:59:59.999"

    await nvd_rate_limiter.acquire()

    async with httpx.AsyncClient() as client:
        try:
            headers = {"User-Agent": "Security-CVE-Bot"}
            if NVD_API_KEY:
                headers["apiKey"] = NVD_API_KEY

            response = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params=params,
                headers=headers,
                timeout=15.0
            )
            response.raise_for_status()
            data = response.json()

            cves = []
            for vuln_wrapper in data.get("vulnerabilities", []):
                vuln = vuln_wrapper["cve"]

                descriptions = vuln.get("descriptions", [])
                description = next(
                    (d["value"] for d in descriptions if d["lang"] == "en"),
                    "No description"
                )

                metrics = vuln.get("metrics", {})
                cvss_score = "N/A"
                severity = "Unknown"

                if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                    cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                    cvss_score = cvss_data.get("baseScore", "N/A")
                    severity = cvss_data.get("baseSeverity", "Unknown")

                cves.append({
                    "cve_id": vuln["id"],
                    "description": description,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "published": vuln.get("published", "Unknown")
                })

            return {
                "keyword": keyword,
                "total_results": data.get("totalResults", 0),
                "cves": cves
            }

        except Exception as e:
            return {"error": f"CVE search failed: {str(e)}"}

if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=8080)
