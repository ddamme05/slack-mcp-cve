from fastmcp import FastMCP
import httpx
from typing import Dict, Optional
import re

mcp = FastMCP("CVE Research MCP", version="1.0.0")

@mcp.tool()
async def lookup_cve_details(cve_id: str) -> Dict:
    """Look up CVE from NIST NVD"""

    # Validate CVE format
    if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id.upper()):
        return {"error": f"Invalid CVE format: {cve_id}"}

    cve_id = cve_id.upper()

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve_id},
                headers={"User-Agent": "Security-CVE-Bot"},
                timeout=10.0
            )
            response.raise_for_status()
            data = response.json()

            if not data.get("vulnerabilities"):
                return {"error": f"CVE {cve_id} not found"}

            # NVD 2.0 API returns vulnerabilities as a list
            vuln = data["vulnerabilities"][0]["cve"]

            # Extract description
            descriptions = vuln.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d["lang"] == "en"),
                "No description available"
            )

            # Get CVSS score
            cvss_score = "N/A"
            severity = "Unknown"
            metrics = vuln.get("metrics", {})

            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore", "N/A")
                severity = cvss_data.get("baseSeverity", "Unknown")

            # Extract references with type classification
            references = []
            for ref in vuln.get("references", []):
                tags = ref.get("tags", [])

                # Determine reference type with emoji and priority
                if "Exploit" in tags:
                    ref_type = "🚨 Exploit"
                    priority = 1
                elif "Patch" in tags or "Vendor Advisory" in tags:
                    ref_type = "🔧 Patch/Fix"
                    priority = 2
                elif "Mitigation" in tags:
                    ref_type = "🛡️ Mitigation"
                    priority = 3
                elif "Third Party Advisory" in tags:
                    ref_type = "📰 Advisory"
                    priority = 4
                else:
                    ref_type = "🔗 Reference"
                    priority = 5

                references.append({
                    "url": ref.get("url", ""),
                    "source": ref.get("source", "Unknown"),
                    "type": ref_type,
                    "priority": priority
                })

            # Sort by priority (exploits first) and limit to top 5
            references.sort(key=lambda x: x['priority'])
            references = references[:5]

            return {
                "cve_id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "severity": severity,
                "published_date": vuln.get("published", "Unknown"),
                "last_modified": vuln.get("lastModified", "Unknown"),
                "references": references
            }

        except Exception as e:
            return {"error": f"NVD API error: {str(e)}"}

@mcp.tool()
async def search_github_cve_repos(cve_id: str, search_type: str = "all") -> Dict:
    """Search GitHub for repos mentioning CVE"""

    if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id.upper()):
        return {"error": "Invalid CVE format"}

    cve_id = cve_id.upper()

    # Build search query based on type
    if search_type == "poc":
        query = f'"{cve_id}" (poc OR exploit OR "proof of concept")'
    elif search_type == "fix":
        query = f'"{cve_id}" (fix OR patch OR mitigation)'
    elif search_type == "discussion":
        query = f'"{cve_id}" (vulnerability OR security OR advisory)'
    else:
        query = f'"{cve_id}"'

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                "https://api.github.com/search/repositories",
                params={"q": query, "per_page": 5, "sort": "stars"},
                headers={
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "Security-CVE-Bot"
                },
                timeout=10.0
            )
            response.raise_for_status()
            data = response.json()

            repos = []
            for repo in data.get("items", []):
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
                "total_found": data.get("total_count", 0),
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

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params=params,
                headers={"User-Agent": "Security-CVE-Bot"},
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
    # Use HTTP transport for worker communication
    mcp.run(transport="http", host="0.0.0.0", port=8080)
