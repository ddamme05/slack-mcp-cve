"""
Slack Block Kit Formatters for CVE Bot

Provides rich, interactive Slack message formatting using Block Kit.
Replaces plain text formatting with structured blocks, interactive buttons,
and better visual hierarchy.

Documentation: https://api.slack.com/block-kit
"""

from typing import Dict, List, Optional


def format_cve_blocks(
    nvd_data: Dict,
    github_data: Dict,
    kev_data: Optional[Dict] = None,
    search_type: str = "all"
) -> List[Dict]:
    """
    Format CVE details as Slack Block Kit blocks

    Args:
        nvd_data: NVD CVE data from lookup_cve_details
        github_data: GitHub repo data from search_github_cve_repos
        kev_data: Optional CISA KEV metadata from check_cisa_kev_details
        search_type: Filter type (all, poc, fix, advisory)

    Returns:
        List of Slack Block Kit blocks
    """

    # Handle errors
    if "error" in nvd_data:
        return format_error_blocks(
            nvd_data.get("error", "Unknown error"),
            nvd_data.get("cve_id", "UNKNOWN")
        )

    # Extract data
    cve_id = nvd_data.get("cve_id", "UNKNOWN")
    severity = nvd_data.get("severity", "Unknown").upper()
    cvss_score = nvd_data.get("cvss_score", "N/A")
    description = nvd_data.get("description", "No description available")
    is_kev = nvd_data.get("is_kev", False)
    cwe_list = nvd_data.get("cwe", [])
    published_date = nvd_data.get("published_date", "Unknown")[:10]
    last_modified = nvd_data.get("last_modified", "Unknown")[:10]
    references = nvd_data.get("references", [])

    # Severity emoji mapping
    severity_emoji = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
        "UNKNOWN": "⚪"
    }
    emoji = severity_emoji.get(severity, "⚪")

    blocks = []

    blocks.append({
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": f"{emoji} {cve_id}",
            "emoji": True
        }
    })

    severity_text = f"*{severity}* (CVSS {cvss_score})"
    if is_kev:
        severity_text += " • 🚨 *ACTIVELY EXPLOITED (CISA KEV)*"

    blocks.append({
        "type": "context",
        "elements": [{
            "type": "mrkdwn",
            "text": severity_text
        }]
    })

    blocks.append({"type": "divider"})

    desc_text = description[:2800] + ("..." if len(description) > 2800 else "")

    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"*Description*\n{desc_text}"
        }
    })

    detail_fields = []

    if cwe_list:
        cwe_str = ", ".join(cwe_list)
        detail_fields.append({
            "type": "mrkdwn",
            "text": f"*Weakness Types*\n{cwe_str}"
        })

    detail_fields.append({
        "type": "mrkdwn",
        "text": f"*Published*\n{published_date}"
    })

    if len(detail_fields) > 0:
        blocks.append({
            "type": "section",
            "fields": detail_fields
        })

    if is_kev and kev_data and kev_data.get("is_kev"):
        blocks.append({"type": "divider"})

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*🚨 CISA Known Exploited Vulnerability*"
            }
        })

        kev_fields = [
            {
                "type": "mrkdwn",
                "text": f"*Added to KEV*\n{kev_data.get('date_added', 'Unknown')}"
            },
            {
                "type": "mrkdwn",
                "text": f"*Remediation Due*\n{kev_data.get('due_date', 'Unknown')}"
            },
            {
                "type": "mrkdwn",
                "text": f"*Ransomware Use*\n{kev_data.get('known_ransomware_use', 'Unknown')}"
            }
        ]

        required_action = kev_data.get("required_action", "")
        if required_action:
            action_text = required_action[:100] + ("..." if len(required_action) > 100 else "")
            kev_fields.append({
                "type": "mrkdwn",
                "text": f"*Required Action*\n{action_text}"
            })

        blocks.append({
            "type": "section",
            "fields": kev_fields
        })

    blocks.append({"type": "divider"})

    filtered_refs = _filter_references(references, search_type)

    if filtered_refs:
        exploits_raw = [r for r in filtered_refs if "poc" in r.get("categories", [])]
        patches_raw = [r for r in filtered_refs if "fix" in r.get("categories", [])]
        advisories_raw = [r for r in filtered_refs if "advisory" in r.get("categories", [])]

        if search_type == "all":
            exploits, patches, advisories = _deduplicate_references(
                exploits_raw, patches_raw, advisories_raw
            )
        else:
            exploits = exploits_raw
            patches = patches_raw
            advisories = advisories_raw

        if exploits and (search_type == "all" or search_type == "poc"):
            total_exploits = len(exploits)
            display_count = min(5, total_exploits)

            exploit_text = "*🚨 Exploits & PoCs*"
            if total_exploits > display_count:
                exploit_text += f" (showing {display_count} of {total_exploits})"
            exploit_text += "\n"

            for ref in exploits[:display_count]:
                exploit_text += _format_reference_link(ref, "exploit") + "\n"

            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": exploit_text
                }
            })

        if patches and (search_type == "all" or search_type == "fix"):
            total_patches = len(patches)
            display_count = min(5, total_patches)

            patch_text = "*🔧 Patches & Fixes*"
            if total_patches > display_count:
                patch_text += f" (showing {display_count} of {total_patches})"
            patch_text += "\n"

            for ref in patches[:display_count]:
                patch_text += _format_reference_link(ref, "patch") + "\n"

            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": patch_text
                }
            })

        if advisories and (search_type == "all" or search_type == "advisory"):
            total_advisories = len(advisories)
            display_count = min(5, total_advisories)

            advisory_text = "*📰 Security Advisories*"
            if total_advisories > display_count:
                advisory_text += f" (showing {display_count} of {total_advisories})"
            advisory_text += "\n"

            for ref in advisories[:display_count]:
                advisory_text += _format_reference_link(ref, "advisory") + "\n"

            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": advisory_text
                }
            })
    elif search_type != "all":
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"ℹ️ No {search_type} resources found in NVD references"
            }
        })

    github_repos = github_data.get("repositories", []) if github_data and not github_data.get("error") else []

    if github_repos:
        blocks.append({"type": "divider"})

        total_found = github_data.get("total_found", 0)
        repo_text = f"*💻 GitHub Resources* ({total_found} found)\n"

        for repo in github_repos[:5]:
            name = repo.get("name", "Unknown")
            stars = repo.get("stars", 0)
            url = repo.get("url", "#")

            if "trailofbits" in name.lower():
                name = f"*{name}* ⭐ Trail of Bits!"

            repo_text += f"• <{url}|{name}> ({stars} ⭐)\n"

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": repo_text
            }
        })
    elif github_data and github_data.get("error"):
        error_msg = github_data.get("error", "Unknown error")
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"⚠️ GitHub search error: {error_msg}"
            }
        })
    elif search_type != "all":
        total = github_data.get("total_found", 0) if github_data else 0
        if total == 0:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"ℹ️ No {search_type} repositories found on GitHub"
                }
            })

    blocks.append({"type": "divider"})

    try:
        cvss = float(cvss_score) if cvss_score != "N/A" else 0
    except (ValueError, TypeError):
        cvss = 0

    if cvss >= 9.0:
        risk_text = "🚨 *Critical severity.* Immediate patching required."
    elif cvss >= 7.0:
        risk_text = "⚠️ *High severity.* Prioritize patching."
    elif cvss >= 4.0:
        risk_text = "⚡ *Medium severity.* Schedule patching."
    else:
        risk_text = "✅ *Low severity.* Update when convenient."

    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"*Risk Assessment*\n{risk_text}"
        }
    })

    blocks.append({"type": "divider"})

    action_buttons = [
        {
            "type": "button",
            "text": {
                "type": "plain_text",
                "text": "View on NVD",
                "emoji": True
            },
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        },
        {
            "type": "button",
            "text": {
                "type": "plain_text",
                "text": "Search GitHub",
                "emoji": True
            },
            "url": f"https://github.com/search?q={cve_id}+poc"
        }
    ]

    if cvss >= 7.0:
        action_buttons.append({
            "type": "button",
            "text": {
                "type": "plain_text",
                "text": "Check Exploits",
                "emoji": True
            },
            "style": "danger",
            "url": f"https://www.exploit-db.com/search?cve={cve_id}"
        })

    blocks.append({
        "type": "actions",
        "elements": action_buttons
    })

    blocks.append({
        "type": "context",
        "elements": [{
            "type": "mrkdwn",
            "text": f"Last modified: {last_modified} | Data from NVD API 2.0"
        }]
    })

    return blocks


def format_cve_list_blocks(cve_data: Dict) -> List[Dict]:
    """
    Format keyword search results as Slack Block Kit blocks

    Args:
        cve_data: CVE list data from search_cve_by_keyword

    Returns:
        List of Slack Block Kit blocks
    """

    if "error" in cve_data:
        return format_error_blocks(cve_data["error"])

    keyword = cve_data.get("keyword", "unknown")
    total = cve_data.get("total_results", 0)
    cves = cve_data.get("cves", [])

    blocks = []

    # ===== HEADER =====
    blocks.append({
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": f"🔍 Search Results: {keyword}",
            "emoji": True
        }
    })

    # ===== CONTEXT: Result count =====
    if total == 0:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"No CVEs found for keyword: `{keyword}`"
            }
        })
        return blocks

    blocks.append({
        "type": "context",
        "elements": [{
            "type": "mrkdwn",
            "text": f"Found {total} CVEs (showing top {min(10, len(cves))})"
        }]
    })

    blocks.append({"type": "divider"})

    # ===== CVE RESULTS =====
    severity_emoji = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
        "UNKNOWN": "⚪"
    }

    for cve in cves[:10]:
        cve_id = cve.get("cve_id", "N/A")
        severity = cve.get("severity", "UNKNOWN").upper()
        cvss = cve.get("cvss_score", "N/A")
        desc = cve.get("description", "")[:150]
        emoji = severity_emoji.get(severity, "⚪")

        # Create clickable CVE ID link
        nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"{emoji} *<{nvd_url}|{cve_id}>* (CVSS {cvss})\n{desc}..."
            },
            "accessory": {
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": "Details",
                    "emoji": True
                },
                "value": cve_id,
                "action_id": f"view_details_{cve_id}"
            }
        })

    # ===== FOOTER: How to get details =====
    blocks.append({"type": "divider"})

    if cves:
        first_cve = cves[0]["cve_id"]
        blocks.append({
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": f"💡 Use `/cve-search {first_cve}` for detailed analysis"
            }]
        })

    return blocks


def format_error_blocks(error_message: str, cve_id: Optional[str] = None) -> List[Dict]:
    """
    Format error message as Slack Block Kit blocks

    Args:
        error_message: Error message to display
        cve_id: Optional CVE ID for context

    Returns:
        List of Slack Block Kit blocks
    """

    blocks = []

    # ===== HEADER =====
    blocks.append({
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": "❌ Error",
            "emoji": True
        }
    })

    # ===== ERROR MESSAGE =====
    # Special handling for "not found" errors
    if cve_id and "not found" in error_message.lower():
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*CVE Not Found:* {cve_id}\n\n"
                        "This CVE ID doesn't exist in the NVD database yet."
            }
        })

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Possible reasons:*\n"
                        "• CVE reserved but details not published yet\n"
                        "• Typo in CVE ID (check year and number)\n"
                        "• Very recent CVE (NVD updates every ~2 hours)"
            }
        })

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*What to try:*\n"
                        "• Check CVE format: `CVE-YYYY-NNNNN` (e.g., CVE-2021-44228)\n"
                        "• Search by keyword: `/cve-search apache log4j`\n"
                        f"• Visit NVD directly: <https://nvd.nist.gov/vuln/detail/{cve_id}|View on NVD>"
            }
        })
    else:
        # Generic error
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Error:* {error_message}"
            }
        })

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "Try using `/cve-help` for usage information."
            }
        })

    return blocks


def _get_reference_label(ref: Dict, section: str) -> str:
    """
    Get context-aware display label for reference

    Args:
        ref: Reference dict with url, type, tags, categories
        section: "exploit", "patch", or "advisory"

    Returns:
        Human-readable label (e.g., "PoC", "Vendor Patch", "Advisory")
    """
    url = ref.get("url", "")
    tags = ref.get("tags", [])

    # Extract domain for context
    domain = ""
    try:
        if "://" in url:
            domain = url.split("://")[1].split("/")[0].lower()
    except:
        pass

    # Section-specific labeling
    if section == "exploit":
        # Prioritize specific exploit types
        if "Exploit" in tags:
            return "Exploit"
        elif any(tag in tags for tag in ["Technical Description", "Technical Write-up"]):
            return "Technical Write-up"
        elif "github.com" in domain or "gitlab.com" in domain:
            return "PoC Repository"
        else:
            return "PoC"

    elif section == "patch":
        # Prioritize specific patch types
        if "Patch" in tags:
            return "Patch"
        elif "Vendor Advisory" in tags:
            return "Vendor Fix"
        elif "Mitigation" in tags:
            return "Mitigation"
        elif "github.com" in domain and "/pull/" in url:
            return "Pull Request"
        elif "github.com" in domain and "/commit/" in url:
            return "Commit"
        else:
            return "Fix"

    elif section == "advisory":
        # Prioritize specific advisory types
        if "Vendor Advisory" in tags:
            # Check for specific vendor domains
            vendor_domains = ["microsoft.com", "oracle.com", "redhat.com", "ubuntu.com",
                            "debian.org", "apache.org", "cisco.com"]
            if any(vendor in domain for vendor in vendor_domains):
                return "Vendor Advisory"
            else:
                return "Advisory"
        elif "Third Party Advisory" in tags:
            return "Third Party Advisory"
        elif "Mailing List" in tags:
            return "Mailing List"
        elif "nvd.nist.gov" in domain:
            return "NVD"
        elif "github.com" in domain and "/advisory/" in url:
            return "GitHub Advisory"
        elif "cve.mitre.org" in domain:
            return "MITRE CVE"
        else:
            return "Advisory"

    # Fallback
    return ref.get("type", "Reference")


def _format_reference_link(ref: Dict, section: str) -> str:
    """
    Format reference as Slack link showing domain/URL

    Args:
        ref: Reference dict
        section: "exploit", "patch", or "advisory"

    Returns:
        Formatted Slack markdown link with URL as display text
    """
    # Validate URL
    url = ref.get("url", "").strip()
    if not url:
        return "• _(Invalid reference - no URL)_"

    # Sanitize URL for Slack (escape special characters that break Slack links)
    # Slack links format: <url|text> - need to escape | > & characters
    sanitized_url = url.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # Extract domain + path for display (show actual URL)
    display_url = url
    try:
        if "://" in url:
            # Remove protocol, show domain + path
            domain_path = url.split("://")[1]
            # Truncate if too long
            if len(domain_path) > 70:
                display_url = domain_path[:67] + "..."
            else:
                display_url = domain_path
    except:
        # Fallback: truncate full URL
        if len(url) > 70:
            display_url = url[:67] + "..."

    # Sanitize display text for Slack (escape characters that break markdown)
    sanitized_display = display_url.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("|", "\\|")

    # Add inference indicator if not NVD-tagged
    inference = ""
    if not ref.get("nvd_tagged", True):
        inference = " _(inferred)_"

    # Format as Slack link: <url|domain/path>
    return f"• <{sanitized_url}|{sanitized_display}>{inference}"


def _deduplicate_references(
    exploits: List[Dict],
    patches: List[Dict],
    advisories: List[Dict]
) -> tuple:
    """
    Remove duplicate references across sections
    Priority: exploits > patches > advisories

    Args:
        exploits: List of exploit references
        patches: List of patch references
        advisories: List of advisory references

    Returns:
        Tuple of (deduplicated_exploits, deduplicated_patches, deduplicated_advisories)
    """
    seen_urls = set()

    # Process exploits first (highest priority)
    deduped_exploits = []
    for ref in exploits:
        url = ref.get("url", "").strip().lower()
        if url and url not in seen_urls:
            seen_urls.add(url)
            deduped_exploits.append(ref)

    # Process patches second
    deduped_patches = []
    for ref in patches:
        url = ref.get("url", "").strip().lower()
        if url and url not in seen_urls:
            seen_urls.add(url)
            deduped_patches.append(ref)

    # Process advisories last
    deduped_advisories = []
    for ref in advisories:
        url = ref.get("url", "").strip().lower()
        if url and url not in seen_urls:
            seen_urls.add(url)
            deduped_advisories.append(ref)

    return (deduped_exploits, deduped_patches, deduped_advisories)


def _filter_references(references: List[Dict], search_type: str) -> List[Dict]:
    """
    Filter references based on search type

    Args:
        references: List of reference dicts from NVD
        search_type: Filter type (all, poc, fix, advisory)

    Returns:
        Filtered list of references
    """
    if search_type == "all":
        return references
    elif search_type == "poc":
        return [r for r in references if "poc" in r.get("categories", [])]
    elif search_type == "fix":
        return [r for r in references if "fix" in r.get("categories", [])]
    elif search_type == "advisory":
        # Exclude references that are primarily exploits (even if they have advisory category)
        # This prevents exploit code from showing in advisory filter
        return [r for r in references
                if "advisory" in r.get("categories", [])
                and "Exploit" not in r.get("tags", [])]

    return references
