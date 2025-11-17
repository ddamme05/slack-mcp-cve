"""
Heuristic URL Classification for CVE References

Extracted from server.py to enable unit testing without API dependencies.
"""
from typing import Dict, List


def classify_reference_tags(
    url: str,
    source: str,
    original_tags: List[str]
) -> tuple[List[str], bool]:
    """
    Classify a CVE reference URL using heuristics
    
    Args:
        url: Reference URL
        source: Reference source (e.g., "cve.mitre.org")
        original_tags: Original NVD tags (if any)
    
    Returns:
        Tuple of (tags, nvd_tagged) where:
        - tags: List of classification tags
        - nvd_tagged: True if NVD provided tags, False if heuristically enhanced
    """
    tags = original_tags.copy() if original_tags else []
    nvd_tagged = bool(original_tags)  # Track if NVD provided initial tags
    
    url_lower = url.lower()
    source_lower = source.lower()
    
    # ALWAYS check for exploit patterns (augment NVD tags, don't replace)
    exploit_indicators = [
        "exploit-db", "exploit", "poc", "metasploit",
        "remote-code-execution", "rce", "injection",
        "code-execution", "payload", "shell"
    ]
    
    # Check for exploit patterns, but exclude URLs that are clearly advisories
    is_advisory_url = any(p in url_lower for p in [
        "security-advisory", "advisory", "bulletin"
    ])
    
    is_exploit = any(p in url_lower for p in exploit_indicators)
    
    if is_exploit and not is_advisory_url:
        if "Exploit" not in tags:
            tags.append("Exploit")
            nvd_tagged = False  # Mark as heuristically enhanced
    
    # ALWAYS check for patch patterns
    patch_patterns = ["/commit/", "/pull/", "/patch", "/diff"]
    if any(p in url_lower for p in patch_patterns):
        if "Patch" not in tags and "Mitigation" not in tags:
            tags.append("Patch")
            nvd_tagged = False
    
    # Apply other heuristics ONLY if tags are still empty
    if not tags:
        # Advisory patterns
        if any(p in url_lower + source_lower for p in [
            "security", "advisory", "bulletin", "msrc", "cert", "cisa", "vuln"
        ]):
            tags = ["Third Party Advisory"]
        # VDB patterns
        elif any(p in url_lower for p in ["vuldb", "cvedetails", "cve.mitre"]):
            tags = ["VDB Entry"]
        # GitHub security advisories
        elif "github.com" in url_lower and "/security/advisories/" in url_lower:
            tags = ["Third Party Advisory"]
        # Issue trackers
        elif any(p in url_lower for p in ["/issues/", "/bug/", "/bugzilla"]):
            tags = ["Issue Tracking"]
        # Mailing lists
        elif any(p in url_lower for p in ["@lists.", "mailing", "pipermail"]):
            tags = ["Mailing List"]
        else:
            tags = ["Untagged Reference"]
    
    return tags, nvd_tagged


def categorize_reference(tags: List[str]) -> List[str]:
    """
    Convert NVD tags to search categories (poc, fix, advisory)
    
    Args:
        tags: List of NVD or heuristic tags
    
    Returns:
        List of categories: ["poc", "fix", "advisory"]
    """
    categories = []
    
    if "Exploit" in tags:
        categories.append("poc")
    
    if "Patch" in tags or "Mitigation" in tags:
        categories.append("fix")
    
    # Advisory includes multiple tag types
    advisory_tags = [
        "Vendor Advisory",
        "Third Party Advisory",
        "Technical Description",
        "Mailing List",
        "Press/Media Coverage",
        "US Government Resource"
    ]
    if any(tag in tags for tag in advisory_tags):
        categories.append("advisory")
    
    return categories


def get_reference_priority_label(tags: List[str]) -> tuple[str, int]:
    """
    Get primary display label and priority for reference
    
    Priority order (lower number = higher priority):
    1. Exploit
    2. Vendor Advisory / Patch / Mitigation
    3. Third Party Advisory / US Gov / Technical Description
    4. VDB Entry / Issue Tracking / Mailing List
    5. Untagged Reference
    
    Args:
        tags: List of classification tags
    
    Returns:
        Tuple of (label, priority)
    """
    # Note: Check Vendor Advisory before Patch to prioritize more specific label
    if "Exploit" in tags:
        return "🚨 Exploit", 1
    elif "Vendor Advisory" in tags:
        return "🔧 Vendor Advisory", 2
    elif "Patch" in tags:
        return "🔧 Patch", 2
    elif "Mitigation" in tags:
        return "🛡️ Mitigation", 2
    elif "Third Party Advisory" in tags:
        return "📰 Third Party Advisory", 3
    elif "US Government Resource" in tags:
        return "📰 US Government Advisory", 3
    elif "Technical Description" in tags:
        return "📰 Technical Analysis", 3
    elif "VDB Entry" in tags:
        return "🔗 VDB Entry", 4
    elif "Issue Tracking" in tags:
        return "🔗 Issue Tracker", 4
    elif "Mailing List" in tags:
        return "🔗 Mailing List", 4
    elif "Untagged Reference" in tags:
        return "🔗 Reference", 5
    else:
        return "🔗 Reference", 4


def normalize_url_for_dedup(url: str) -> str:
    """
    Normalize URL for deduplication matching
    
    Args:
        url: Original URL
    
    Returns:
        Normalized URL (lowercase, stripped, no trailing slash)
    """
    return url.strip().lower().rstrip('/')


def is_broken_link(tags: List[str]) -> bool:
    """
    Check if reference is marked as broken link
    
    Args:
        tags: List of tags
    
    Returns:
        True if broken link tag present
    """
    return "Broken Link" in tags
