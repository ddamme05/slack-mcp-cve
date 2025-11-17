"""
Real integration tests for MCP server heuristic classification

These tests import and test actual production functions from mcp-server/heuristics.py
"""
import sys
import os

# Add parent directory to path to import from mcp-server
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'mcp-server'))

from heuristics import (
    classify_reference_tags,
    categorize_reference,
    get_reference_priority_label,
    normalize_url_for_dedup,
    is_broken_link
)

import pytest


class TestRealExploitDetection:
    """Test real exploit URL classification using production functions"""
    
    def test_exploit_db_urls(self, exploit_urls):
        """Exploit-DB URLs should be classified as exploits"""
        exploit_db_urls = [u for u in exploit_urls if "exploit-db" in u.lower()]
        
        for url in exploit_db_urls:
            tags, nvd_tagged = classify_reference_tags(url, "", [])
            
            assert "Exploit" in tags, f"Exploit-DB URL should be tagged as Exploit: {url}"
            assert not nvd_tagged, "Should be heuristically classified"
    
    def test_packetstorm_exploit_urls(self, exploit_urls):
        """PacketStorm exploit URLs should be classified as exploits"""
        packetstorm_exploits = [
            u for u in exploit_urls 
            if "packetstorm" in u and ("Remote-Code-Execution" in u or "Injection" in u)
        ]
        
        for url in packetstorm_exploits:
            tags, nvd_tagged = classify_reference_tags(url, "packetstormsecurity.com", [])
            
            assert "Exploit" in tags, f"PacketStorm exploit should be tagged: {url}"
            assert not nvd_tagged
    
    def test_packetstorm_advisory_urls_excluded(self, advisory_urls):
        """PacketStorm advisory URLs should NOT be classified as exploits"""
        packetstorm_advisories = [
            u for u in advisory_urls 
            if "packetstorm" in u and ("Advisory" in u or "Security" in u)
        ]
        
        for url in packetstorm_advisories:
            tags, nvd_tagged = classify_reference_tags(url, "packetstormsecurity.com", [])
            
            assert "Exploit" not in tags, f"Advisory should NOT be tagged as Exploit: {url}"
            assert "Third Party Advisory" in tags or "Untagged Reference" in tags
    
    def test_metasploit_urls(self, exploit_urls):
        """Metasploit URLs should be classified as exploits"""
        metasploit_urls = [u for u in exploit_urls if "metasploit" in u.lower()]
        
        for url in metasploit_urls:
            tags, nvd_tagged = classify_reference_tags(url, "github.com", [])
            
            assert "Exploit" in tags
    
    def test_poc_repository_detection(self, exploit_urls):
        """PoC repository URLs should be detected"""
        poc_repos = [u for u in exploit_urls if "poc" in u.lower() or "shell-poc" in u.lower()]
        
        for url in poc_repos:
            tags, nvd_tagged = classify_reference_tags(url, "", [])
            
            assert "Exploit" in tags, f"PoC repo should be classified as exploit: {url}"
    
    def test_augments_nvd_tags(self):
        """Heuristics should augment NVD tags, not replace them"""
        url = "https://www.exploit-db.com/exploits/50337"
        original_tags = ["Third Party Advisory"]  # NVD provided this
        
        tags, nvd_tagged = classify_reference_tags(url, "exploit-db.com", original_tags)
        
        # Should have BOTH original tag AND Exploit tag
        assert "Third Party Advisory" in tags, "Original NVD tag should be preserved"
        assert "Exploit" in tags, "Exploit tag should be added"
        assert not nvd_tagged, "Should be marked as heuristically enhanced"
    
    def test_preserves_nvd_tags_when_no_heuristics_match(self):
        """If NVD provided tags and no heuristics match, preserve original"""
        url = "https://example.com/some-reference"
        original_tags = ["Technical Description"]
        
        tags, nvd_tagged = classify_reference_tags(url, "example.com", original_tags)
        
        assert tags == ["Technical Description"], "Original tags should be preserved"
        assert nvd_tagged, "Should be marked as NVD-tagged (not enhanced)"


class TestRealAdvisoryDetection:
    """Test real advisory URL classification"""
    
    def test_vendor_advisory_urls(self, advisory_urls):
        """Vendor advisory URLs should NOT be tagged as exploits"""
        vendor_advisories = [
            u for u in advisory_urls
            if any(vendor in u for vendor in ["microsoft.com", "oracle.com", "redhat.com"])
        ]
        
        for url in vendor_advisories:
            tags, nvd_tagged = classify_reference_tags(url, "", [])
            
            assert "Exploit" not in tags, f"Vendor advisory should not be exploit: {url}"
            assert any(tag in tags for tag in [
                "Third Party Advisory", "VDB Entry", "Untagged Reference"
            ])
    
    def test_security_bulletin_classification(self, advisory_urls):
        """Security bulletins should be recognized"""
        bulletins = [u for u in advisory_urls if "bulletin" in u.lower()]
        
        for url in bulletins:
            tags, nvd_tagged = classify_reference_tags(url, "", [])
            
            assert "Third Party Advisory" in tags or "Untagged Reference" in tags
            assert "Exploit" not in tags


class TestRealPatchDetection:
    """Test real patch/fix URL classification"""
    
    def test_github_commit_urls(self, patch_urls):
        """GitHub commit URLs should be detected as patches"""
        commits = [u for u in patch_urls if "/commit/" in u]
        
        for url in commits:
            tags, nvd_tagged = classify_reference_tags(url, "github.com", [])
            
            assert "Patch" in tags, f"Commit should be classified as patch: {url}"
            assert not nvd_tagged
    
    def test_github_pull_request_urls(self, patch_urls):
        """GitHub PR URLs should be detected as patches"""
        prs = [u for u in patch_urls if "/pull/" in u]
        
        for url in prs:
            tags, nvd_tagged = classify_reference_tags(url, "github.com", [])
            
            assert "Patch" in tags
    
    def test_patch_file_urls(self, patch_urls):
        """Direct .patch and .diff files should be detected"""
        patch_files = [u for u in patch_urls if ".patch" in u or ".diff" in u]
        
        for url in patch_files:
            tags, nvd_tagged = classify_reference_tags(url, "", [])
            
            assert "Patch" in tags


class TestRealCategorization:
    """Test categorization of tags into search types"""
    
    def test_exploit_categorization(self):
        """Exploit tag should map to 'poc' category"""
        tags = ["Exploit"]
        categories = categorize_reference(tags)
        
        assert "poc" in categories
        assert len(categories) == 1
    
    def test_patch_categorization(self):
        """Patch/Mitigation tags should map to 'fix' category"""
        tags = ["Patch"]
        categories = categorize_reference(tags)
        assert "fix" in categories
        
        tags = ["Mitigation"]
        categories = categorize_reference(tags)
        assert "fix" in categories
    
    def test_advisory_categorization(self):
        """Advisory tags should map to 'advisory' category"""
        advisory_tags = [
            ["Vendor Advisory"],
            ["Third Party Advisory"],
            ["Technical Description"],
            ["Mailing List"],
            ["US Government Resource"]
        ]
        
        for tags in advisory_tags:
            categories = categorize_reference(tags)
            assert "advisory" in categories, f"Tags {tags} should map to advisory"
    
    def test_multi_category_reference(self):
        """Reference can belong to multiple categories"""
        tags = ["Exploit", "Third Party Advisory"]
        categories = categorize_reference(tags)
        
        assert "poc" in categories
        assert "advisory" in categories
        assert len(categories) == 2
    
    def test_exploit_and_patch_combo(self):
        """Reference with both exploit and patch tags"""
        tags = ["Exploit", "Patch"]
        categories = categorize_reference(tags)
        
        assert "poc" in categories
        assert "fix" in categories


class TestRealPriorityLabeling:
    """Test priority and label assignment"""
    
    def test_exploit_priority(self):
        """Exploits should have highest priority (1)"""
        tags = ["Exploit"]
        label, priority = get_reference_priority_label(tags)
        
        assert priority == 1
        assert "Exploit" in label
        assert "🚨" in label
    
    def test_vendor_advisory_priority_over_patch(self):
        """Vendor Advisory should be checked before generic Patch"""
        tags = ["Vendor Advisory"]
        label, priority = get_reference_priority_label(tags)
        
        assert priority == 2
        assert "Vendor Advisory" in label
        assert "🔧" in label
    
    def test_patch_priority(self):
        """Patches should have priority 2"""
        tags = ["Patch"]
        label, priority = get_reference_priority_label(tags)
        
        assert priority == 2
        assert "Patch" in label
    
    def test_third_party_advisory_priority(self):
        """Third party advisories should have priority 3"""
        tags = ["Third Party Advisory"]
        label, priority = get_reference_priority_label(tags)
        
        assert priority == 3
        assert "Advisory" in label
        assert "📰" in label
    
    def test_vdb_entry_priority(self):
        """VDB entries should have priority 4"""
        tags = ["VDB Entry"]
        label, priority = get_reference_priority_label(tags)
        
        assert priority == 4
        assert "VDB" in label
    
    def test_untagged_reference_priority(self):
        """Untagged references should have lowest priority"""
        tags = ["Untagged Reference"]
        label, priority = get_reference_priority_label(tags)
        
        assert priority == 5
        assert "Reference" in label


class TestRealURLNormalization:
    """Test URL normalization for deduplication"""
    
    def test_lowercase_normalization(self):
        """URLs should be normalized to lowercase"""
        url = "HTTPS://EXAMPLE.COM/PATH"
        normalized = normalize_url_for_dedup(url)
        
        assert normalized == "https://example.com/path"
    
    def test_trailing_slash_removal(self):
        """Trailing slashes should be removed"""
        urls = [
            "https://example.com/path/",
            "https://example.com/path"
        ]
        
        normalized = [normalize_url_for_dedup(u) for u in urls]
        
        assert normalized[0] == normalized[1]
        assert not normalized[0].endswith('/')
    
    def test_whitespace_stripping(self):
        """Leading/trailing whitespace should be stripped"""
        url = "  https://example.com/path  "
        normalized = normalize_url_for_dedup(url)
        
        assert normalized == "https://example.com/path"
    
    def test_combined_normalization(self):
        """All normalizations should be applied"""
        url = "  HTTPS://EXAMPLE.COM/Path/  "
        normalized = normalize_url_for_dedup(url)
        
        assert normalized == "https://example.com/path"


class TestRealEdgeCases:
    """Test edge cases with real functions"""
    
    def test_advisory_with_exploit_mention(self):
        """Advisory mentioning 'exploit' should not be tagged as exploit"""
        url = "https://example.com/security-advisory-about-rce-exploit"
        tags, nvd_tagged = classify_reference_tags(url, "", [])
        
        # Has both "rce" and "advisory" - advisory wins
        assert "Exploit" not in tags
        assert "Third Party Advisory" in tags
    
    def test_empty_url(self):
        """Empty URL should not crash"""
        tags, nvd_tagged = classify_reference_tags("", "", [])
        
        assert isinstance(tags, list)
        assert "Untagged Reference" in tags
    
    def test_empty_tags_list(self):
        """Empty original tags should trigger heuristics"""
        url = "https://www.exploit-db.com/exploits/12345"
        tags, nvd_tagged = classify_reference_tags(url, "", [])
        
        assert "Exploit" in tags
        assert not nvd_tagged
    
    def test_broken_link_detection(self):
        """Broken Link tag should be detectable"""
        tags = ["Broken Link", "Third Party Advisory"]
        
        assert is_broken_link(tags)
    
    def test_case_insensitive_matching(self):
        """All pattern matching should be case-insensitive"""
        urls = [
            "https://EXPLOIT-DB.com/exploits/123",
            "https://example.com/REMOTE-CODE-EXECUTION",
            "https://example.com/PoC-Demo"
        ]
        
        for url in urls:
            tags, _ = classify_reference_tags(url, "", [])
            assert "Exploit" in tags, f"Case-insensitive matching failed for: {url}"


class TestRealProductionScenarios:
    """Test real-world scenarios from production"""
    
    def test_log4shell_packetstorm_exploit(self):
        """Real PacketStorm exploit URL from Log4Shell"""
        url = "https://packetstormsecurity.com/files/165270/Apache-Log4j2-Remote-Code-Execution.html"
        tags, nvd_tagged = classify_reference_tags(url, "packetstormsecurity.com", [])
        
        assert "Exploit" in tags, "Log4Shell RCE exploit should be tagged"
    
    def test_log4shell_packetstorm_advisory(self):
        """Real PacketStorm advisory URL from Log4Shell"""
        url = "https://packetstormsecurity.com/files/165260/VMware-Security-Advisory-2021-0028.html"
        tags, nvd_tagged = classify_reference_tags(url, "packetstormsecurity.com", [])
        
        assert "Exploit" not in tags, "VMware advisory should NOT be exploit"
        assert "Third Party Advisory" in tags or "Untagged Reference" in tags
    
    def test_github_poc_repository(self):
        """Real GitHub PoC repository"""
        url = "https://github.com/kozmer/log4j-shell-poc"
        tags, nvd_tagged = classify_reference_tags(url, "github.com", [])
        
        assert "Exploit" in tags
        categories = categorize_reference(tags)
        assert "poc" in categories
    
    def test_microsoft_vendor_advisory(self):
        """Real Microsoft security advisory"""
        url = "https://www.microsoft.com/security-advisory/CVE-2021-44228"
        tags, nvd_tagged = classify_reference_tags(url, "microsoft.com", [])
        
        assert "Exploit" not in tags
        assert "Third Party Advisory" in tags
    
    def test_github_patch_commit(self):
        """Real GitHub patch commit"""
        url = "https://github.com/apache/logging-log4j2/commit/44569090f1cf1e92c711fb96dfd18cd7dccc72ea"
        tags, nvd_tagged = classify_reference_tags(url, "github.com", [])
        
        assert "Patch" in tags
        categories = categorize_reference(tags)
        assert "fix" in categories
    
    def test_nvd_reference(self):
        """NVD CVE detail page"""
        url = "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
        tags, nvd_tagged = classify_reference_tags(url, "nvd.nist.gov", [])
        
        assert "Exploit" not in tags
        # NVD is a VDB (Vulnerability Database)
        categories = categorize_reference(tags)
        # VDB Entry doesn't map to any search category (it's informational)
