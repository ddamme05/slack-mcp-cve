"""
Real integration tests for worker Block Kit formatter functions

These tests import and test actual production functions from worker/blocks.py
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'worker'))

from blocks import (
    _filter_references,
    _deduplicate_references,
    _format_reference_link,
    format_cve_blocks,
    format_cve_list_blocks,
    format_error_blocks
)

import pytest


class TestRealReferenceFiltering:
    """Test real _filter_references function from blocks.py"""
    
    def test_filter_by_poc_real(self, sample_nvd_reference):
        """Test real PoC filtering"""
        references = [
            {**sample_nvd_reference, "categories": ["poc"], "tags": ["Exploit"]},
            {**sample_nvd_reference, "categories": ["fix"], "tags": ["Patch"]},
            {**sample_nvd_reference, "categories": ["advisory"], "tags": ["Third Party Advisory"]}
        ]
        
        filtered = _filter_references(references, "poc")
        
        assert len(filtered) == 1
        assert filtered[0]["categories"] == ["poc"]
        assert "Exploit" in filtered[0]["tags"]
    
    def test_filter_by_fix_real(self, sample_nvd_reference):
        """Test real fix filtering"""
        references = [
            {**sample_nvd_reference, "categories": ["poc"], "tags": ["Exploit"]},
            {**sample_nvd_reference, "categories": ["fix"], "tags": ["Patch"]},
            {**sample_nvd_reference, "categories": ["advisory"], "tags": ["Third Party Advisory"]}
        ]
        
        filtered = _filter_references(references, "fix")
        
        assert len(filtered) == 1
        assert "Patch" in filtered[0]["tags"]
    
    def test_filter_by_advisory_excludes_exploits_real(self, sample_nvd_reference):
        """Test real advisory filtering excludes Exploit tags"""
        references = [
            {**sample_nvd_reference, "categories": ["poc"], "tags": ["Exploit"]},
            {**sample_nvd_reference, "categories": ["advisory"], "tags": ["Third Party Advisory"]},
            # Edge case: Has advisory category but also Exploit tag
            {**sample_nvd_reference, "categories": ["advisory", "poc"], 
             "tags": ["Exploit", "Third Party Advisory"]}
        ]
        
        filtered = _filter_references(references, "advisory")
        
        # Should only return the pure advisory (not the one with Exploit tag)
        assert len(filtered) == 1
        assert "Third Party Advisory" in filtered[0]["tags"]
        assert "Exploit" not in filtered[0]["tags"]
    
    def test_filter_all_returns_everything_real(self, sample_nvd_reference):
        """Test that 'all' filter returns all references"""
        references = [
            {**sample_nvd_reference, "categories": ["poc"]},
            {**sample_nvd_reference, "categories": ["fix"]},
            {**sample_nvd_reference, "categories": ["advisory"]}
        ]
        
        filtered = _filter_references(references, "all")
        
        assert len(filtered) == 3
    
    def test_multi_category_reference_real(self, sample_nvd_reference):
        """Test reference with multiple categories"""
        ref = {
            **sample_nvd_reference,
            "categories": ["poc", "advisory"],
            "tags": ["Exploit", "Third Party Advisory"]
        }
        
        # Should appear in poc filter
        assert len(_filter_references([ref], "poc")) == 1
        
        # Should NOT appear in advisory filter (has Exploit tag)
        assert len(_filter_references([ref], "advisory")) == 0


class TestRealReferenceDeduplication:
    """Test real _deduplicate_references function"""
    
    def test_deduplication_across_sections_real(self, sample_nvd_reference):
        """Test real deduplication with same URL in multiple sections"""
        exploit_ref = {
            **sample_nvd_reference,
            "url": "https://example.com/resource",
            "categories": ["poc"]
        }
        advisory_ref = {
            **sample_nvd_reference,
            "url": "https://example.com/resource",
            "categories": ["advisory"]
        }
        
        exploits, patches, advisories = _deduplicate_references(
            [exploit_ref],
            [],
            [advisory_ref]
        )
        
        assert len(exploits) == 1, "URL should appear in exploits"
        assert len(advisories) == 0, "URL should NOT appear in advisories"
    
    def test_deduplication_priority_order_real(self, sample_nvd_reference):
        """Test real priority: exploits > patches > advisories"""
        url = "https://example.com/same-resource"
        
        exploit_ref = {**sample_nvd_reference, "url": url, "categories": ["poc"]}
        patch_ref = {**sample_nvd_reference, "url": url, "categories": ["fix"]}
        advisory_ref = {**sample_nvd_reference, "url": url, "categories": ["advisory"]}
        
        exploits, patches, advisories = _deduplicate_references(
            [exploit_ref],
            [patch_ref],
            [advisory_ref]
        )
        
        assert len(exploits) == 1
        assert len(patches) == 0
        assert len(advisories) == 0
    
    def test_url_normalization_for_dedup_real(self, sample_nvd_reference):
        """Test real URL normalization in deduplication"""
        # URLs with same lowercase + stripped form
        refs = [
            {**sample_nvd_reference, "url": " https://example.com/path ", "categories": ["advisory"]},
            {**sample_nvd_reference, "url": "HTTPS://EXAMPLE.COM/PATH", "categories": ["advisory"]},
            {**sample_nvd_reference, "url": "  https://EXAMPLE.com/path  ", "categories": ["advisory"]}
        ]
        
        # Put them all in advisory section
        _, _, advisories = _deduplicate_references([], [], refs)
        
        # All three should deduplicate to one (lowercase + strip matching)
        assert len(advisories) == 1


class TestRealReferenceLinkFormatting:
    """Test real _format_reference_link function"""
    
    def test_basic_link_formatting_real(self, sample_nvd_reference):
        """Test basic Slack link formatting"""
        ref = {
            **sample_nvd_reference,
            "url": "https://example.com/advisory",
            "nvd_tagged": True
        }
        
        link = _format_reference_link(ref, "advisory")
        
        # Should be Slack link format: <url|display>
        assert link.startswith("• <")
        assert "|" in link
        assert link.endswith(">")
        assert "example.com/advisory" in link
    
    def test_inference_indicator_real(self, sample_nvd_reference):
        """Test inference indicator on heuristically classified refs"""
        ref = {
            **sample_nvd_reference,
            "url": "https://example.com/exploit",
            "nvd_tagged": False  # Heuristically classified
        }
        
        link = _format_reference_link(ref, "exploit")
        
        assert "_(inferred)_" in link
    
    def test_no_inference_indicator_real(self, sample_nvd_reference):
        """Test no inference indicator on NVD-tagged refs"""
        ref = {
            **sample_nvd_reference,
            "url": "https://example.com/advisory",
            "nvd_tagged": True  # NVD provided tags
        }
        
        link = _format_reference_link(ref, "advisory")
        
        assert "_(inferred)_" not in link
    
    def test_url_truncation_real(self, sample_nvd_reference):
        """Test URL truncation for very long URLs"""
        long_url = "https://example.com/" + "a" * 200
        ref = {
            **sample_nvd_reference,
            "url": long_url,
            "nvd_tagged": True
        }
        
        link = _format_reference_link(ref, "advisory")
        
        # Should be truncated with ...
        assert "..." in link
    
    def test_special_character_escaping_real(self, sample_nvd_reference):
        """Test special character escaping in URLs"""
        ref = {
            **sample_nvd_reference,
            "url": "https://example.com/page?foo=bar&baz=qux",
            "nvd_tagged": True
        }
        
        link = _format_reference_link(ref, "advisory")
        
        # Ampersands should be escaped
        assert "&amp;" in link
    
    def test_empty_url_handling_real(self, sample_nvd_reference):
        """Test handling of empty URLs"""
        ref = {
            **sample_nvd_reference,
            "url": "",
            "nvd_tagged": True
        }
        
        link = _format_reference_link(ref, "advisory")
        
        assert "Invalid reference" in link


class TestRealCVEBlockGeneration:
    """Test real format_cve_blocks function"""
    
    def test_header_generation_real(self, sample_cve_data, sample_github_data):
        """Test real header block generation"""
        blocks = format_cve_blocks(sample_cve_data, sample_github_data, None, "all")
        
        # Find header block
        header = next((b for b in blocks if b["type"] == "header"), None)
        
        assert header is not None
        assert "CVE-2021-44228" in header["text"]["text"]
        assert "🔴" in header["text"]["text"]  # Critical emoji
    
    def test_kev_indicator_real(self, sample_cve_data, sample_github_data, sample_kev_data):
        """Test real KEV indicator in context block"""
        blocks = format_cve_blocks(sample_cve_data, sample_github_data, sample_kev_data, "all")
        
        # Find context block with KEV indicator
        context = next((b for b in blocks if b["type"] == "context"), None)
        
        assert context is not None
        assert "ACTIVELY EXPLOITED" in context["elements"][0]["text"]
    
    def test_cwe_field_generation_real(self, sample_cve_data, sample_github_data):
        """Test real CWE field generation"""
        blocks = format_cve_blocks(sample_cve_data, sample_github_data, None, "all")
        
        # Find section with CWE fields
        cwe_section = None
        for block in blocks:
            if block.get("type") == "section" and block.get("fields"):
                for field in block["fields"]:
                    if "Weakness Types" in field.get("text", ""):
                        cwe_section = field
                        break
        
        assert cwe_section is not None
        assert "CWE-20" in cwe_section["text"]
    
    def test_action_buttons_generation_real(self, sample_cve_data, sample_github_data):
        """Test real action button generation"""
        blocks = format_cve_blocks(sample_cve_data, sample_github_data, None, "all")
        
        # Find actions block
        actions = next((b for b in blocks if b["type"] == "actions"), None)
        
        assert actions is not None
        assert len(actions["elements"]) >= 2  # At least NVD and GitHub buttons
        
        # Critical CVE should have Exploit-DB button
        assert any("exploit-db.com" in btn.get("url", "") for btn in actions["elements"])
    
    def test_error_handling_real(self):
        """Test real error block generation"""
        nvd_data = {"error": "CVE not found", "cve_id": "CVE-9999-9999"}
        github_data = {}
        
        blocks = format_cve_blocks(nvd_data, github_data, None, "all")
        
        # Should return error blocks
        assert len(blocks) > 0
        header = next((b for b in blocks if b["type"] == "header"), None)
        assert header is not None
        assert "Error" in header["text"]["text"]


class TestRealCVEListBlockGeneration:
    """Test real format_cve_list_blocks function"""
    
    def test_list_header_generation_real(self):
        """Test real list header generation"""
        cve_data = {
            "keyword": "log4j",
            "total_results": 10,
            "cves": [
                {
                    "cve_id": "CVE-2021-44228",
                    "description": "Apache Log4j2 vulnerability",
                    "cvss_score": 10.0,
                    "severity": "CRITICAL",
                    "published": "2021-12-10"
                }
            ]
        }
        
        blocks = format_cve_list_blocks(cve_data)
        
        # Find header
        header = next((b for b in blocks if b["type"] == "header"), None)
        assert header is not None
        assert "log4j" in header["text"]["text"]
    
    def test_list_empty_results_real(self):
        """Test real handling of empty search results"""
        cve_data = {
            "keyword": "nonexistent",
            "total_results": 0,
            "cves": []
        }
        
        blocks = format_cve_list_blocks(cve_data)
        
        # Should have a message about no results
        assert len(blocks) > 0
        # Find section with "No CVEs found"
        has_no_results = any(
            "No CVEs found" in block.get("text", {}).get("text", "")
            for block in blocks
            if block.get("type") == "section"
        )
        assert has_no_results


class TestRealErrorBlockGeneration:
    """Test real format_error_blocks function"""
    
    def test_generic_error_real(self):
        """Test generic error block generation"""
        blocks = format_error_blocks("API timeout error")
        
        assert len(blocks) > 0
        header = next((b for b in blocks if b["type"] == "header"), None)
        assert header is not None
        assert "Error" in header["text"]["text"]
    
    def test_cve_not_found_error_real(self):
        """Test CVE not found error with helpful message"""
        blocks = format_error_blocks("CVE not found", "CVE-2021-44228")
        
        # Should have helpful suggestions
        has_suggestions = any(
            "Possible reasons" in block.get("text", {}).get("text", "")
            for block in blocks
            if block.get("type") == "section"
        )
        assert has_suggestions


class TestRealProductionScenarios:
    """Test real production scenarios with actual data structures"""
    
    def test_log4shell_full_block_generation(self, sample_cve_data, sample_github_data, sample_kev_data):
        """Test full block generation for Log4Shell CVE"""
        # Add real references
        sample_cve_data["references"] = [
            {
                "url": "https://www.exploit-db.com/exploits/50337",
                "source": "exploit-db.com",
                "tags": ["Exploit"],
                "categories": ["poc"],
                "type": "🚨 Exploit",
                "priority": 1,
                "nvd_tagged": False
            },
            {
                "url": "https://github.com/apache/logging-log4j2/commit/44569090",
                "source": "github.com",
                "tags": ["Patch"],
                "categories": ["fix"],
                "type": "🔧 Patch",
                "priority": 2,
                "nvd_tagged": True
            },
            {
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                "source": "nvd.nist.gov",
                "tags": ["Third Party Advisory"],
                "categories": ["advisory"],
                "type": "📰 Third Party Advisory",
                "priority": 3,
                "nvd_tagged": True
            }
        ]
        
        blocks = format_cve_blocks(sample_cve_data, sample_github_data, sample_kev_data, "all")
        
        # Should have header
        assert any(b["type"] == "header" for b in blocks)
        
        # Should have KEV warning
        has_kev = any(
            "ACTIVELY EXPLOITED" in str(b)
            for b in blocks
        )
        assert has_kev
        
        # Should have action buttons
        assert any(b["type"] == "actions" for b in blocks)
        
        # Should have sections for exploits, patches, and advisories
        section_texts = [
            block.get("text", {}).get("text", "")
            for block in blocks
            if block.get("type") == "section"
        ]
        
        has_exploit_section = any("Exploits & PoCs" in text for text in section_texts)
        has_patch_section = any("Patches & Fixes" in text for text in section_texts)
        has_advisory_section = any("Security Advisories" in text for text in section_texts)
        
        assert has_exploit_section
        assert has_patch_section
        assert has_advisory_section
    
    def test_filtered_by_poc_only(self, sample_cve_data, sample_github_data):
        """Test filtering to show only PoCs"""
        sample_cve_data["references"] = [
            {
                "url": "https://www.exploit-db.com/exploits/50337",
                "tags": ["Exploit"],
                "categories": ["poc"],
                "nvd_tagged": False
            },
            {
                "url": "https://github.com/apache/logging-log4j2/commit/44569090",
                "tags": ["Patch"],
                "categories": ["fix"],
                "nvd_tagged": True
            }
        ]
        
        blocks = format_cve_blocks(sample_cve_data, sample_github_data, None, "poc")
        
        section_texts = [
            block.get("text", {}).get("text", "")
            for block in blocks
            if block.get("type") == "section"
        ]
        
        # Should have exploits section
        has_exploit_section = any("Exploits & PoCs" in text for text in section_texts)
        assert has_exploit_section
        
        # Should NOT have patches section (filtered out)
        has_patch_section = any("Patches & Fixes" in text for text in section_texts)
        assert not has_patch_section
    
    def test_github_repos_shown_when_filtering_by_type(self, sample_cve_data):
        """
        Test that GitHub repos are shown even when filtering by search_type.
        
        REGRESSION TEST: Previously showed "No poc repositories found on GitHub"
        even when GitHub API returned repos, because the condition was wrong.
        Bug reported: User filtered by --type poc and saw "No poc repositories found"
        but clicking the button showed GitHub repos existed.
        """
        # NVD data with no references (to isolate GitHub behavior)
        cve_data = {
            "cve_id": "CVE-2021-44228",
            "description": "Log4Shell vulnerability",
            "cvss_score": 10.0,
            "severity": "CRITICAL",
            "published_date": "2021-12-10",
            "last_modified": "2023-01-01",
            "references": [],
            "is_kev": True,
            "cwe": ["CWE-502"]
        }
        
        # GitHub data with PoC repos found
        github_data = {
            "cve_id": "CVE-2021-44228",
            "search_type": "poc",
            "total_found": 42,  # Many repos found!
            "repositories": [
                {
                    "name": "christophetd/log4shell-vulnerable-app",
                    "description": "Vulnerable app for testing",
                    "stars": 1500,
                    "url": "https://github.com/christophetd/log4shell-vulnerable-app",
                    "updated": "2021-12-15"
                },
                {
                    "name": "kozmer/log4j-shell-poc",
                    "description": "PoC for CVE-2021-44228",
                    "stars": 1200,
                    "url": "https://github.com/kozmer/log4j-shell-poc",
                    "updated": "2021-12-14"
                }
            ]
        }
        
        # Format with search_type="poc" (the bug scenario)
        blocks = format_cve_blocks(cve_data, github_data, None, "poc")
        
        # Find all section texts
        section_texts = [
            block.get("text", {}).get("text", "")
            for block in blocks
            if block.get("type") == "section"
        ]
        
        full_text = "\n".join(section_texts)
        
        # CRITICAL: GitHub section should be present
        has_github_section = any("GitHub Resources" in text for text in section_texts)
        assert has_github_section, "GitHub section missing even though repos were found"
        
        # Should show the count
        assert "42 found" in full_text, "Should show total_found count from GitHub API"
        
        # Should show repo names
        assert "christophetd/log4shell-vulnerable-app" in full_text
        assert "kozmer/log4j-shell-poc" in full_text
        
        # Should NOT show "No poc repositories found" message
        assert "No poc repositories found on GitHub" not in full_text, \
            "BUG: Shows 'No repos found' even when GitHub API returned repos"
    
    def test_github_error_shows_error_message_not_no_results(self, sample_cve_data):
        """
        Test that we show ERROR message (not "no results") when GitHub search fails.
        
        IMPROVEMENT: Previously would show "No poc repositories found" even when
        the search failed due to rate limits or other errors. Now shows actual error.
        """
        cve_data = {
            "cve_id": "CVE-2021-44228",
            "description": "Test",
            "cvss_score": 10.0,
            "severity": "CRITICAL",
            "published_date": "2021-12-10",
            "last_modified": "2023-01-01",
            "references": [],
            "is_kev": False,
            "cwe": []
        }
        
        # GitHub returns error
        github_data = {
            "error": "GitHub API rate limit exceeded"
        }
        
        # Format with search_type="poc"
        blocks = format_cve_blocks(cve_data, github_data, None, "poc")
        
        section_texts = [
            block.get("text", {}).get("text", "")
            for block in blocks
            if block.get("type") == "section"
        ]
        
        full_text = "\n".join(section_texts)
        
        # Should show ERROR message (not "no results")
        assert "GitHub search error" in full_text
        assert "rate limit exceeded" in full_text
        
        # Should NOT show "No repos found" when there's an error
        assert "No poc repositories found on GitHub" not in full_text
    
    def test_github_empty_results_shows_no_repos_message(self, sample_cve_data):
        """
        Test message shown when GitHub API returns successfully but finds 0 results.
        """
        cve_data = {
            "cve_id": "CVE-9999-99999",
            "description": "Test",
            "cvss_score": 5.0,
            "severity": "MEDIUM",
            "published_date": "2023-01-01",
            "last_modified": "2023-01-02",
            "references": [],
            "is_kev": False,
            "cwe": []
        }
        
        # GitHub returns successfully but with 0 results
        github_data = {
            "cve_id": "CVE-9999-99999",
            "search_type": "poc",
            "total_found": 0,
            "repositories": []
        }
        
        # Format with search_type="poc"
        blocks = format_cve_blocks(cve_data, github_data, None, "poc")
        
        section_texts = [
            block.get("text", {}).get("text", "")
            for block in blocks
            if block.get("type") == "section"
        ]
        
        full_text = "\n".join(section_texts)
        
        # Should show "No repos found" when legitimately no results
        assert "No poc repositories found on GitHub" in full_text


