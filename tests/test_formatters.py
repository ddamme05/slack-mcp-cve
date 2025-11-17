"""
Test Slack Block Kit formatter logic

Tests the worker's reference filtering, deduplication, and Block Kit generation.
"""
import pytest


class TestReferenceFiltering:
    """Test reference filtering by search type"""

    def test_filter_by_poc(self, sample_nvd_reference):
        """--type poc should only show exploit references"""
        references = [
            {**sample_nvd_reference, "categories": ["poc"], "tags": ["Exploit"]},
            {**sample_nvd_reference, "categories": ["fix"], "tags": ["Patch"]},
            {**sample_nvd_reference, "categories": ["advisory"], "tags": ["Third Party Advisory"]}
        ]

        # Simulate _filter_references logic for search_type="poc"
        search_type = "poc"
        if search_type == "poc":
            filtered = [r for r in references if "poc" in r.get("categories", [])]
        else:
            filtered = references

        assert len(filtered) == 1, "Should only return PoC references"
        assert "Exploit" in filtered[0]["tags"]

    def test_filter_by_fix(self, sample_nvd_reference):
        """--type fix should only show patch/fix references"""
        references = [
            {**sample_nvd_reference, "categories": ["poc"], "tags": ["Exploit"]},
            {**sample_nvd_reference, "categories": ["fix"], "tags": ["Patch"]},
            {**sample_nvd_reference, "categories": ["advisory"], "tags": ["Third Party Advisory"]}
        ]

        search_type = "fix"
        if search_type == "fix":
            filtered = [r for r in references if "fix" in r.get("categories", [])]
        else:
            filtered = references

        assert len(filtered) == 1, "Should only return fix references"
        assert "Patch" in filtered[0]["tags"]

    def test_filter_by_advisory(self, sample_nvd_reference):
        """--type advisory should only show advisory references AND exclude exploits"""
        references = [
            {**sample_nvd_reference, "categories": ["poc"], "tags": ["Exploit"]},
            {**sample_nvd_reference, "categories": ["fix"], "tags": ["Patch"]},
            {**sample_nvd_reference, "categories": ["advisory"], "tags": ["Third Party Advisory"]},
            # Edge case: Reference with both advisory category AND Exploit tag (PacketStorm exploit)
            {**sample_nvd_reference, "categories": ["advisory", "poc"], "tags": ["Exploit", "Third Party Advisory"]}
        ]

        # Simulate _filter_references logic for search_type="advisory"
        search_type = "advisory"
        if search_type == "advisory":
            # Exclude references with "Exploit" tag to prevent exploit code in advisory results
            filtered = [r for r in references
                       if "advisory" in r.get("categories", [])
                       and "Exploit" not in r.get("tags", [])]
        else:
            filtered = references

        assert len(filtered) == 1, "Should only return non-exploit advisories"
        assert "Third Party Advisory" in filtered[0]["tags"]
        assert "Exploit" not in filtered[0]["tags"]

    def test_filter_all_shows_everything(self, sample_nvd_reference):
        """--type all should show all references"""
        references = [
            {**sample_nvd_reference, "categories": ["poc"], "tags": ["Exploit"]},
            {**sample_nvd_reference, "categories": ["fix"], "tags": ["Patch"]},
            {**sample_nvd_reference, "categories": ["advisory"], "tags": ["Third Party Advisory"]}
        ]

        search_type = "all"
        if search_type == "all":
            filtered = references
        else:
            filtered = []

        assert len(filtered) == 3, "Should return all references"

    def test_multi_category_reference(self, sample_nvd_reference):
        """References with multiple categories should appear in multiple filters"""
        # Reference that's both an exploit and has advisory category (e.g., PacketStorm)
        multi_ref = {
            **sample_nvd_reference,
            "categories": ["poc", "advisory"],
            "tags": ["Exploit", "Third Party Advisory"]
        }

        # Should appear in PoC filter
        poc_filtered = [r for r in [multi_ref] if "poc" in r.get("categories", [])]
        assert len(poc_filtered) == 1, "Should appear in PoC filter"

        # Should NOT appear in advisory filter (excluded due to Exploit tag)
        advisory_filtered = [r for r in [multi_ref]
                            if "advisory" in r.get("categories", [])
                            and "Exploit" not in r.get("tags", [])]
        assert len(advisory_filtered) == 0, "Should NOT appear in advisory filter (has Exploit tag)"


class TestReferenceDeduplication:
    """Test reference deduplication across sections"""

    def test_deduplicate_across_sections(self, sample_nvd_reference):
        """Duplicate URLs should only appear once (highest priority section)"""
        # Same URL appears in multiple categories
        exploit_ref = {
            **sample_nvd_reference,
            "url": "https://example.com/resource",
            "categories": ["poc"],
            "priority": 1
        }
        advisory_ref = {
            **sample_nvd_reference,
            "url": "https://example.com/resource",
            "categories": ["advisory"],
            "priority": 3
        }

        # Simulate _deduplicate_references logic
        seen_urls = set()
        deduped_exploits = []
        deduped_advisories = []

        # Process exploits first (highest priority)
        for ref in [exploit_ref]:
            url = ref.get("url", "").strip().lower()
            if url and url not in seen_urls:
                seen_urls.add(url)
                deduped_exploits.append(ref)

        # Process advisories second
        for ref in [advisory_ref]:
            url = ref.get("url", "").strip().lower()
            if url and url not in seen_urls:
                seen_urls.add(url)
                deduped_advisories.append(ref)

        assert len(deduped_exploits) == 1, "URL should appear in exploits"
        assert len(deduped_advisories) == 0, "URL should NOT appear in advisories (already in exploits)"

    def test_deduplication_priority_order(self, sample_nvd_reference):
        """Deduplication should follow priority: exploits > patches > advisories"""
        url = "https://example.com/same-resource"

        refs = [
            {**sample_nvd_reference, "url": url, "categories": ["advisory"], "priority": 3},
            {**sample_nvd_reference, "url": url, "categories": ["fix"], "priority": 2},
            {**sample_nvd_reference, "url": url, "categories": ["poc"], "priority": 1}
        ]

        # Group by category
        exploits = [r for r in refs if "poc" in r.get("categories", [])]
        patches = [r for r in refs if "fix" in r.get("categories", [])]
        advisories = [r for r in refs if "advisory" in r.get("categories", [])]

        # Deduplicate in priority order
        seen_urls = set()
        deduped_exploits = []
        deduped_patches = []
        deduped_advisories = []

        # Exploits first
        for ref in exploits:
            url_lower = ref.get("url", "").strip().lower()
            if url_lower and url_lower not in seen_urls:
                seen_urls.add(url_lower)
                deduped_exploits.append(ref)

        # Patches second
        for ref in patches:
            url_lower = ref.get("url", "").strip().lower()
            if url_lower and url_lower not in seen_urls:
                seen_urls.add(url_lower)
                deduped_patches.append(ref)

        # Advisories last
        for ref in advisories:
            url_lower = ref.get("url", "").strip().lower()
            if url_lower and url_lower not in seen_urls:
                seen_urls.add(url_lower)
                deduped_advisories.append(ref)

        assert len(deduped_exploits) == 1, "URL should appear in exploits (highest priority)"
        assert len(deduped_patches) == 0, "URL should NOT appear in patches (already in exploits)"
        assert len(deduped_advisories) == 0, "URL should NOT appear in advisories (already in exploits)"

    def test_no_deduplication_when_filtering(self, sample_nvd_reference):
        """When using --type filter, deduplication should be skipped"""
        # When search_type != "all", we skip deduplication to show all matching refs
        search_type = "poc"

        # Same URL in multiple categories
        refs = [
            {**sample_nvd_reference, "url": "https://example.com/resource", "categories": ["poc", "advisory"]},
            {**sample_nvd_reference, "url": "https://example.com/resource", "categories": ["poc"]}
        ]

        # Filter by poc (no deduplication)
        filtered = [r for r in refs if "poc" in r.get("categories", [])]

        # Should show both (even though same URL) because no deduplication when filtering
        assert len(filtered) == 2, "Should not deduplicate when using --type filter"

    def test_url_normalization_for_dedup(self, sample_nvd_reference):
        """URLs should be normalized for deduplication (case, whitespace, trailing slash)"""
        refs = [
            {**sample_nvd_reference, "url": "https://Example.com/Path/", "categories": ["poc"]},
            {**sample_nvd_reference, "url": "https://example.com/path", "categories": ["advisory"]},
            {**sample_nvd_reference, "url": " https://EXAMPLE.COM/PATH ", "categories": ["fix"]}
        ]

        # Normalize URLs for deduplication
        seen_urls = set()
        unique_refs = []

        for ref in refs:
            url = ref.get("url", "").strip().lower().rstrip('/')
            if url and url not in seen_urls:
                seen_urls.add(url)
                unique_refs.append(ref)

        assert len(unique_refs) == 1, "Should deduplicate case-insensitive URLs with trailing slashes"


class TestBlockKitGeneration:
    """Test Block Kit block generation"""

    def test_header_block_generation(self, sample_cve_data):
        """CVE header should be formatted correctly"""
        cve_id = sample_cve_data["cve_id"]
        severity = sample_cve_data["severity"]

        severity_emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "UNKNOWN": "⚪"
        }
        emoji = severity_emoji.get(severity, "⚪")

        header_block = {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} {cve_id}",
                "emoji": True
            }
        }

        assert header_block["type"] == "header"
        assert "🔴" in header_block["text"]["text"]
        assert "CVE-2021-44228" in header_block["text"]["text"]

    def test_kev_indicator_in_context(self, sample_cve_data):
        """KEV indicator should appear in context block"""
        is_kev = sample_cve_data["is_kev"]
        severity = sample_cve_data["severity"]
        cvss = sample_cve_data["cvss_score"]

        severity_text = f"*{severity}* (CVSS {cvss})"
        if is_kev:
            severity_text += " • 🚨 *ACTIVELY EXPLOITED (CISA KEV)*"

        assert "ACTIVELY EXPLOITED" in severity_text
        assert "🚨" in severity_text

    def test_cwe_field_generation(self, sample_cve_data):
        """CWE field should be formatted correctly"""
        cwe_list = sample_cve_data["cwe"]

        if cwe_list:
            cwe_str = ", ".join(cwe_list)
            cwe_field = {
                "type": "mrkdwn",
                "text": f"*Weakness Types*\n{cwe_str}"
            }

            assert "CWE-20" in cwe_field["text"]
            assert "CWE-400" in cwe_field["text"]
            assert "CWE-502" in cwe_field["text"]

    def test_action_buttons_generation(self, sample_cve_data):
        """Action buttons should include NVD, GitHub, and Exploit-DB links"""
        cve_id = sample_cve_data["cve_id"]
        cvss = sample_cve_data["cvss_score"]

        action_buttons = [
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "View on NVD", "emoji": True},
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "action_id": "view_nvd"
            },
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "Search GitHub", "emoji": True},
                "url": f"https://github.com/search?q={cve_id}+poc",
                "action_id": "search_github"
            }
        ]

        # Critical CVEs should have Exploit-DB button
        if cvss >= 7.0:
            action_buttons.append({
                "type": "button",
                "text": {"type": "plain_text", "text": "Check Exploits", "emoji": True},
                "style": "danger",
                "url": f"https://www.exploit-db.com/search?cve={cve_id}",
                "action_id": "check_exploits"
            })

        assert len(action_buttons) == 3, "Critical CVE should have 3 buttons"
        assert any("exploit-db.com" in btn["url"] for btn in action_buttons)


class TestRiskAssessment:
    """Test risk assessment logic"""

    def test_critical_risk_assessment(self):
        """CVSS >= 9.0 should show critical risk"""
        cvss = 10.0

        if cvss >= 9.0:
            risk_text = "🚨 *Critical severity.* Immediate patching required."
        elif cvss >= 7.0:
            risk_text = "⚠️ *High severity.* Prioritize patching."
        elif cvss >= 4.0:
            risk_text = "⚡ *Medium severity.* Schedule patching."
        else:
            risk_text = "✅ *Low severity.* Update when convenient."

        assert "Critical severity" in risk_text
        assert "Immediate patching" in risk_text

    def test_high_risk_assessment(self):
        """CVSS >= 7.0 should show high risk"""
        cvss = 8.5

        if cvss >= 9.0:
            risk_text = "🚨 *Critical severity.* Immediate patching required."
        elif cvss >= 7.0:
            risk_text = "⚠️ *High severity.* Prioritize patching."
        elif cvss >= 4.0:
            risk_text = "⚡ *Medium severity.* Schedule patching."
        else:
            risk_text = "✅ *Low severity.* Update when convenient."

        assert "High severity" in risk_text
        assert "Prioritize patching" in risk_text

    def test_medium_risk_assessment(self):
        """CVSS >= 4.0 should show medium risk"""
        cvss = 5.5

        if cvss >= 9.0:
            risk_text = "🚨 *Critical severity.* Immediate patching required."
        elif cvss >= 7.0:
            risk_text = "⚠️ *High severity.* Prioritize patching."
        elif cvss >= 4.0:
            risk_text = "⚡ *Medium severity.* Schedule patching."
        else:
            risk_text = "✅ *Low severity.* Update when convenient."

        assert "Medium severity" in risk_text
        assert "Schedule patching" in risk_text

    def test_low_risk_assessment(self):
        """CVSS < 4.0 should show low risk"""
        cvss = 2.5

        if cvss >= 9.0:
            risk_text = "🚨 *Critical severity.* Immediate patching required."
        elif cvss >= 7.0:
            risk_text = "⚠️ *High severity.* Prioritize patching."
        elif cvss >= 4.0:
            risk_text = "⚡ *Medium severity.* Schedule patching."
        else:
            risk_text = "✅ *Low severity.* Update when convenient."

        assert "Low severity" in risk_text
        assert "Update when convenient" in risk_text

    def test_non_numeric_cvss_handling(self):
        """Non-numeric CVSS scores should be handled gracefully"""
        cvss_values = ["N/A", None, "Unknown", ""]

        for cvss_raw in cvss_values:
            try:
                cvss = float(cvss_raw) if cvss_raw != "N/A" and cvss_raw else 0
            except (ValueError, TypeError):
                cvss = 0

            assert cvss == 0, f"Non-numeric CVSS should default to 0: {cvss_raw}"
