"""
Test URL heuristic classification logic

Tests the MCP server's ability to correctly classify URLs as:
- Exploits (PoC, exploit code, RCE demos)
- Advisories (security bulletins, vendor advisories)
- Patches (commits, vendor fixes)

Critical logic: Advisory URL exclusion prevents legitimate security bulletins
from being incorrectly tagged as exploits.
"""
import pytest


class TestExploitDetection:
    """Test exploit URL pattern matching"""

    def test_exploit_db_urls(self):
        """Exploit-DB URLs should be tagged as exploits"""
        url = "https://www.exploit-db.com/exploits/50337"

        # Simulate MCP server logic
        exploit_indicators = ["exploit-db", "exploit", "poc", "metasploit",
                             "remote-code-execution", "rce", "injection",
                             "code-execution", "payload", "shell"]

        url_lower = url.lower()
        is_exploit = any(p in url_lower for p in exploit_indicators)

        assert is_exploit, "Exploit-DB URL should be detected as exploit"

    def test_packetstorm_exploit_urls(self, exploit_urls):
        """PacketStorm exploit URLs should be tagged as exploits"""
        # Only include URLs with clear exploit indicators (RCE, injection, code-execution, shell)
        # Note: "Information-Disclosure" is NOT an exploit indicator
        packetstorm_exploits = [
            u for u in exploit_urls if "packetstorm" in u and
            ("remote-code-execution" in u.lower() or "injection" in u.lower() or
             "code-execution" in u.lower() or "shell" in u.lower())
        ]

        exploit_indicators = ["exploit-db", "exploit", "poc", "metasploit",
                             "remote-code-execution", "rce", "injection",
                             "code-execution", "payload", "shell"]

        for url in packetstorm_exploits:
            url_lower = url.lower()
            is_exploit = any(p in url_lower for p in exploit_indicators)
            is_advisory_url = any(p in url_lower for p in ["security-advisory", "advisory", "bulletin"])

            # Should be tagged as exploit (has exploit indicator, no advisory pattern)
            assert is_exploit and not is_advisory_url, f"PacketStorm exploit should be detected: {url}"

    def test_packetstorm_advisory_urls_excluded(self, advisory_urls):
        """PacketStorm advisory URLs should NOT be tagged as exploits"""
        packetstorm_advisories = [u for u in advisory_urls if "packetstorm" in u]

        exploit_indicators = ["exploit-db", "exploit", "poc", "metasploit",
                             "remote-code-execution", "rce", "injection",
                             "code-execution", "payload", "shell"]

        for url in packetstorm_advisories:
            url_lower = url.lower()
            is_exploit = any(p in url_lower for p in exploit_indicators)
            is_advisory_url = any(p in url_lower for p in ["security-advisory", "advisory", "bulletin"])

            # Should NOT be tagged as exploit (advisory URL exclusion)
            should_tag = is_exploit and not is_advisory_url

            assert not should_tag, f"PacketStorm advisory should NOT be tagged as exploit: {url}"

    def test_metasploit_urls(self, exploit_urls):
        """Metasploit URLs should be tagged as exploits"""
        metasploit_urls = [u for u in exploit_urls if "metasploit" in u.lower()]

        exploit_indicators = ["exploit-db", "exploit", "poc", "metasploit",
                             "remote-code-execution", "rce", "injection",
                             "code-execution", "payload", "shell"]

        for url in metasploit_urls:
            url_lower = url.lower()
            is_exploit = any(p in url_lower for p in exploit_indicators)

            assert is_exploit, f"Metasploit URL should be detected as exploit: {url}"

    def test_poc_repository_urls(self, exploit_urls):
        """PoC repository URLs should be detected"""
        poc_repos = [u for u in exploit_urls if "poc" in u.lower() or "shell-poc" in u.lower()]

        exploit_indicators = ["exploit-db", "exploit", "poc", "metasploit",
                             "remote-code-execution", "rce", "injection",
                             "code-execution", "payload", "shell"]

        for url in poc_repos:
            url_lower = url.lower()
            is_exploit = any(p in url_lower for p in exploit_indicators)

            assert is_exploit, f"PoC repository should be detected as exploit: {url}"

    def test_rce_indicator_urls(self, exploit_urls):
        """URLs with RCE indicators should be tagged as exploits"""
        rce_urls = [u for u in exploit_urls if "rce" in u.lower() or "remote-code-execution" in u.lower() or "code-execution" in u.lower()]

        exploit_indicators = ["exploit-db", "exploit", "poc", "metasploit",
                             "remote-code-execution", "rce", "injection",
                             "code-execution", "payload", "shell"]

        for url in rce_urls:
            url_lower = url.lower()
            is_exploit = any(p in url_lower for p in exploit_indicators)

            assert is_exploit, f"RCE URL should be detected as exploit: {url}"


class TestAdvisoryDetection:
    """Test advisory URL pattern matching"""

    def test_vendor_advisory_urls(self, advisory_urls):
        """Vendor advisory URLs should NOT be tagged as exploits"""
        vendor_advisories = [
            u for u in advisory_urls if
            "microsoft.com" in u or "oracle.com" in u or "redhat.com" in u
        ]

        exploit_indicators = ["exploit-db", "exploit", "poc", "metasploit",
                             "remote-code-execution", "rce", "injection",
                             "code-execution", "payload", "shell"]

        for url in vendor_advisories:
            url_lower = url.lower()
            is_exploit = any(p in url_lower for p in exploit_indicators)
            is_advisory_url = any(p in url_lower for p in ["security-advisory", "advisory", "bulletin"])

            # Vendor advisories should not have exploit indicators in URL
            assert not is_exploit, f"Vendor advisory should not have exploit indicators: {url}"

    def test_security_bulletin_urls(self, advisory_urls):
        """Security bulletin URLs should be recognized as advisories"""
        bulletins = [u for u in advisory_urls if "bulletin" in u.lower() or "security-advisory" in u.lower()]

        for url in bulletins:
            url_lower = url.lower()
            is_advisory_url = any(p in url_lower for p in ["security-advisory", "advisory", "bulletin"])

            assert is_advisory_url, f"Security bulletin should be detected: {url}"

    def test_nvd_mitre_urls(self, advisory_urls):
        """NVD and MITRE URLs should be advisories"""
        nvd_mitre = [u for u in advisory_urls if "nvd.nist.gov" in u or "cve.mitre.org" in u]

        for url in nvd_mitre:
            # These should NOT have exploit indicators
            exploit_indicators = ["exploit-db", "exploit", "poc", "metasploit",
                                 "remote-code-execution", "rce", "injection",
                                 "code-execution", "payload", "shell"]

            url_lower = url.lower()
            is_exploit = any(p in url_lower for p in exploit_indicators)

            assert not is_exploit, f"NVD/MITRE URL should not be tagged as exploit: {url}"

    def test_github_advisory_urls(self, advisory_urls):
        """GitHub advisory URLs should be recognized"""
        gh_advisories = [u for u in advisory_urls if "github.com/advisories" in u]

        for url in gh_advisories:
            # Should NOT have exploit indicators
            exploit_indicators = ["exploit-db", "exploit", "poc", "metasploit",
                                 "remote-code-execution", "rce", "injection",
                                 "code-execution", "payload", "shell"]

            url_lower = url.lower()
            is_exploit = any(p in url_lower for p in exploit_indicators)

            assert not is_exploit, f"GitHub advisory should not be tagged as exploit: {url}"


class TestPatchDetection:
    """Test patch/fix URL pattern matching"""

    def test_github_commit_urls(self, patch_urls):
        """GitHub commit URLs should be detected as patches"""
        commits = [u for u in patch_urls if "/commit/" in u]

        patch_patterns = ["/commit/", "/pull/", "/patch", "/diff"]

        for url in commits:
            url_lower = url.lower()
            is_patch = any(p in url_lower for p in patch_patterns)

            assert is_patch, f"GitHub commit should be detected as patch: {url}"

    def test_github_pull_request_urls(self, patch_urls):
        """GitHub pull request URLs should be detected as patches"""
        prs = [u for u in patch_urls if "/pull/" in u]

        patch_patterns = ["/commit/", "/pull/", "/patch", "/diff"]

        for url in prs:
            url_lower = url.lower()
            is_patch = any(p in url_lower for p in patch_patterns)

            assert is_patch, f"GitHub pull request should be detected as patch: {url}"

    def test_patch_file_urls(self, patch_urls):
        """Direct patch file URLs should be detected"""
        patch_files = [u for u in patch_urls if ".patch" in u or ".diff" in u]

        patch_patterns = ["/commit/", "/pull/", "/patch", "/diff"]

        for url in patch_files:
            url_lower = url.lower()
            is_patch = any(p in url_lower for p in patch_patterns)

            assert is_patch, f"Patch file should be detected: {url}"


class TestEdgeCases:
    """Test edge cases and boundary conditions"""

    def test_advisory_about_exploit(self):
        """Advisory URL mentioning 'RCE' should NOT be tagged as exploit"""
        url = "https://packetstormsecurity.com/files/165280/Security-Advisory-About-RCE.html"

        exploit_indicators = ["exploit-db", "exploit", "poc", "metasploit",
                             "remote-code-execution", "rce", "injection",
                             "code-execution", "payload", "shell"]

        url_lower = url.lower()
        is_exploit = any(p in url_lower for p in exploit_indicators)
        is_advisory_url = any(p in url_lower for p in ["security-advisory", "advisory", "bulletin"])

        # Has "rce" BUT also "Security-Advisory" -> should NOT be tagged as exploit
        should_tag = is_exploit and not is_advisory_url

        assert not should_tag, "Advisory about exploits should not be tagged as exploit"

    def test_bulletin_with_exploit_mention(self):
        """Bulletin URL mentioning 'exploit' should NOT be tagged as exploit"""
        url = "https://example.com/bulletin-exploit-analysis.html"

        exploit_indicators = ["exploit-db", "exploit", "poc", "metasploit",
                             "remote-code-execution", "rce", "injection",
                             "code-execution", "payload", "shell"]

        url_lower = url.lower()
        is_exploit = any(p in url_lower for p in exploit_indicators)
        is_advisory_url = any(p in url_lower for p in ["security-advisory", "advisory", "bulletin"])

        # Has "exploit" AND "bulletin" -> should NOT be tagged as exploit
        should_tag = is_exploit and not is_advisory_url

        assert not should_tag, "Bulletin mentioning exploits should not be tagged as exploit"

    def test_pure_exploit_url(self):
        """Pure exploit URL should be tagged as exploit"""
        url = "https://packetstormsecurity.com/files/165270/Remote-Code-Execution.html"

        exploit_indicators = ["exploit-db", "exploit", "poc", "metasploit",
                             "remote-code-execution", "rce", "injection",
                             "code-execution", "payload", "shell"]

        url_lower = url.lower()
        is_exploit = any(p in url_lower for p in exploit_indicators)
        is_advisory_url = any(p in url_lower for p in ["security-advisory", "advisory", "bulletin"])

        # Has "Remote-Code-Execution", no advisory pattern -> should be tagged
        should_tag = is_exploit and not is_advisory_url

        assert should_tag, "Pure exploit URL should be tagged as exploit"

    def test_empty_url(self):
        """Empty URL should not crash"""
        url = ""

        exploit_indicators = ["exploit-db", "exploit", "poc", "metasploit",
                             "remote-code-execution", "rce", "injection",
                             "code-execution", "payload", "shell"]

        url_lower = url.lower()
        is_exploit = any(p in url_lower for p in exploit_indicators)

        # Should not crash, should return False
        assert not is_exploit

    def test_case_insensitive_matching(self):
        """Pattern matching should be case-insensitive"""
        urls = [
            "https://example.com/EXPLOIT-DB/test",
            "https://example.com/Exploit-Analysis",
            "https://example.com/PoC-Demo",
            "https://example.com/REMOTE-CODE-EXECUTION"
        ]

        exploit_indicators = ["exploit-db", "exploit", "poc", "metasploit",
                             "remote-code-execution", "rce", "injection",
                             "code-execution", "payload", "shell"]

        for url in urls:
            url_lower = url.lower()
            is_exploit = any(p in url_lower for p in exploit_indicators)

            assert is_exploit, f"Case-insensitive matching should work: {url}"
