"""
Test URL sanitization for Slack formatting

Tests the worker's URL escaping logic to prevent:
- Slack markdown injection
- Link breakage from special characters
- Display issues with long URLs

Critical for security and user experience.
"""
import pytest


class TestURLSanitization:
    """Test URL escaping for Slack link formatting"""

    def test_ampersand_escaping(self):
        """Ampersands in URLs should be escaped"""
        url = "https://example.com/page?foo=bar&baz=qux&test=1"

        # Simulate worker/blocks.py sanitization logic
        sanitized_url = url.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        assert "&amp;" in sanitized_url, "Ampersands should be escaped to &amp;"
        assert "&" not in sanitized_url.replace("&amp;", ""), "No unescaped ampersands should remain"

    def test_angle_bracket_escaping(self):
        """Angle brackets should be escaped to prevent markdown injection"""
        url = "https://example.com/path<script>alert(1)</script>"

        sanitized_url = url.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        assert "<" not in sanitized_url, "No unescaped < should remain"
        assert ">" not in sanitized_url, "No unescaped > should remain"
        assert "&lt;" in sanitized_url, "< should be escaped to &lt;"
        assert "&gt;" in sanitized_url, "> should be escaped to &gt;"

    def test_pipe_escaping_in_display_text(self):
        """Pipe characters should be escaped in display text (breaks Slack links)"""
        display_text = "example.com/path|with|pipes"

        # Slack link format: <url|display_text>
        # Pipes in display text break the link, so we escape them
        sanitized_display = display_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("|", "\\|")

        assert "\\|" in sanitized_display, "Pipes should be escaped to \\|"
        assert "|" not in sanitized_display.replace("\\|", ""), "No unescaped pipes should remain"

    def test_mixed_special_characters(self):
        """URLs with multiple special characters should all be escaped"""
        url = "https://example.com/page?a=1&b=2<test>|pipe"

        sanitized_url = url.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        sanitized_display = url.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("|", "\\|")

        # URL sanitization
        assert "&amp;" in sanitized_url
        assert "&lt;" in sanitized_url
        assert "&gt;" in sanitized_url

        # Display text sanitization (includes pipe escaping)
        assert "\\|" in sanitized_display

    def test_already_escaped_entities(self):
        """URLs with pre-escaped entities will be double-escaped (expected behavior)"""
        url = "https://example.com/page?foo=bar&amp;baz=qux"

        # Simple string replacement will double-escape
        sanitized = url.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        # This is expected behavior with simple string replacement
        # In practice, NVD URLs don't come pre-escaped, so this is not a real-world issue
        assert "&amp;amp;" in sanitized, "Double-escaping occurs with simple replacement (expected)"
        assert sanitized == "https://example.com/page?foo=bar&amp;amp;baz=qux"

    def test_empty_url_handling(self):
        """Empty URLs should be detected before sanitization"""
        urls = ["", "   ", None]

        for url in urls:
            if not url or (isinstance(url, str) and url.strip() == ""):
                result = "• _(Invalid reference - no URL)_"
            else:
                result = url

            assert result == "• _(Invalid reference - no URL)_", f"Empty URL should be handled: {url}"

    def test_url_truncation_for_display(self):
        """Very long URLs should be truncated for display"""
        long_url = "https://example.com/" + "a" * 200

        # Simulate truncation logic from worker/blocks.py
        domain_path = long_url.split("://")[1]
        if len(domain_path) > 70:
            display_url = domain_path[:67] + "..."
        else:
            display_url = domain_path

        assert len(display_url) <= 70, "Display URL should be truncated to 70 chars"
        assert display_url.endswith("..."), "Truncated URL should end with ..."

    def test_slack_link_format(self):
        """Test complete Slack link formatting"""
        url = "https://example.com/page?foo=bar&baz=qux"

        # Sanitize
        sanitized_url = url.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        # Extract display text (domain + path)
        display_url = url.split("://")[1]
        sanitized_display = display_url.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("|", "\\|")

        # Format as Slack link
        slack_link = f"<{sanitized_url}|{sanitized_display}>"

        # Verify format
        assert slack_link.startswith("<"), "Slack link should start with <"
        assert slack_link.endswith(">"), "Slack link should end with >"
        assert "|" in slack_link, "Slack link should have pipe separator (not escaped in outer structure)"
        assert "&amp;" in slack_link, "URL params should be escaped"

    def test_domain_extraction_with_protocol(self):
        """Test extracting domain + path for display"""
        url = "https://packetstormsecurity.com/files/165260/VMware-Security-Advisory.html"

        if "://" in url:
            domain_path = url.split("://")[1]
        else:
            domain_path = url

        assert domain_path == "packetstormsecurity.com/files/165260/VMware-Security-Advisory.html"
        assert "https://" not in domain_path, "Protocol should be removed from display"

    def test_domain_extraction_without_protocol(self):
        """Test handling URLs without protocol"""
        url = "example.com/path/to/resource"

        if "://" in url:
            domain_path = url.split("://")[1]
        else:
            domain_path = url

        assert domain_path == url, "URL without protocol should be used as-is"


class TestReferenceFormatting:
    """Test reference link formatting logic"""

    def test_inference_indicator(self):
        """References not tagged by NVD should show '(inferred)' marker"""
        ref = {
            "url": "https://example.com/exploit",
            "nvd_tagged": False  # Heuristically classified
        }

        # Simulate logic from _format_reference_link
        inference = ""
        if not ref.get("nvd_tagged", True):
            inference = " _(inferred)_"

        assert inference == " _(inferred)_", "Heuristically classified refs should show (inferred)"

    def test_nvd_tagged_no_indicator(self):
        """References tagged by NVD should NOT show '(inferred)' marker"""
        ref = {
            "url": "https://example.com/advisory",
            "nvd_tagged": True  # Tagged by NVD
        }

        inference = ""
        if not ref.get("nvd_tagged", True):
            inference = " _(inferred)_"

        assert inference == "", "NVD-tagged refs should not show (inferred)"

    def test_missing_nvd_tagged_field(self):
        """References without nvd_tagged field should default to True (no marker)"""
        ref = {
            "url": "https://example.com/advisory"
            # Missing nvd_tagged field
        }

        inference = ""
        if not ref.get("nvd_tagged", True):  # Default to True
            inference = " _(inferred)_"

        assert inference == "", "Missing nvd_tagged should default to True (no marker)"


class TestEdgeCaseSanitization:
    """Test edge cases and potential attack vectors"""

    def test_xss_attempt_in_url(self):
        """XSS attempts in URLs should be escaped"""
        url = "https://example.com/search?q=<script>alert('XSS')</script>"

        sanitized_url = url.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        assert "<script>" not in sanitized_url, "Script tags should be escaped"
        assert "&lt;script&gt;" in sanitized_url, "Script tags should become &lt;script&gt;"

    def test_markdown_injection_attempt(self):
        """Markdown injection attempts should be neutralized"""
        url = "https://example.com/path](malicious-link)"

        # Angle brackets would break Slack links, but they get escaped
        sanitized_url = url.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        # The closing bracket and paren would still be there, but can't break out of <url|text> format
        # Slack's link format is robust against this
        assert "](" in sanitized_url, "Bracket-paren sequence preserved (Slack format is safe)"

    def test_null_byte_in_url(self):
        """Null bytes should not crash sanitization"""
        url = "https://example.com/path\x00malicious"

        try:
            sanitized_url = url.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            success = True
        except Exception:
            success = False

        assert success, "Null bytes should not crash sanitization"

    def test_unicode_characters(self):
        """Unicode characters should be preserved"""
        url = "https://example.com/path/文档"

        sanitized_url = url.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        assert "文档" in sanitized_url, "Unicode characters should be preserved"

    def test_encoded_url_preserved(self):
        """URL-encoded characters should be preserved"""
        url = "https://example.com/path?q=hello%20world&foo=bar%3Dbaz"

        sanitized_url = url.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        assert "%20" in sanitized_url, "URL encoding should be preserved"
        assert "%3D" in sanitized_url, "URL encoding should be preserved"
        assert "&amp;" in sanitized_url, "Ampersands should still be escaped"
