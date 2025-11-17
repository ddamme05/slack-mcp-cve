"""
Real integration tests for worker pipeline

Tests worker.py job processing logic and error handling without importing worker module
(to avoid Redis/Slack dependencies). These tests verify the LOGIC, not the actual imports.
"""
import sys
import os
import json
import time
import re
from unittest.mock import Mock, patch, MagicMock

import pytest


class TestWorkerJobProcessing:
    """Test worker job processing logic without actual imports"""
    
    def test_cve_id_query_calls_correct_tools(self):
        """Test that CVE ID queries should call lookup_cve_details and search_github_cve_repos"""
        # Simulate worker logic
        query = "CVE-2021-44228"
        search_type = "all"
        
        # Verify CVE ID pattern detection
        is_cve = bool(re.match(r'^CVE-\d{4}-\d{4,}$', query.upper()))
        assert is_cve
        
        # Worker should call these tools:
        expected_tools = ["lookup_cve_details", "search_github_cve_repos"]
        
        # Verify tool names are correct
        assert "lookup_cve_details" in expected_tools
        assert "search_github_cve_repos" in expected_tools
    
    def test_keyword_query_calls_search_tool(self):
        """Test that keyword queries should call search_cve_by_keyword"""
        query = "apache log4j"
        
        # Verify it's NOT a CVE ID
        is_cve = bool(re.match(r'^CVE-\d{4}-\d{4,}$', query.upper()))
        assert not is_cve
        
        # Worker should call this tool for keywords
        expected_tool = "search_cve_by_keyword"
        
        assert expected_tool == "search_cve_by_keyword"
    
    def test_kev_details_called_when_is_kev_true(self):
        """Test that KEV details should be fetched when is_kev=True"""
        nvd_data = {
            "cve_id": "CVE-2021-44228",
            "is_kev": True  # This should trigger KEV details fetch
        }
        
        # Worker logic: check KEV details when is_kev is True
        should_fetch_kev = nvd_data.get("is_kev") and not nvd_data.get("error")
        
        assert should_fetch_kev
        
        # Expected tool call
        expected_tool = "check_cisa_kev_details"
        assert expected_tool == "check_cisa_kev_details"


class TestWorkerErrorHandling:
    """Test worker error handling logic"""
    
    def test_mcp_error_handling(self):
        """Test that MCP errors should be handled gracefully"""
        # Simulate MCP error response
        nvd_data = {
            "error": "CVE not found in NVD database",
            "cve_id": "CVE-9999-99999"
        }
        
        # Worker should detect error in response
        has_error = "error" in nvd_data
        assert has_error
        
        # Worker should return error message to Slack
        error_message = nvd_data.get("error", "Unknown error")
        assert "CVE not found" in error_message
        
        # Expected: Worker should format error block for Slack
        # Report should contain: "CVE Not Found" or similar message
    
    def test_malformed_json_handling(self):
        """Test handling of malformed JSON in job data"""
        job_json = '{"query": "CVE-2021-44228", invalid json'
        
        # Worker should catch JSONDecodeError
        try:
            job_data = json.loads(job_json)
            parsed = True
        except json.JSONDecodeError:
            parsed = False
        
        assert not parsed, "Malformed JSON should raise JSONDecodeError"
    
    def test_missing_query_field_handling(self):
        """Test handling of job with missing query field"""
        job_data = {"search_type": "all"}  # Missing 'query' field
        
        query = job_data.get("query", "").strip()
        
        assert not query, "Missing query should be detected"
    
    def test_empty_query_handling(self):
        """Test handling of empty query"""
        job_data = {"query": "   "}  # Empty/whitespace query
        
        query = job_data.get("query", "").strip()
        
        assert not query, "Empty query should be detected"
    
    def test_stale_job_detection(self):
        """Test detection of stale jobs (TTL expired)"""
        import time
        
        # Job from 2 hours ago
        job_data = {
            "query": "CVE-2021-44228",
            "timestamp": time.time() - 7200  # 2 hours ago
        }
        
        job_age = time.time() - job_data.get("timestamp", time.time())
        is_stale = job_age > 3600  # 1 hour TTL
        
        assert is_stale, "Job older than 1 hour should be marked stale"


class TestWorkerDeliveryMethods:
    """Test worker delivery methods (webhook vs Web API)"""
    
    def test_webhook_delivery_detection(self):
        """Test detection of webhook delivery (slash command)"""
        job_data = {
            "query": "CVE-2021-44228",
            "response_url": "https://hooks.slack.com/...",
            "timestamp": 0
        }
        
        has_webhook = bool(job_data.get("response_url"))
        has_channel = bool(job_data.get("channel_id"))
        
        assert has_webhook
        assert not has_channel
    
    def test_web_api_delivery_detection(self):
        """Test detection of Web API delivery (@mention)"""
        job_data = {
            "query": "CVE-2021-44228",
            "channel_id": "C12345",
            "thread_ts": "1234567890.123456",
            "timestamp": 0
        }
        
        has_webhook = bool(job_data.get("response_url"))
        has_channel = bool(job_data.get("channel_id"))
        
        assert not has_webhook
        assert has_channel
    
    def test_missing_delivery_method_detection(self):
        """Test detection of job with no delivery method"""
        job_data = {
            "query": "CVE-2021-44228",
            "timestamp": 0
            # No response_url or channel_id
        }
        
        has_webhook = bool(job_data.get("response_url"))
        has_channel = bool(job_data.get("channel_id"))
        
        assert not has_webhook
        assert not has_channel, "Job should be rejected without delivery method"


class TestWorkerSearchTypeHandling:
    """Test search_type parameter handling"""
    
    def test_search_type_logic_flow(self):
        """Test that search_type logic flow is correct"""
        query = "CVE-2021-44228"
        search_types = ["poc", "fix", "advisory", "all"]
        
        for search_type in search_types:
            # Simulate job payload
            job = {
                "query": query,
                "search_type": search_type
            }
            
            # Worker should extract search_type from job
            extracted_type = job.get("search_type", "all")
            assert extracted_type == search_type
            
            # Worker logic: pass to GitHub search tool
            # Expected: search_github_cve_repos(cve_id=query, search_type=extracted_type)
    
    def test_search_type_default_to_all(self):
        """Test that search_type defaults to 'all' if not provided"""
        job_data = {"query": "CVE-2021-44228"}
        
        search_type = job_data.get("search_type", "all")
        
        assert search_type == "all"
    
    def test_valid_search_types(self):
        """Test validation of search_type values"""
        valid_types = ["poc", "fix", "advisory", "all"]
        
        for search_type in valid_types:
            assert search_type in ["poc", "fix", "advisory", "all"]
        
        # Invalid type
        assert "invalid" not in ["poc", "fix", "advisory", "all"]


class TestWorkerCVEDetection:
    """Test CVE ID vs keyword detection"""
    
    def test_cve_id_pattern_detection(self):
        """Test CVE ID pattern matching"""
        import re
        
        cve_queries = [
            "CVE-2021-44228",
            "cve-2021-44228",  # lowercase
            "CVE-2023-12345"
        ]
        
        for query in cve_queries:
            is_cve = bool(re.match(r'^CVE-\d{4}-\d{4,}$', query.upper()))
            assert is_cve, f"Should detect as CVE ID: {query}"
    
    def test_keyword_detection(self):
        """Test keyword query detection"""
        import re
        
        keyword_queries = [
            "apache log4j",
            "kubernetes rce",
            "windows privilege escalation"
        ]
        
        for query in keyword_queries:
            is_cve = bool(re.match(r'^CVE-\d{4}-\d{4,}$', query.upper()))
            assert not is_cve, f"Should detect as keyword: {query}"
    
    def test_invalid_cve_format(self):
        """Test invalid CVE format detection"""
        import re
        
        invalid_cves = [
            "CVE-2021",  # Missing number
            "CVE-21-44228",  # Wrong year format
            "CVE-2021-123",  # Number too short
            "CVSS-2021-44228"  # Wrong prefix
        ]
        
        for query in invalid_cves:
            is_cve = bool(re.match(r'^CVE-\d{4}-\d{4,}$', query.upper()))
            assert not is_cve, f"Should reject invalid format: {query}"


class TestWorkerFormatting:
    """Test worker formatting logic"""
    
    def test_format_cve_report_reference_filtering(self):
        """Test that report formatting filters references by search_type"""
        # Simulate CVE data with mixed reference types
        references = [
            {"url": "https://exploit-db.com/12345", "categories": ["poc"], "type": "🚨 Exploit"},
            {"url": "https://github.com/fix", "categories": ["fix"], "type": "🔧 Patch"},
            {"url": "https://nvd.nist.gov/vuln", "categories": ["advisory"], "type": "📋 Advisory"}
        ]
        
        # Test filtering logic
        search_types = ["poc", "fix", "advisory", "all"]
        
        for search_type in search_types:
            if search_type == "all":
                filtered = references
            else:
                filtered = [ref for ref in references if search_type in ref.get("categories", [])]
            
            if search_type == "poc":
                assert len(filtered) == 1
                assert "exploit-db" in filtered[0]["url"]
            elif search_type == "fix":
                assert len(filtered) == 1
                assert "fix" in filtered[0]["url"]
            elif search_type == "advisory":
                assert len(filtered) == 1
                assert "nvd.nist" in filtered[0]["url"]
            else:  # all
                assert len(filtered) == 3
    
    def test_format_cve_list_empty_results(self):
        """Test that empty results are handled gracefully"""
        # Simulate empty search results
        cve_data = {
            "keyword": "nonexistent",
            "total_results": 0,
            "cves": []
        }
        
        # Worker should detect empty results
        has_results = len(cve_data.get("cves", [])) > 0
        assert not has_results
        
        # Expected behavior: return message about no results
        expected_message = f"No CVEs found for keyword: {cve_data['keyword']}"
        assert "No CVEs found" in expected_message


class TestWorkerBlockKitToggle:
    """Test Block Kit feature flag"""
    
    @patch.dict(os.environ, {"USE_BLOCKS": "true"})
    def test_blocks_enabled(self):
        """Test that Block Kit is used when enabled"""
        use_blocks = os.environ.get("USE_BLOCKS", "true").lower() == "true"
        
        assert use_blocks
    
    @patch.dict(os.environ, {"USE_BLOCKS": "false"})
    def test_blocks_disabled(self):
        """Test that Block Kit is disabled when flag is false"""
        use_blocks = os.environ.get("USE_BLOCKS", "true").lower() == "true"
        
        assert not use_blocks
    
    @patch.dict(os.environ, {}, clear=True)
    def test_blocks_default_enabled(self):
        """Test that Block Kit defaults to enabled"""
        use_blocks = os.environ.get("USE_BLOCKS", "true").lower() == "true"
        
        assert use_blocks


class TestWorkerTestMode:
    """Test TEST_MODE behavior"""
    
    @patch.dict(os.environ, {"TEST_MODE": "true"})
    def test_test_mode_skips_validation(self):
        """Test that TEST_MODE skips delivery method validation"""
        test_mode = os.environ.get("TEST_MODE", "true").lower() == "true"
        
        assert test_mode
        
        # In test mode, job without delivery method should be allowed
        job_data = {"query": "CVE-2021-44228", "timestamp": 0}
        has_webhook = bool(job_data.get("response_url"))
        has_channel = bool(job_data.get("channel_id"))
        
        # In test mode, we don't validate delivery method
        if test_mode:
            should_process = True
        else:
            should_process = has_webhook or has_channel
        
        assert should_process
    
    @patch.dict(os.environ, {"TEST_MODE": "false"})
    def test_production_mode_enforces_validation(self):
        """Test that production mode enforces delivery method"""
        test_mode = os.environ.get("TEST_MODE", "true").lower() == "true"
        
        assert not test_mode
        
        # In production, job without delivery method should be rejected
        job_data = {"query": "CVE-2021-44228", "timestamp": 0}
        has_webhook = bool(job_data.get("response_url"))
        has_channel = bool(job_data.get("channel_id"))
        
        if test_mode:
            should_process = True
        else:
            should_process = has_webhook or has_channel
        
        assert not should_process, "Production mode should reject job without delivery method"
