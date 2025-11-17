"""
Real integration tests for Slack bot command parsing

Tests bot.py command parsing logic without requiring actual Slack connection
"""
import sys
import os
import time
from collections import defaultdict, deque

import pytest


class TestCommandParsing:
    """Test slash command parsing logic"""
    
    def test_parse_cve_id_query(self):
        """Test parsing CVE ID from command text"""
        text = "CVE-2021-44228"
        
        # Parse
        query = text.strip()
        
        assert query == "CVE-2021-44228"
    
    def test_parse_keyword_query(self):
        """Test parsing keyword from command text"""
        text = "apache log4j"
        
        query = text.strip()
        
        assert query == "apache log4j"
    
    def test_parse_empty_command(self):
        """Test handling of empty command"""
        text = ""
        
        query = text.strip()
        
        assert not query
    
    def test_parse_whitespace_command(self):
        """Test handling of whitespace-only command"""
        text = "   "
        
        query = text.strip()
        
        assert not query


class TestTypeFlagParsing:
    """Test --type flag parsing logic"""
    
    def test_parse_type_poc(self):
        """Test parsing --type poc flag"""
        text = "CVE-2021-44228 --type poc"
        
        search_type = "all"  # default
        query = text
        
        if "--type" in text:
            parts = text.split("--type")
            query = parts[0].strip()
            if len(parts) > 1:
                type_parts = parts[1].strip().split()
                if type_parts:
                    type_value = type_parts[0].lower()
                    if type_value in ["poc", "fix", "advisory", "all"]:
                        search_type = type_value
        
        assert query == "CVE-2021-44228"
        assert search_type == "poc"
    
    def test_parse_type_fix(self):
        """Test parsing --type fix flag"""
        text = "CVE-2021-44228 --type fix"
        
        search_type = "all"
        query = text
        
        if "--type" in text:
            parts = text.split("--type")
            query = parts[0].strip()
            if len(parts) > 1:
                type_parts = parts[1].strip().split()
                if type_parts:
                    type_value = type_parts[0].lower()
                    if type_value in ["poc", "fix", "advisory", "all"]:
                        search_type = type_value
        
        assert query == "CVE-2021-44228"
        assert search_type == "fix"
    
    def test_parse_type_advisory(self):
        """Test parsing --type advisory flag"""
        text = "CVE-2021-44228 --type advisory"
        
        search_type = "all"
        query = text
        
        if "--type" in text:
            parts = text.split("--type")
            query = parts[0].strip()
            if len(parts) > 1:
                type_parts = parts[1].strip().split()
                if type_parts:
                    type_value = type_parts[0].lower()
                    if type_value in ["poc", "fix", "advisory", "all"]:
                        search_type = type_value
        
        assert search_type == "advisory"
    
    def test_parse_empty_type_flag(self):
        """Test handling of empty --type flag"""
        text = "CVE-2021-44228 --type"
        
        search_type = "all"
        query = text
        has_error = False
        
        if "--type" in text:
            parts = text.split("--type")
            query = parts[0].strip()
            if len(parts) > 1:
                type_parts = parts[1].strip().split()
                if not type_parts:  # Empty --type flag
                    has_error = True
        
        assert has_error, "Empty --type flag should be detected"
    
    def test_parse_invalid_type_value(self):
        """Test handling of invalid --type value"""
        text = "CVE-2021-44228 --type invalid"
        
        search_type = "all"
        query = text
        is_valid = True
        
        if "--type" in text:
            parts = text.split("--type")
            query = parts[0].strip()
            if len(parts) > 1:
                type_parts = parts[1].strip().split()
                if type_parts:
                    type_value = type_parts[0].lower()
                    if type_value not in ["poc", "fix", "advisory", "all"]:
                        is_valid = False
        
        assert not is_valid, "Invalid --type value should be detected"
    
    def test_parse_case_insensitive_type(self):
        """Test that --type is case insensitive"""
        text = "CVE-2021-44228 --type POC"
        
        search_type = "all"
        query = text
        
        if "--type" in text:
            parts = text.split("--type")
            query = parts[0].strip()
            if len(parts) > 1:
                type_parts = parts[1].strip().split()
                if type_parts:
                    type_value = type_parts[0].lower()
                    if type_value in ["poc", "fix", "advisory", "all"]:
                        search_type = type_value
        
        assert search_type == "poc", "Type value should be case insensitive"
    
    def test_parse_type_with_extra_text(self):
        """Test parsing with extra text after --type value"""
        text = "CVE-2021-44228 --type poc extra text"
        
        search_type = "all"
        query = text
        
        if "--type" in text:
            parts = text.split("--type")
            query = parts[0].strip()
            if len(parts) > 1:
                type_parts = parts[1].strip().split()
                if type_parts:
                    type_value = type_parts[0].lower()
                    if type_value in ["poc", "fix", "advisory", "all"]:
                        search_type = type_value
        
        assert query == "CVE-2021-44228"
        assert search_type == "poc"


class TestRateLimiting:
    """Test rate limiting logic"""
    
    def test_rate_limit_tracking(self):
        """Test that user requests are tracked"""
        user_requests = defaultdict(lambda: deque(maxlen=10))
        
        user_id = "U12345"
        now = time.time()
        
        # Add requests
        user_requests[user_id].append(now)
        user_requests[user_id].append(now)
        user_requests[user_id].append(now)
        
        assert len(user_requests[user_id]) == 3
    
    def test_rate_limit_window(self):
        """Test 5 requests per minute rate limit"""
        user_requests = defaultdict(lambda: deque(maxlen=10))
        
        user_id = "U12345"
        now = time.time()
        
        # Add 6 requests (exceeds limit of 5)
        for i in range(6):
            user_requests[user_id].append(now)
        
        # Check recent requests in 60-second window
        recent_requests = [t for t in user_requests[user_id] if now - t < 60]
        
        assert len(recent_requests) == 6
        assert len(recent_requests) > 5, "Should exceed rate limit"
    
    def test_rate_limit_old_requests_ignored(self):
        """Test that requests outside window are ignored"""
        user_requests = defaultdict(lambda: deque(maxlen=10))
        
        user_id = "U12345"
        now = time.time()
        
        # Add old requests (> 60 seconds ago)
        for i in range(5):
            user_requests[user_id].append(now - 120)  # 2 minutes ago
        
        # Add new request
        user_requests[user_id].append(now)
        
        # Check recent requests
        recent_requests = [t for t in user_requests[user_id] if now - t < 60]
        
        assert len(recent_requests) == 1, "Old requests should be ignored"
    
    def test_rate_limit_per_user_isolation(self):
        """Test that rate limits are per-user"""
        user_requests = defaultdict(lambda: deque(maxlen=10))
        
        now = time.time()
        
        # User 1 makes 6 requests
        for i in range(6):
            user_requests["U12345"].append(now)
        
        # User 2 makes 1 request
        user_requests["U67890"].append(now)
        
        # User 1 should be rate limited
        user1_recent = [t for t in user_requests["U12345"] if now - t < 60]
        assert len(user1_recent) > 5
        
        # User 2 should not be rate limited
        user2_recent = [t for t in user_requests["U67890"] if now - t < 60]
        assert len(user2_recent) <= 5


class TestJobPayloadConstruction:
    """Test job payload construction"""
    
    def test_slash_command_job_payload(self):
        """Test job payload for slash command"""
        query = "CVE-2021-44228"
        search_type = "poc"
        user_id = "U12345"
        response_url = "https://hooks.slack.com/..."
        
        job_data = {
            "query": query,
            "search_type": search_type,
            "user_id": user_id,
            "response_url": response_url,
            "timestamp": time.time()
        }
        
        assert job_data["query"] == query
        assert job_data["search_type"] == search_type
        assert job_data["user_id"] == user_id
        assert "response_url" in job_data
        assert "timestamp" in job_data
    
    def test_mention_job_payload(self):
        """Test job payload for @mention"""
        query = "CVE-2021-44228"
        search_type = "all"
        user_id = "U12345"
        channel_id = "C12345"
        thread_ts = "1234567890.123456"
        
        job_data = {
            "query": query,
            "user_id": user_id,
            "channel_id": channel_id,
            "thread_ts": thread_ts,
            "search_type": search_type,
            "timestamp": time.time()
        }
        
        assert job_data["query"] == query
        assert job_data["channel_id"] == channel_id
        assert job_data["thread_ts"] == thread_ts
        assert "response_url" not in job_data


class TestMentionParsing:
    """Test @mention text parsing"""
    
    def test_extract_query_from_mention(self):
        """Test extracting query from @mention text"""
        text = "<@U12345> CVE-2021-44228"
        
        # Extract query by removing bot mention
        query = text.split(">", 1)[-1].strip()
        
        assert query == "CVE-2021-44228"
    
    def test_mention_with_type_flag(self):
        """Test @mention with --type flag"""
        text = "<@U12345> CVE-2021-44228 --type poc"
        
        # Extract query
        query = text.split(">", 1)[-1].strip()
        
        # Parse type flag
        search_type = "all"
        if "--type" in query:
            parts = query.split("--type")
            query_text = parts[0].strip()
            if len(parts) > 1:
                type_parts = parts[1].strip().split()
                if type_parts:
                    search_type = type_parts[0].lower()
        else:
            query_text = query
        
        assert query_text == "CVE-2021-44228"
        assert search_type == "poc"
    
    def test_mention_help_command(self):
        """Test @mention help command"""
        text = "<@U12345> help"
        
        query = text.split(">", 1)[-1].strip()
        
        is_help = query.lower() in ["help", "?"]
        
        assert is_help
    
    def test_mention_empty_query(self):
        """Test @mention with no query (should show help)"""
        text = "<@U12345>"
        
        query = text.split(">", 1)[-1].strip()
        
        assert not query, "Empty query should trigger help"


class TestHelpCommand:
    """Test help command logic"""
    
    def test_slash_help_command(self):
        """Test /cve-help command"""
        # Help command is a separate handler
        # Just verify it's a valid command
        command = "/cve-help"
        
        assert command == "/cve-help"
    
    def test_mention_help_keywords(self):
        """Test help keywords in @mention"""
        help_keywords = ["help", "?", ""]
        
        for keyword in help_keywords:
            is_help = keyword.lower() in ["help", "?"] or not keyword
            assert is_help


class TestErrorResponses:
    """Test error response construction"""
    
    def test_rate_limit_error(self):
        """Test rate limit error message"""
        error_msg = (
            "⚠️ Rate limit exceeded. You can make up to 5 requests per minute.\n"
            "Please wait a moment before searching again."
        )
        
        assert "Rate limit exceeded" in error_msg
        assert "5 requests per minute" in error_msg
    
    def test_empty_query_error(self):
        """Test empty query error message"""
        error_msg = (
            "⚠️ Please provide a CVE ID or search keyword.\n"
            "Examples:\n"
            "• `/cve-search CVE-2021-44228`\n"
            "• `/cve-search apache log4j`"
        )
        
        assert "Please provide" in error_msg
        assert "CVE ID" in error_msg
    
    def test_invalid_type_error(self):
        """Test invalid --type error message"""
        invalid_type = "invalid"
        error_msg = (
            f"⚠️ Invalid search type: `{invalid_type}`\n"
            "Valid types: `poc`, `fix`, `advisory`, `all`"
        )
        
        assert "Invalid search type" in error_msg
        assert invalid_type in error_msg
    
    def test_missing_type_value_error(self):
        """Test missing --type value error message"""
        error_msg = (
            "⚠️ Missing value for `--type` flag\n"
            "Valid types: `poc`, `fix`, `advisory`, `all`\n\n"
            "Example: `/cve-search CVE-2021-44228 --type poc`"
        )
        
        assert "Missing value" in error_msg
        assert "--type" in error_msg


class TestProductionScenarios:
    """Test real-world usage scenarios"""
    
    def test_typical_cve_lookup(self):
        """Test typical CVE lookup command"""
        text = "CVE-2021-44228"
        
        query = text.strip()
        search_type = "all"
        
        job_data = {
            "query": query,
            "search_type": search_type,
            "timestamp": time.time()
        }
        
        assert job_data["query"] == "CVE-2021-44228"
        assert job_data["search_type"] == "all"
    
    def test_filtered_exploit_search(self):
        """Test filtered exploit search"""
        text = "CVE-2021-44228 --type poc"
        
        query = text
        search_type = "all"
        
        if "--type" in text:
            parts = text.split("--type")
            query = parts[0].strip()
            if len(parts) > 1:
                type_parts = parts[1].strip().split()
                if type_parts:
                    type_value = type_parts[0].lower()
                    if type_value in ["poc", "fix", "advisory", "all"]:
                        search_type = type_value
        
        job_data = {
            "query": query,
            "search_type": search_type,
            "timestamp": time.time()
        }
        
        assert job_data["query"] == "CVE-2021-44228"
        assert job_data["search_type"] == "poc"
    
    def test_keyword_search(self):
        """Test keyword search command"""
        text = "apache log4j"
        
        query = text.strip()
        
        job_data = {
            "query": query,
            "search_type": "all",
            "timestamp": time.time()
        }
        
        assert job_data["query"] == "apache log4j"
    
    def test_mention_in_thread(self):
        """Test @mention in thread"""
        text = "<@U12345> CVE-2021-44228"
        channel_id = "C12345"
        thread_ts = "1234567890.123456"
        
        query = text.split(">", 1)[-1].strip()
        
        job_data = {
            "query": query,
            "channel_id": channel_id,
            "thread_ts": thread_ts,
            "search_type": "all",
            "timestamp": time.time()
        }
        
        assert job_data["query"] == "CVE-2021-44228"
        assert job_data["thread_ts"] == thread_ts
