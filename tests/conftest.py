"""
Shared test fixtures and data for Slack CVE Bot tests
"""
import pytest


@pytest.fixture
def sample_nvd_reference():
    """Sample NVD reference structure"""
    return {
        "url": "https://example.com/advisory",
        "source": "example.com",
        "tags": ["Third Party Advisory"],
        "categories": ["advisory"],
        "type": "📰 Third Party Advisory",
        "priority": 3,
        "nvd_tagged": True
    }


@pytest.fixture
def exploit_urls():
    """Collection of URLs that should be classified as exploits"""
    return [
        # Exploit-DB
        "https://www.exploit-db.com/exploits/50337",

        # PacketStorm exploits
        "https://packetstormsecurity.com/files/165270/Apache-Log4j2-Remote-Code-Execution.html",
        "https://packetstormsecurity.com/files/165261/Apache-Log4j2-Information-Disclosure.html",
        "http://packetstormsecurity.com/files/165532/Log4Shell-HTTP-Header-Injection.html",

        # Metasploit
        "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploit/multi/http/log4shell.rb",

        # PoC repositories
        "https://github.com/kozmer/log4j-shell-poc",
        "https://github.com/christophetd/log4shell-vulnerable-app",

        # RCE indicators
        "https://example.com/remote-code-execution-poc",
        "https://example.com/rce-exploit",
        "https://example.com/code-execution-demo",

        # Generic exploit patterns
        "https://example.com/exploit-analysis",
        "https://example.com/poc-demonstration",
        "https://example.com/payload-delivery",
        "https://example.com/shell-access"
    ]


@pytest.fixture
def advisory_urls():
    """Collection of URLs that should be classified as advisories (NOT exploits)"""
    return [
        # PacketStorm advisories (should NOT be tagged as exploits)
        "https://packetstormsecurity.com/files/165260/VMware-Security-Advisory-2021-0028.html",
        "https://packetstormsecurity.com/files/165280/Apache-Log4j2-Security-Advisory.html",

        # Vendor advisories
        "https://www.microsoft.com/security-advisory/CVE-2021-44228",
        "https://www.oracle.com/security-alerts/cpuapr2022.html",
        "https://access.redhat.com/security/cve/CVE-2021-44228",

        # Security bulletins
        "https://example.com/security-bulletin/2021-001",
        "https://example.com/advisory/log4j-vulnerability",

        # NVD and MITRE
        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228",

        # GitHub security advisories
        "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",

        # Mailing lists
        "https://www.openwall.com/lists/oss-security/2021/12/10/1",
        "https://seclists.org/fulldisclosure/2022/Jul/11"
    ]


@pytest.fixture
def patch_urls():
    return [
        # GitHub commits
        "https://github.com/apache/logging-log4j2/commit/44569090f1cf1e92c711fb96dfd18cd7dccc72ea",
        "https://github.com/spring-projects/spring-boot/commit/0cf933c",

        # GitHub pull requests
        "https://github.com/apache/logging-log4j2/pull/608",

        # Vendor patches
        "https://logging.apache.org/log4j/2.x/security.html",
        "https://msrc-blog.microsoft.com/2021/12/11/microsofts-response-to-cve-2021-44228-apache-log4j2/",

        # Direct patch files
        "https://example.com/patches/CVE-2021-44228.patch",
        "https://example.com/diff/log4j-fix.diff"
    ]


@pytest.fixture
def special_character_urls():
    """URLs with special characters that need sanitization"""
    return [
        # Ampersands (query params)
        "https://example.com/page?foo=bar&baz=qux&test=1",

        # Angle brackets (rare but possible)
        "https://example.com/path<script>alert(1)</script>",

        # Pipe characters (Slack markdown conflict)
        "https://example.com/path|with|pipes",

        # Mixed special characters
        "https://example.com/page?a=1&b=2<test>|pipe",

        # Credentials in URL (should be handled gracefully)
        "https://user:pass@example.com/path",

        # Very long URLs
        "https://example.com/" + "a" * 200,

        # Empty/invalid URLs
        "",
        "   ",
        "not-a-url",
        "javascript:alert(1)"
    ]


@pytest.fixture
def sample_cve_data():
    """Sample CVE data structure from NVD"""
    return {
        "cve_id": "CVE-2021-44228",
        "description": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "published_date": "2021-12-10T10:15:09.253",
        "last_modified": "2023-11-25T11:15:18.697",
        "cwe": ["CWE-20", "CWE-400", "CWE-502"],
        "is_kev": True,
        "references": []  # Will be populated in tests
    }


@pytest.fixture
def sample_github_data():
    """Sample GitHub search results"""
    return {
        "cve_id": "CVE-2021-44228",
        "search_type": "all",
        "total_found": 475,
        "repositories": [
            {
                "name": "fullhunt/log4j-scan",
                "description": "A fully automated, accurate, and extensive scanner for finding log4j RCE CVE-2021-44228",
                "stars": 3434,
                "url": "https://github.com/fullhunt/log4j-scan",
                "updated": "2023-01-15T12:00:00Z"
            },
            {
                "name": "NCSC-NL/log4shell",
                "description": "Operational information regarding the log4shell vulnerabilities in the Log4j logging library.",
                "stars": 1892,
                "url": "https://github.com/NCSC-NL/log4shell",
                "updated": "2023-01-10T12:00:00Z"
            }
        ]
    }


@pytest.fixture
def sample_kev_data():
    """Sample CISA KEV data"""
    return {
        "is_kev": True,
        "cve_id": "CVE-2021-44228",
        "vulnerability_name": "Apache Log4j2 Remote Code Execution Vulnerability",
        "date_added": "2021-12-10",
        "due_date": "2021-12-24",
        "known_ransomware_use": "Known",
        "short_description": "Apache Log4j2 contains a remote code execution vulnerability.",
        "required_action": "Apply updates per vendor instructions."
    }


@pytest.fixture
def complete_cve_response():
    """Complete CVE response with all reference types"""
    return {
        "cve_id": "CVE-2021-44228",
        "description": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration do not protect against attacker controlled LDAP endpoints.",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "published_date": "2021-12-10T10:15:09.253",
        "last_modified": "2023-11-25T11:15:18.697",
        "cwe": ["CWE-20", "CWE-400", "CWE-502"],
        "is_kev": True,
        "references": [
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
                "url": "https://github.com/kozmer/log4j-shell-poc",
                "source": "github.com",
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
                "url": "https://logging.apache.org/log4j/2.x/security.html",
                "source": "apache.org",
                "tags": ["Vendor Advisory", "Patch"],
                "categories": ["advisory", "fix"],
                "type": "🔧 Vendor Advisory",
                "priority": 2,
                "nvd_tagged": True
            },
            {
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities",
                "source": "cisa.gov",
                "tags": ["US Government Resource"],
                "categories": ["advisory"],
                "type": "📰 US Government Advisory",
                "priority": 3,
                "nvd_tagged": True
            },
            {
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                "source": "nvd.nist.gov",
                "tags": ["VDB Entry"],
                "categories": [],
                "type": "🔗 VDB Entry",
                "priority": 4,
                "nvd_tagged": True
            }
        ]
    }


@pytest.fixture
def job_payload_slash_command():
    """Sample job payload from slash command"""
    import time
    return {
        "query": "CVE-2021-44228",
        "search_type": "all",
        "user_id": "U12345",
        "response_url": "https://hooks.slack.com/commands/...",
        "timestamp": time.time()
    }


@pytest.fixture
def job_payload_mention():
    """Sample job payload from @mention"""
    import time
    return {
        "query": "CVE-2021-44228",
        "search_type": "poc",
        "user_id": "U12345",
        "channel_id": "C12345",
        "thread_ts": "1234567890.123456",
        "timestamp": time.time()
    }


@pytest.fixture
def mcp_error_response():
    return {
        "error": "CVE not found",
        "cve_id": "CVE-9999-9999"
    }


@pytest.fixture
def empty_github_response():
    return {
        "cve_id": "CVE-2021-44228",
        "search_type": "all",
        "total_found": 0,
        "repositories": []
    }
