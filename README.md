## Demo


https://github.com/user-attachments/assets/6b7763a1-6a5e-45d1-992c-0647ba3e4471



*Demo showing exact CVE queries, keyword searches, resource links and overview of CVE's*

# Slack CVE Bot - MCP Implementation

A production-ready Slack bot for CVE research using the Model Context Protocol (MCP), Docker, Redis, and Python.

## Key Features

### 🚨 Instant Exploit Detection & NVD Data Quality Solutions
**Advanced Reference Classification** - Handles incomplete NVD data with heuristic URL-based classification:
- **🚨 Exploit**: Public exploits available (immediate threat)
- **🔧 Patch/Fix**: Vendor patches, fixes, and mitigations
- **📰 Advisory**: Security advisories (Vendor + Third Party)
- **🚨 CISA KEV**: Known Exploited Vulnerabilities (actively exploited in the wild)
- **🔗 Auto-classified**: Heuristic classification when NVD tags missing (~85% accuracy)

**Key Features**:
- **Slack Block Kit UI**: Rich interactive messages with headers, sections, and formatted blocks
- **Refined Categorization**: URL-based heuristics distinguish exploits from advisories (no more false positives)
- **NVD Order Preservation**: References shown in chronological order (respects NVD's semantic ordering)
- **URL Sanitization**: Properly escaped URLs prevent Slack link formatting issues
- **Multi-Category Support**: References can belong to multiple categories
- **CWE Display**: Shows vulnerability weakness type (CWE-79: XSS, CWE-89: SQLi, etc.)
- **NVD Crisis Resilient**: Works with 60-70% of new CVEs having incomplete tags (since Feb 2024)
- **Transparency**: Auto-classified refs clearly labeled, data quality warnings shown
- **Robust Input Handling**: Graceful error messages for invalid --type flags

**Example** (Slack Block Kit format):
```
🔴 CVE-2021-44228
CRITICAL (CVSS 10.0) • 🚨 ACTIVELY EXPLOITED (CISA KEV)

Description
Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features do not protect...

Weakness Types
CWE-20, CWE-400, CWE-502

Published: 2021-12-10

🚨 CISA Known Exploited Vulnerability
Added to KEV: 2021-12-10
Remediation Due: 2021-12-24
Ransomware Use: Known

🚨 Exploits & PoCs (showing 5 of 47)
• packetstormsecurity.com/files/165270/...Remote-Code-Execution.html (inferred)
• github.com/christophetd/log4shell-vulnerable-app (inferred)
...

🔧 Patches & Fixes (showing 5 of 6)
• msrc-blog.microsoft.com/2021/12/11/microsofts-response...
• oracle.com/security-alerts/cpuapr2022.html
...

📰 Security Advisories (showing 5 of 28)
• nvd.nist.gov/vuln/detail/CVE-2021-44228
• github.com/advisories/GHSA-jfh8-c2jp-5v3q
...

💻 GitHub Resources (475 found)
• fullhunt/log4j-scan (3433 ⭐)
• NCSC-NL/log4shell (1892 ⭐)
...

Risk Assessment
🚨 Critical severity. Immediate patching required.
```

**Filtering**: Use `--type poc`, `--type fix`, or `--type advisory` to filter results by category

---

## Architecture

```
Slack User → Slack Bot (Socket Mode)
         ↓
    Redis Queue (FIFO)
         ↓
    Worker Service (2 replicas)
         ↓
    MCP Server (rate-limited, sandboxed)
         ↓
    External APIs (NIST NVD, GitHub)
         ↓
    Python Formatter
         ↓
    Slack Webhook Response
```

### Services

- **slack-bot**: Socket Mode handler, slash command processor
- **redis**: Job queue with persistence
- **worker** (2x): Job consumers with MCP client
- **mcp-server**: FastMCP with 3 tools + rate limiting

## Features

1. **Slack Bot** (slack-bolt 1.27.0)
   - Socket Mode for real-time event handling
   - `/cve-search` slash command
   - @mention support with CVE query parsing
   - Default help command when @mentioned without query
   - Support for --type filters in @mentions
   - Redis job queue integration
   - Automatic response_url capture for webhook delivery

2. **MCP Server** (FastMCP 2.13.0.2)
   - 4 async tools:
     - `lookup_cve_details`: NVD data with heuristic classification
     - `search_github_cve_repos`: GitHub PoC/exploit repos
     - `search_cve_by_keyword`: NVD keyword search
     - `check_cisa_kev_details`: CISA KEV catalog metadata (optional)
   - Streamable HTTP transport on port 8080 (`/mcp` endpoint)
   - **API rate limiting**: Automatic throttling based on API key presence
     - NVD: 50 req/30s (with key) or 5 req/30s (without)
     - GitHub: 5000 req/hour (with token) or 60 req/hour (without)
   - **GitHub rate limit monitoring**: Proactive warnings when < 10 requests remaining
   - **Refined heuristic classification**: Path-aware exploit detection
     - Distinguishes exploit code from advisory pages on same platform (e.g., PacketStorm)
     - Advisory URL exclusion prevents false positives
     - No longer filters legitimate security bulletins as exploits
   - **NVD order preservation**: Returns all references in original NVD order
   - **URL deduplication**: Prevents duplicate references from different NVD sources
   - **CISA KEV detection**: Checks all refs for active exploitation indicators (95%+ accuracy)
   - **CWE display**: Shows vulnerability weakness types
   - Security: non-root user (uid 1000), read-only filesystem, capabilities dropped

3. **Worker Service** (2 replicas)
   - Redis job consumer with exponential backoff retry
   - Resilient Redis connection (1s, 2s, 4s, 8s, 16s retry delays)
   - Query dispatcher (auto-detects CVE ID vs keyword)
   - FastMCP Client with Streamable HTTP support
   - Pure Python formatting (deterministic, no AI APIs)
   - **Slack Block Kit formatting**: Rich interactive messages with headers, sections, dividers
   - **URL sanitization**: Escaped special characters prevent Slack link issues
   - **Reference categorization**: Shows up to 5 exploits, 5 patches, 5 advisories per CVE
   - **NVD order preservation**: References displayed in chronological order
   - **Instant threat assessment** via reference type emojis (🚨 Exploit, 🔧 Patch, 📰 Advisory)
   - **CISA KEV metadata display** (date added, due dates, ransomware use)
   - **Dual delivery system**: Webhook (slash commands) + Slack Web API (@mentions)
   - Graceful error handling for CISA API failures and invalid user input

4. **Redis** (version 7-alpine)
   - Persistence enabled (appendonly yes)
   - Health checks configured
   - Backend network isolation

5. **Docker Infrastructure**
   - 3 isolated networks: `frontend` (Slack bot), `backend` (Redis), `mcp-isolated` (MCP server)
   - Resource limits: 256-512MB RAM, 0.25-0.5 CPU per service
   - Security policies: no-new-privileges, capability dropping
   - Health checks for all critical services

## Getting Started

**1. Start all services:**
```bash
docker-compose up -d
```

**2. Check service status:**
```bash
docker-compose ps
docker-compose logs mcp-server worker redis slack-bot
```

**3. Use in Slack:**
```
/cve-search CVE-2021-44228
/cve-search apache log4j
@CVE Research Bot help
```

**4. Test with manual job (optional):**
```bash
docker exec slack-mcp-redis-1 redis-cli LPUSH mcp_jobs \
  '{"query": "CVE-2021-44228", "user_id": "test", "response_url": "http://test.com/webhook"}'
```

**5. View worker logs:**
```bash
docker logs slack-mcp-worker-1 --tail 50
docker logs slack-mcp-worker-2 --tail 50
```

## Optional Langfuse Tracing

The worker can emit Langfuse traces without changing default app behavior. This is off by default.

Add these values to `.env` before starting or rebuilding the worker:

```bash
LANGFUSE_ENABLED=true
LANGFUSE_PUBLIC_KEY=pk-lf-...
LANGFUSE_SECRET_KEY=sk-lf-...
LANGFUSE_BASE_URL=http://host.docker.internal:3000
LANGFUSE_DISABLE_TELEMETRY=true
```

Notes:

- Docker Desktop usually supports `host.docker.internal`.
- On Linux Docker Engine, you may need an `extra_hosts` host-gateway mapping or you can run Langfuse as another Compose service instead.
- The worker derives a deterministic Langfuse trace ID from the queued `job_id`, so the queue correlation key stays platform-neutral.
- When `LANGFUSE_ENABLED=false`, the worker keeps using the local trace scaffold only.

Rebuild and start the worker after changing dependencies or env vars:

```bash
docker compose up -d --build worker
docker compose logs -f worker
```

If Langfuse is configured correctly, the worker will log:

```text
✅ Langfuse tracing enabled
```

## Example Output

**CVE Lookup (`CVE-2021-44228`):**
```
🔴 **CRITICAL**: CVE-2021-44228 🚨 *ACTIVELY EXPLOITED (CISA KEV)*

📋 **Summary**
Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features do not protect...

📊 **Details**
• CVSS Score: 10.0
• Weakness: CWE-20, CWE-400, CWE-502
• Published: 2021-12-10
• Last Modified: 2025-10-27

⚠️ *CISA KEV Details*
• Added to KEV: 2021-12-10
• Remediation Due: 2021-12-24
• Ransomware Use: Known
• Action Required: Apply updates per vendor instructions

🔗 **References**
• 🚨 Exploit: http://packetstormsecurity.com/files/165261/Apache-Log4j2-2.14.1-Information-Disclosure.html
• 🚨 Exploit: http://packetstormsecurity.com/files/165270/Apache-Log4j2-2.14.1-Remote-Code-Execution.html
• 🚨 Exploit: http://packetstormsecurity.com/files/165371/VMware-Security-Advisory-2021-0028.4.html
• 🚨 Exploit: http://packetstormsecurity.com/files/165532/Log4Shell-HTTP-Header-Injection.html
• 🚨 Exploit: http://packetstormsecurity.com/files/165642/VMware-vCenter-Server-Unauthenticated-Log4Shell-JNDI-Injection-Remote-Code-Execution.html

🐙 **GitHub Resources** (474 total)
• fullhunt/log4j-scan (3434 ⭐)
• NCSC-NL/log4shell (1892 ⭐)

⚠️ **Risk Assessment**
🚨 Critical severity. Immediate patching required.

🔍 Full details: https://nvd.nist.gov/vuln/detail/CVE-2021-44228
```

**Keyword Search (`apache log4j`):**
```
🔍 **CVE Search Results**: `apache log4j`
Found 16 CVEs (showing top 10):

🔴 **CVE-2021-44228** (CVSS: 10.0)
   Apache Log4j2 2.0-beta9 through 2.15.0...

🟠 **CVE-2021-45046** (CVSS: 9.0)
   Fix to address CVE-2021-44228 was incomplete...

💡 Use `/cve-search CVE-2021-44228` for detailed info
```

## Environment Variables

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

**Required (Phase 1):**
- `REDIS_URL=redis://redis:6379`
- `MCP_SERVER_URL=http://mcp-server:8080`
- `TEST_MODE=true` (console output) or `false` (Slack webhooks)

**For Production (Slack Integration):**
- `SLACK_BOT_TOKEN=xoxb-...` (Bot User OAuth Token from api.slack.com/apps)
- `SLACK_APP_TOKEN=xapp-...` (App-Level Token with connections:write scope)
- `SLACK_SIGNING_SECRET=...` (Signing Secret from Basic Information)
- `NVD_API_KEY=...` (NIST NVD API key for higher rate limits)
- `GITHUB_TOKEN=...` (GitHub personal access token for higher rate limits)

## Setting Up Slack Bot

| Component | Technology | Version |
|-----------|-----------|---------|
| Language | Python | 3.11 |
| Slack SDK | slack-bolt | 1.27.0 |
| MCP Framework | FastMCP | 2.13.0.2 |
| MCP SDK (worker) | FastMCP Client | 2.13.0.2+ |
| HTTP Client | httpx | 0.28.1 |
| Redis Client | redis-py | 7.0.1 |
| Job Queue | Redis | 7-alpine |
| Containerization | Docker Compose | 3.8 |
| CVE Data Source | NIST NVD API | 2.0 |
| Code Search | GitHub REST API | v3 |
| Transport | Streamable HTTP / Socket Mode | - |

## Security Features

### Container Security & Sandboxing
- ✅ **Network Isolation**: Three-tier network architecture (frontend, backend, mcp-isolated)
  - MCP server in isolated network with no direct external access
  - Redis backend network isolated from Slack bot frontend
  - Principle of least privilege for inter-service communication
- ✅ **Container Hardening**: 
  - Non-root users (uid 1000) in all containers
  - Read-only root filesystem on MCP server
  - Dropped capabilities (`cap_drop: [ALL]`)
  - `no-new-privileges` security option enabled
  - Minimal Alpine/Slim base images reducing attack surface
- ✅ **Resource Controls**: Memory (256-512MB) and CPU (0.25-0.5 cores) limits prevent resource exhaustion

### Application Security
- ✅ **Input Validation & Sanitization**:
  - CVE ID format validation (`CVE-YYYY-NNNN+` pattern)
  - URL sanitization prevents Slack injection attacks
  - Markdown escape handling for user-controlled content
- ✅ **Secrets Management**:
  - No hardcoded credentials in code or Dockerfiles
  - Environment variable-based configuration
  - `.gitignore` protection for `.env` files
- ✅ **API Security**:
  - Rate limiting with automatic throttling (NVD: 50 req/30s, GitHub: 5000 req/hr)
  - Slack request signature verification
  - GitHub token authentication with rate limit monitoring
  - NVD API key support for enhanced rate limits

### MCP Server Isolation (OWASP MCP Best Practices)
- ✅ **Sandboxed Execution**: MCP server runs in isolated Docker network with restricted egress
- ✅ **Principle of Least Privilege**: Read-only filesystem, dropped capabilities, non-root execution
- ✅ **No Shell Access**: Python-based server without shell command execution
- ✅ **Controlled External API Access**: Only NIST NVD and GitHub APIs (no arbitrary HTTP requests)
- ✅ **Stateless Design**: No persistent storage requirements, ephemeral container lifecycle

### Additional Security Measures
- ✅ **Error Handling**: Graceful failures prevent information disclosure
- ✅ **Logging**: Audit trail of all CVE lookups and API calls
- ✅ **Health Checks**: Automatic service monitoring and restart on failure
- ✅ **Redis Persistence**: Append-only file (AOF) with data durability

## Setting Up Slack Bot

1. **Create Slack App** at https://api.slack.com/apps
   - Click "Create New App" → "From scratch"
   - Name it "CVE Research Bot" and choose your workspace

2. **Enable Socket Mode**
   - Go to "Socket Mode" in the sidebar
   - Enable Socket Mode
   - Generate an App-Level Token with `connections:write` scope
   - Save this as `SLACK_APP_TOKEN`

3. **Configure OAuth & Permissions**
   - Go to "OAuth & Permissions"
   - Add Bot Token Scopes:
     - `chat:write` - Send messages
     - `commands` - Use slash commands
     - `app_mentions:read` - Read @mentions
   - Install app to workspace
   - Copy the "Bot User OAuth Token" as `SLACK_BOT_TOKEN`

4. **Get Signing Secret**
   - Go to "Basic Information"
   - Copy the "Signing Secret" as `SLACK_SIGNING_SECRET`

5. **Create Slash Command**
   - Go to "Slash Commands"
   - Create command `/cve-search`
   - Request URL can be anything (Socket Mode doesn't use it)
   - Description: "Search for CVE information"
   - Usage hint: `CVE-2021-44228` or `apache log4j`

6. **Update .env file**
   ```bash
   SLACK_BOT_TOKEN=xoxb-your-token
   SLACK_APP_TOKEN=xapp-your-token
   SLACK_SIGNING_SECRET=your-secret
   TEST_MODE=false  # Enable webhook delivery
   ```

7. **Start all services**
   ```bash
   docker-compose up -d
   ```

**Usage in Slack:**

```
/cve-search CVE-2021-44228
/cve-search apache log4j
@CVE Research Bot help
```

## Testing

### Unit Tests

The project includes a comprehensive test suite covering critical heuristics and formatters:

```bash
cd tests
pip install -r requirements.txt
pytest
```

**Test Coverage:**
- **Heuristic Classification** (18 tests): Exploit detection, advisory URL exclusion, patch detection
- **URL Sanitization** (17 tests): Slack escaping, XSS prevention, markdown injection
- **Block Kit Formatters** (18 tests): Reference filtering, deduplication, Block generation
- **Total**: 54 tests, all passing ✅

**Key Tests:**
```bash
# Test PacketStorm advisory filtering (Round 8 bug fix)
pytest tests/test_heuristics.py::TestExploitDetection::test_packetstorm_advisory_urls_excluded -v

# Test URL sanitization
pytest tests/test_sanitization.py::TestURLSanitization -v

# Test reference filtering by type
pytest tests/test_formatters.py::TestReferenceFiltering -v
```

## Development

**Build all services:**
```bash
docker-compose build
```

**Start in detached mode:**
```bash
docker-compose up -d
```

**View logs:**
```bash
docker-compose logs -f worker
```

**Stop all services:**
```bash
docker-compose down
```

**Clean volumes:**
```bash
docker-compose down -v
```

## License

MIT

## Attribution

**NVD API Usage**: This product uses the NVD API but is not endorsed or certified by the NVD.

The NVD API is intended to be used to develop services to search, display, analyze, retrieve, view and otherwise "get" information from NVD data. Services which utilize or access the NVD API are asked to display the above notice prominently within the application.
