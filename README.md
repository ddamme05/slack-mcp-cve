# Slack CVE Bot - MCP Implementation

A production-ready Slack bot for CVE research using the Model Context Protocol (MCP), Docker, Redis, and Python.

## Project Status

- ✅ **Phase 1: Core Infrastructure** - COMPLETE (Bug fixes applied)
- ✅ **Phase 1.5: Reference Type Classification** - COMPLETE (Exploit detection)
- ⏳ **Phase 2: Slack Integration** - Pending

**📋 See [FEEDBACK_TRACKING.md](FEEDBACK_TRACKING.md) for Phase 1 bug fixes**
**📋 See [FEEDBACK_ANALYSIS_ROUND2.md](FEEDBACK_ANALYSIS_ROUND2.md) for enhancement analysis**

## Key Features

### 🚨 Instant Exploit Detection
**Reference Type Classification** - Automatically identifies and labels CVE references by type:
- **🚨 Exploit**: Public exploits available (immediate threat)
- **🔧 Patch/Fix**: Vendor patches and fixes
- **🛡️ Mitigation**: Workarounds and mitigations
- **📰 Advisory**: Security advisories

**Example**:
```
🔗 **References**
• 🚨 Exploit: http://packetstormsecurity.com/files/165261/...
• 🚨 Exploit: http://packetstormsecurity.com/files/165270/...
```

---

## Architecture

```
Slack User → Slack Bot (Socket Mode) 
         ↓
    Redis Queue (FIFO) 
         ↓
    Worker Service (2 replicas) 
         ↓
    MCP Server (sandboxed Docker container) 
         ↓
    External APIs (NIST NVD, GitHub) 
         ↓
    Python Formatter
         ↓
    Slack Webhook Response
```

## Phase 1: What's Working

### Core Components

1. **MCP Server** (FastMCP 2.13.0.2)
   - 3 async tools: `lookup_cve_details`, `search_github_cve_repos`, `search_cve_by_keyword`
   - Streamable HTTP transport on port 8080 (`/mcp` endpoint)
   - **Reference type classification**: Automatic exploit/patch/advisory detection from NVD tags
   - Security: non-root user (uid 1000), read-only filesystem, capabilities dropped

2. **Worker Service** (2 replicas)
   - Redis job consumer (BRPOP blocking queue)
   - Query dispatcher (auto-detects CVE ID vs keyword)
   - FastMCP Client with Streamable HTTP support
   - Pure Python formatting (deterministic, no AI APIs)
   - **Instant threat assessment** via reference type emojis (🚨 Exploit, 🔧 Patch, 📰 Advisory)

3. **Redis** (version 7-alpine)
   - Persistence enabled (appendonly yes)
   - Health checks configured
   - Backend network isolation

4. **Docker Infrastructure**
   - 3 isolated networks: `frontend`, `backend`, `mcp-isolated`
   - Resource limits: 512MB RAM, 0.5 CPU per service
   - Security policies: no-new-privileges, capability dropping

### Testing Phase 1

**1. Start all services:**
```bash
docker-compose up -d
```

**2. Check service status:**
```bash
docker-compose ps
docker-compose logs mcp-server worker redis
```

**3. Test CVE ID lookup:**
```bash
docker exec slack-mcp-redis-1 redis-cli LPUSH mcp_jobs \
  '{"query": "CVE-2021-44228", "user_id": "test", "response_url": "http://test.com/webhook"}'
```

**4. Test keyword search:**
```bash
docker exec slack-mcp-redis-1 redis-cli LPUSH mcp_jobs \
  '{"query": "CrowdStrike", "user_id": "test", "response_url": "http://test.com/webhook"}'
```

**5. View results (TEST_MODE=true):**
```bash
docker logs slack-mcp-worker-1 --tail 50
docker logs slack-mcp-worker-2 --tail 50
```

**6. Test webhook delivery (TEST_MODE=false):**
```bash
# Edit .env: TEST_MODE=false
# Restart workers
docker-compose restart worker

# Inject job with httpbin webhook for testing
docker exec slack-mcp-redis-1 redis-cli LPUSH mcp_jobs \
  '{"query": "CVE-2024-1234", "user_id": "test", "response_url": "https://httpbin.org/post"}'

# Check webhook was sent
docker logs slack-mcp-worker-1 | grep "sent to Slack"
```

### Example Output

**CVE Lookup (`CVE-2021-44228`):**
```
🔴 **CRITICAL**: CVE-2021-44228

📋 **Summary**
Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features do not protect...

📊 **Details**
• CVSS Score: 10.0
• Published: 2021-12-10
• Last Modified: 2025-10-27

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

**For Phase 2:**
- `SLACK_BOT_TOKEN=xoxb-...` (from api.slack.com/apps)
- `SLACK_APP_TOKEN=xapp-...` (Socket Mode token)

### Worker Modes

The worker supports two modes via `TEST_MODE` environment variable:

**Phase 1 Testing (`TEST_MODE=true`):**
- Prints formatted reports to console/logs
- No external HTTP calls
- Perfect for development and testing

**Phase 2 Production (`TEST_MODE=false`):**
- Sends formatted reports to Slack via webhook
- Requires valid `response_url` in job data
- Logs success/failure of webhook delivery

**Webhook Testing with httpbin:**
```bash
# Set TEST_MODE=false in .env
TEST_MODE=false

# Inject job with httpbin webhook
docker exec slack-mcp-redis-1 redis-cli LPUSH mcp_jobs \
  '{"query": "CVE-2021-44228", "user_id": "test", "response_url": "https://httpbin.org/post"}'

# Check worker processed and sent to webhook
docker logs slack-mcp-worker-1
```

## Technology Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| Language | Python | 3.11 |
| MCP Framework | FastMCP | 2.13.0.2 |
| MCP SDK (worker) | FastMCP Client | 2.13.0.2+ |
| HTTP Client | httpx | 0.28.1 |
| Redis Client | redis-py | 7.0.1 |
| Job Queue | Redis | 7-alpine |
| Containerization | Docker Compose | 3.8 |
| CVE Data Source | NIST NVD API | 2.0 |
| Code Search | GitHub REST API | v3 |
| Transport | Streamable HTTP | - |

## Security Features

- ✅ Docker network isolation (3 tiers)
- ✅ Non-root users in all containers (uid 1000)
- ✅ Read-only filesystems (MCP server)
- ✅ Input validation (CVE format: `CVE-YYYY-NNNN+`)
- ✅ Resource limits (CPU: 0.5, Memory: 512MB)
- ✅ No hardcoded secrets (environment variables)
- ✅ Capability dropping (cap_drop: [ALL])
- ✅ No-new-privileges security option

## Next Steps (Phase 2)

- [ ] Implement Slack bot with Socket Mode
- [ ] Add `/cve-search` slash command handler
- [ ] Connect bot to existing job queue
- [ ] Test end-to-end with real Slack workspace
- [ ] Add error handling for Slack API failures
- [ ] Implement rate limiting for NVD/GitHub APIs

## Project Structure

```
slack-cve-bot/
├── mcp-server/          # FastMCP with 3 tools ✅
│   ├── server.py
│   ├── requirements.txt
│   └── Dockerfile
├── worker/              # Redis consumer + formatter ✅
│   ├── worker.py
│   ├── requirements.txt
│   └── Dockerfile
├── slack-bot/           # Slack Socket Mode (Phase 2)
├── docker-compose.yml   # Multi-service orchestration ✅
├── .env.example         # Environment template ✅
├── .env                 # Secrets (gitignored) ✅
├── .gitignore           # Security exclusions ✅
└── README.md            # This file
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