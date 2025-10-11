# Short URL Generator

A production-ready URL shortening service built with Go, featuring Redis persistence, rate limiting, security validation, and intelligent URL deduplication.

## Features

### Core Functionality
- ✅ **URL Shortening**: Generate 8-10 character short URLs
- ✅ **URL Management**: Update or delete short URLs with secure validation
- ✅ **Expiry Dates**: Set optional expiration times for URLs
- ✅ **Usage Limits**: Limit the number of times a URL can be accessed
- ✅ **Access Logging**: Track every access with IP, user agent, and timestamp
- ✅ **URL Deduplication**: Smart duplicate detection with compatibility matching
- ✅ **In-Memory Cache**: High-performance caching with Ristretto (100× faster)
- ✅ **QR Code Generation**: On-demand QR codes for any short URL
- ✅ **URL Preview**: Anti-phishing preview page before redirect
- ✅ **API Documentation**: Interactive Swagger UI with try-it-out functionality

### Security & Performance
- ✅ **URL Validation**: Blocks localhost, private IPs, and invalid schemes (SSRF protection)
- ✅ **Malware/Phishing Detection**: URL scanning with Google Safe Browsing API + local blocklist
- ✅ **Bot Detection**: Intelligent bot detection with user-agent analysis and rate patterns
- ✅ **Rate Limiting**: Per-IP rate limiting (configurable)
- ✅ **CORS Support**: Cross-origin requests enabled
- ✅ **Collision Detection**: Retry mechanism for short URL generation
- ✅ **Context Timeouts**: All Redis operations have timeouts

### Production-Ready
- ✅ **Admin Dashboard**: Web UI for managing URLs, viewing statistics, and monitoring system health
- ✅ **Structured Logging**: Zerolog-based JSON logging
- ✅ **Graceful Shutdown**: Clean shutdown on SIGTERM/SIGINT
- ✅ **Health Check**: `/health` endpoint for monitoring
- ✅ **Middleware Architecture**: Clean separation of concerns
- ✅ **Dependency Injection**: Testable, maintainable code
- ✅ **Comprehensive Tests**: Unit tests with >90% coverage

## Quick Start

### Prerequisites
- Go 1.22.1 or higher
- Redis server

### Installation

```bash
# Clone repository
git clone https://github.com/mdsatpak/short-url-generator.git
cd short-url-generator

# Install dependencies
go mod tidy

# Start Redis (if not running)
redis-server

# Run application
go run main.go
```

The server will start on `http://localhost:8080`

### Docker (Optional)

```bash
# Build image
docker build -t short-url-generator .

# Run with docker-compose
docker-compose up
```

## API Documentation

### Interactive Documentation (Swagger UI)

The service includes **comprehensive interactive API documentation** powered by Swagger/OpenAPI 3.0:

```
http://localhost:8080/swagger/index.html
```

**Features:**
- 📖 Complete API reference with examples
- 🧪 Try-it-out functionality for all endpoints
- 📋 Request/response schemas
- 🔍 Search and filter endpoints
- 💾 Export OpenAPI spec (JSON/YAML)

**Available at:** `GET /swagger/index.html`

### Manual API Reference

### Health Check

```bash
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "redis": "connected"
}
```

### Shorten URL

```bash
POST /shorten
Content-Type: application/json

{
  "originalURL": "https://example.com",
  "customSlug": "my-link",                     // Optional, custom vanity slug (3-64 chars)
  "expiry": "2024-12-31T23:59:59+03:30",      // Optional, RFC3339 with timezone (use +HH:MM or Z for UTC)
  "maxUsage": 10                               // Optional, integer
}
```

**Success Response (201 Created):**
```json
{
  "originalURL": "https://example.com",
  "shortURL": "http://localhost:8080/my-link",
  "managementID": "550e8400-e29b-41d4-a716-446655440000",
  "slug": "my-link",
  "isCustomSlug": true,
  "qrCodeURL": "http://localhost:8080/qr/my-link"
}
```

**Custom Slug Rules:**
- Length: 3-64 characters
- Allowed: letters, numbers, hyphens, underscores
- Must start/end with alphanumeric
- Cannot be reserved words (health, admin, api, etc.)
- Case-insensitive uniqueness

**Important:** Save the `managementID` to update or delete the URL later.

**Duplicate Response (200 OK):** *(if deduplication enabled)*
```json
{
  "originalURL": "https://example.com",
  "shortURL": "http://localhost:8080/abc123",
  "managementID": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Error Response (4xx/5xx):**
```json
{
  "error": "URL cannot be empty",
  "message": "Additional context"
}
```

**Custom Slug Conflict (409 Conflict):** *(with alternative suggestions)*
```json
{
  "error": "custom slug already taken",
  "message": "The slug 'my-link' is already in use. Try a different slug or leave blank for auto-generation.",
  "suggestions": [
    "my-link-2",
    "my-link-3",
    "my-link-x17"
  ]
}
```

**Note:** When a custom slug is already taken, the API automatically generates up to 3 alternative suggestions using:
- Numeric suffixes (my-link-2, my-link-3, etc.)
- Random suffixes (my-link-x17, my-link-x42, etc.)

The number of suggestions can be configured via `features.slug_suggestions_count` in config.yaml.

### Access Short URL

```bash
GET /{shortURL}
```

**Success**: Redirects to original URL (301 Moved Permanently)

**Error Responses:**
- `404 Not Found`: Short URL doesn't exist
- `410 Gone`: URL has expired
- `403 Forbidden`: Usage limit exceeded

### Update URL

```bash
PUT /shorten/{managementID}
Content-Type: application/json

{
  "originalURL": "https://example.com",
  "shortURL": "abc123",
  "newOriginalURL": "https://newexample.com"
}
```

**Success Response (200 OK):**
```json
{
  "originalURL": "https://newexample.com",
  "shortURL": "http://localhost:8080/abc123",
  "managementID": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Security:** Requires 2-factor validation (managementID + shortURL + originalURL)

**Error Responses:**
- `400 Bad Request`: Missing or invalid fields
- `403 Forbidden`: Validation failed (wrong shortURL or originalURL)
- `404 Not Found`: Management ID not found

### Delete URL

```bash
DELETE /shorten/{managementID}
Content-Type: application/json

{
  "originalURL": "https://example.com",
  "shortURL": "abc123"
}
```

**Success Response:** `204 No Content`

**Security:** Requires 3-factor validation (managementID + shortURL + originalURL)

**Error Responses:**
- `400 Bad Request`: Missing required fields
- `403 Forbidden`: Validation failed
- `404 Not Found`: Management ID not found

### Generate QR Code

```bash
GET /{shortURL}/qr?size=256&level=medium
```

Generates a QR code image for any short URL. Perfect for marketing materials, posters, and print media.

**Query Parameters:**
- `size` (optional): QR code size in pixels
  - Default: `256`
  - Range: `128` to `1024`
  - Example: `?size=512`
- `level` (optional): Error correction level
  - Options: `low`, `medium` (default), `high`, `highest`
  - Higher levels allow recovery from more damage but increase QR size
  - Example: `?level=high`

**Success Response (200 OK):**
- Content-Type: `image/png`
- Cache-Control: `public, max-age=3600` (1 hour)
- Binary PNG image data

**Examples:**
```bash
# Generate default 256px QR code
curl http://localhost:8080/my-link/qr -o my-link-qr.png

# Generate large 512px QR code with high error correction
curl "http://localhost:8080/my-link/qr?size=512&level=high" -o large-qr.png

# Generate small 128px QR code
curl "http://localhost:8080/my-link/qr?size=128" -o small-qr.png
```

**Error Responses:**
- `400 Bad Request`: Invalid size or level parameter
- `404 Not Found`: Short URL doesn't exist

**Use Cases:**
- 📄 Print media (posters, flyers, business cards)
- 📱 Mobile-friendly sharing
- 🎫 Event tickets and passes
- 📦 Product packaging
- 🏪 Retail displays

### Cache Metrics

```bash
GET /cache/metrics
```

**Response:**
```json
{
  "hits": 15234,
  "misses": 1876,
  "hit_ratio": 0.89,
  "keys_added": 3421,
  "keys_evicted": 421,
  "ttl_seconds": 300
}
```

### URL Preview (Anti-Phishing)

The service includes a preview page feature that shows users the destination URL before redirecting, providing protection against phishing and malicious links.

**Direct Preview Page:**
```bash
GET /preview/{shortURL}
```

**Preview via Query Parameter:**
```bash
GET /{shortURL}?preview=1
```

**Auto-redirect Option:**
```bash
GET /preview/{shortURL}?autoredirect=5  # Auto-redirect after 5 seconds
```

**Preview Page Features:**
- 🔍 Shows full destination URL
- 🔒 Displays security indicator (HTTPS vs HTTP)
- 📅 Shows creation date and expiry info
- 📊 Displays usage statistics
- ⏱️ Optional auto-redirect with countdown
- 📱 Mobile-responsive design

**Example Usage:**
```bash
# View preview page before redirecting
curl http://localhost:8080/preview/abc123

# Or append ?preview=1 to any short URL
curl http://localhost:8080/abc123?preview=1

# Auto-redirect after 10 seconds
curl http://localhost:8080/preview/abc123?autoredirect=10
```

**Configuration:**
```yaml
features:
  preview_enabled: true           # Enable preview feature
  preview_auto_redirect: 0        # Default auto-redirect seconds (0 = disabled)
```

**Use Cases:**
- 🛡️ Anti-phishing protection for end users
- ✅ Link verification before clicking
- 📧 Email safety (inspect links from unknown sources)
- 🏢 Corporate security policies
- 🎓 Educational platforms

## Timezone Support

The service fully supports timezone-aware expiry dates using RFC3339 format.

### Setting Expiry Times

**With Timezone Offset (Recommended):**
```json
{
  "originalURL": "https://example.com",
  "expiry": "2024-12-31T23:59:59+03:30"  // Iran Standard Time
}
```

**UTC Time:**
```json
{
  "originalURL": "https://example.com",
  "expiry": "2024-12-31T23:59:59Z"  // UTC (Z suffix)
}
```

**Common Timezone Offsets:**
- Iran: `+03:30`
- India: `+05:30`
- Japan: `+09:00`
- New York: `-05:00` (EST) or `-04:00` (EDT)
- London: `+00:00` or `+01:00` (BST)

**Validation:**
- Expiry must be in the future (validated against server time)
- Invalid or past expiry dates are rejected with helpful error messages
- All times are stored and compared correctly regardless of timezone

## Configuration

### config.yaml

```yaml
webserver:
  port: "8080"
  ip: "127.0.0.1"
  scheme: "http"              # http or https
  base_url: ""                # Public URL for short links (e.g., "https://myapp.com"). Leave empty to auto-construct
  read_timeout: 15            # seconds
  write_timeout: 15           # seconds
  shutdown_timeout: 30        # seconds

redis:
  address: "localhost:6379"
  password: ""
  db: 0
  pool_size: 10
  min_idle_conns: 5
  operation_timeout: 5        # seconds

cache:
  enabled: true               # Enable in-memory cache
  max_size_mb: 100           # Maximum cache size (MB)
  ttl_seconds: 300           # Cache TTL (5 minutes)
  counter_size: 1000000      # Keys to track for admission

ratelimit:
  requests_per_second: 10
  burst: 20

features:
  deduplication_enabled: true     # Smart duplicate URL detection
  custom_slugs_enabled: true      # Allow custom vanity URLs
  min_slug_length: 3              # Minimum custom slug length
  max_slug_length: 64             # Maximum custom slug length
  slug_suggestions_count: 3       # Number of alternatives when slug is taken
  require_auth_for_custom: false  # Future: require auth for custom slugs
  preview_enabled: true           # Enable URL preview feature (anti-phishing)
  preview_auto_redirect: 0        # Auto-redirect seconds on preview page (0 = disabled)

security:
  url_scanning_enabled: true             # Enable malware/phishing URL scanning
  blocklist_enabled: true                # Enable local blocklist
  safe_browsing_api_key: ""              # Google Safe Browsing API key (optional)
  bot_detection_enabled: true            # Enable bot detection
  bot_max_requests_per_minute: 60        # Max requests per IP before flagging as bot
```

### Environment Variables

Override any config value using `SHORTURL_` prefix:

```bash
export SHORTURL_WEBSERVER_PORT="3000"
export SHORTURL_WEBSERVER_BASE_URL="https://myapp.com"
export SHORTURL_REDIS_ADDRESS="redis:6379"
export SHORTURL_CACHE_ENABLED="true"
export SHORTURL_CACHE_MAX_SIZE_MB="100"
export SHORTURL_FEATURES_DEDUPLICATION_ENABLED="false"
```

## URL Deduplication

The service includes intelligent URL deduplication to prevent creating multiple short URLs for the same original URL.

### How It Works

1. **Hash-Based Index**: Uses SHA256 hash of original URL as lookup key
2. **Smart Matching**: Returns existing short URL only if:
   - Same original URL
   - Same expiry time (or both have no expiry)
   - Same max usage limit
3. **Performance**: O(1) hash lookup (~0.1ms overhead)
4. **Auto-Cleanup**: Index entries removed when URLs expire/reach limit

### Example

```bash
# First request
curl -X POST http://localhost:8080/shorten \
  -d '{"originalURL":"https://example.com"}'
# Returns: http://localhost:8080/abc123 (201 Created)

# Duplicate request (same URL, no params)
curl -X POST http://localhost:8080/shorten \
  -d '{"originalURL":"https://example.com"}'
# Returns: http://localhost:8080/abc123 (200 OK) ✅ Same short URL

# Different parameters (different expiry)
curl -X POST http://localhost:8080/shorten \
  -d '{"originalURL":"https://example.com","expiry":"2025-12-31T23:59:59Z"}'
# Returns: http://localhost:8080/xyz789 (201 Created) ✅ New short URL
```

See [DEDUPLICATION.md](DEDUPLICATION.md) for complete documentation.

## URL Management

Every shortened URL receives a unique **Management ID** (UUID v4) that enables secure update and deletion operations.

### How It Works

1. **Creation**: When you create a short URL, you receive a `managementID` in the response
2. **Storage**: The managementID is securely indexed in Redis for O(1) lookups
3. **Security**: Multi-factor validation prevents unauthorized access
4. **Operations**: Update destination URL or delete short URL completely

### Security Model

**Update URL** (2-factor validation):
- Requires: `managementID` + `shortURL` + `originalURL`
- Validates all three values match before allowing update

**Delete URL** (3-factor validation):
- Requires: `managementID` + `shortURL` + `originalURL`
- Validates all three values match before allowing deletion

### Example Workflow

```bash
# 1. Create a short URL
curl -X POST http://localhost:8080/shorten \
  -H "Content-Type: application/json" \
  -d '{"originalURL":"https://example.com"}'

# Response includes managementID:
# {
#   "originalURL": "https://example.com",
#   "shortURL": "http://localhost:8080/abc123",
#   "managementID": "550e8400-e29b-41d4-a716-446655440000"
# }

# 2. Update the destination URL
curl -X PUT http://localhost:8080/shorten/550e8400-e29b-41d4-a716-446655440000 \
  -H "Content-Type: application/json" \
  -d '{
    "originalURL": "https://example.com",
    "shortURL": "abc123",
    "newOriginalURL": "https://newexample.com"
  }'

# 3. Delete the short URL
curl -X DELETE http://localhost:8080/shorten/550e8400-e29b-41d4-a716-446655440000 \
  -H "Content-Type: application/json" \
  -d '{
    "originalURL": "https://newexample.com",
    "shortURL": "abc123"
  }'
```

**Important:** Save the `managementID` from the creation response. Without it, you cannot update or delete the short URL.

## High-Performance Caching

The service includes an in-memory cache layer (Ristretto) that dramatically improves performance for frequently accessed URLs.

### Performance Characteristics

- **Latency**: Cache hits are ~100× faster than Redis lookups (microseconds vs milliseconds)
- **Hit Ratio**: Typically 80-95% for production workloads with hot URLs
- **Redis Load**: 90%+ reduction for popular links
- **Memory**: ~1KB per cached URL

### Cache Metrics

Monitor cache performance in real-time:

```bash
curl http://localhost:8080/cache/metrics
```

**Response:**
```json
{
  "hits": 15234,
  "misses": 1876,
  "hit_ratio": 0.89,
  "keys_added": 3421,
  "keys_evicted": 421,
  "ttl_seconds": 300
}
```

### Configuration

```yaml
cache:
  enabled: true          # Enable/disable cache
  max_size_mb: 100      # Maximum cache size
  ttl_seconds: 300      # Cache TTL (5 minutes)
  counter_size: 1000000 # TinyLFU admission policy size
```

**When to disable:**
- Very low traffic (< 10 req/s)
- Strict consistency requirements
- Memory-constrained environments

## Security Features

### Malware & Phishing Detection

The service includes comprehensive URL scanning to protect users from malicious links.

**Two-Layer Protection:**

1. **Local Blocklist** (No API key required)
   - Fast, immediate blocking of known malicious patterns
   - Blocks common phishing keywords and suspicious TLDs
   - Blocks malware file extensions
   - Customizable blocklist

2. **Google Safe Browsing API** (Optional)
   - Real-time threat intelligence from Google
   - Detects malware, phishing, unwanted software
   - Requires free API key from Google Cloud Console

**Configuration:**
```yaml
security:
  url_scanning_enabled: true           # Enable URL scanning
  blocklist_enabled: true              # Enable local blocklist
  safe_browsing_api_key: "YOUR_API_KEY" # Optional: Google Safe Browsing API
```

**How it works:**
1. When a URL is submitted, it's checked against the local blocklist first
2. If Safe Browsing API is configured, URL is checked against Google's threat database
3. If threats are detected, the URL is rejected with details about the threat

**Example blocked patterns:**
- Phishing keywords: `account-verify`, `confirm-account`, `suspended-account`
- Malware extensions: `.exe?`, `.scr?`, `.bat?`
- Suspicious TLDs: `.tk`, `.ml`, `.ga`

**Get your Safe Browsing API key:**
```bash
# 1. Visit: https://console.cloud.google.com
# 2. Enable "Safe Browsing API"
# 3. Create API credentials
# 4. Set in config or environment variable
export SHORTURL_SECURITY_SAFE_BROWSING_API_KEY="your-api-key"
```

### Bot Detection

Intelligent bot detection prevents automated abuse and scraping.

**Detection Methods:**
1. **User-Agent Analysis**
   - Identifies known bot patterns (scrapers, crawlers)
   - Allows legitimate bots (Googlebot, social media crawlers)
   - Flags suspicious or missing user agents

2. **Rate-Based Detection**
   - Tracks requests per IP address
   - Flags IPs exceeding threshold (default: 60 req/min)
   - Auto-cleanup of old tracking data

3. **Behavior Patterns**
   - Detects automated tools (curl, wget, python-requests)
   - Identifies missing browser fingerprints

**Configuration:**
```yaml
security:
  bot_detection_enabled: true
  bot_max_requests_per_minute: 60  # Requests per IP before flagging
```

**Legitimate bots (allowed):**
- Search engines: Googlebot, Bingbot
- Social media: Slackbot, Twitterbot, FacebookExternalHit
- Messaging: WhatsApp, Telegram, Discord

**Blocked patterns:**
- Generic bots, scrapers, crawlers
- Automated tools: curl, wget, python-requests
- Suspicious user agents

**Response when bot detected:**
```json
{
  "error": "Bot detected",
  "message": "This request appears to be automated. If you believe this is an error, please contact support.",
  "reason": "excessive_request_rate"
}
```

### Security Best Practices

1. **Enable all security features:**
   ```yaml
   security:
     url_scanning_enabled: true
     blocklist_enabled: true
     bot_detection_enabled: true
   ```

2. **Get Safe Browsing API key** for enhanced protection

3. **Monitor security events** in logs:
   ```bash
   # Check for blocked URLs
   grep "Malicious URL detected" logs/app.log

   # Check for bot activity
   grep "Bot detected" logs/app.log
   ```

4. **Customize blocklist** for your use case:
   - Add industry-specific threats
   - Block competitor domains (if needed)
   - Add custom patterns

## Development

### Run Tests

```bash
# Run all tests
go test -v ./...

# Run specific package tests
go test -v ./utils
go test -v ./handler

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Build

```bash
# Development build
go build -v

# Production build
go build -o short-url-generator -ldflags="-s -w"
```

### Project Structure

```
.
├── cache/           # Ristretto in-memory cache
├── config/          # Configuration management
├── docs/            # Swagger/OpenAPI documentation (auto-generated)
├── handler/         # HTTP request handlers
├── logger/          # Structured logging setup
├── middleware/      # HTTP middleware (CORS, rate limiting, logging)
├── model/           # Data models and Swagger schemas
├── redis/           # Redis client initialization
├── utils/           # Utility functions (validation, hashing)
├── main.go          # Application entry point
├── config.yaml      # Configuration file
└── README.md        # This file
```

## Security

### URL Validation

The service blocks potentially dangerous URLs:
- ❌ Localhost and loopback addresses (127.0.0.1, ::1, localhost)
- ❌ Private IP ranges (10.x.x.x, 192.168.x.x, 172.16-31.x.x)
- ❌ Link-local addresses (169.254.x.x)
- ❌ Non-HTTP(S) schemes (ftp, javascript, etc.)

### Rate Limiting

Per-IP rate limiting prevents abuse:
- Default: 10 requests/second per IP
- Burst: 20 requests
- Configurable in `config.yaml`

### Input Validation

- JSON schema validation
- URL format validation
- Expiry time validation (RFC3339 format with timezone support)
- Expiry must be in the future
- Max usage validation (positive integer)

### Management API Security

- **UUID v4 Management IDs**: 122 bits of cryptographically secure randomness
- **Multi-Factor Validation**:
  - Update: Requires managementID + shortURL + originalURL
  - Delete: Requires managementID + shortURL + originalURL
- **Prevents Unauthorized Access**: All three values must match to modify/delete
- **No Credential Reuse**: Each short URL has a unique management ID

## Monitoring

### Logs

Structured JSON logs with zerolog:

```json
{
  "level": "info",
  "method": "POST",
  "path": "/shorten",
  "remote_addr": "127.0.0.1:12345",
  "status": 201,
  "bytes": 89,
  "duration_ms": 2.5,
  "time": "2024-01-15T10:30:00Z",
  "message": "HTTP request"
}
```

### Health Check

```bash
curl http://localhost:8080/health
```

Use for:
- Kubernetes liveness/readiness probes
- Load balancer health checks
- Monitoring systems

## Admin Dashboard

The admin dashboard provides a comprehensive web interface for managing and monitoring your URL shortener service.

### Access Dashboard

Navigate to:
```
http://localhost:8080/admin/dashboard
```

**Authentication Required:**
The dashboard requires an admin API key configured in `config.yaml`:

```yaml
admin:
  enabled: true
  api_key: "your-secret-admin-key"  # CHANGE THIS IN PRODUCTION!
```

Or via environment variable:
```bash
export SHORTURL_ADMIN_API_KEY="your-secret-admin-key"
```

### Dashboard Features

**1. Overview Tab**
- Total URLs (all time)
- Active URLs (currently valid)
- Total clicks across all URLs
- URLs created today
- Cache performance metrics (hit rate, enabled status)

**2. URL Manager Tab**
- Search URLs by short code or original URL
- Filter by status (active/expired/all)
- Paginated table view with 20 URLs per page
- View creation date, click count, and status
- Quick links to short URL and original destination

**3. System Health Tab**
- Overall system status
- Redis connection status
- Cache metrics (hits, misses, hit rate, evictions)
- Feature configuration (deduplication, URL scanning, bot detection)
- Rate limiting configuration

### Admin API Endpoints

All admin API endpoints require authentication via `X-Admin-Key` header or `Authorization: Bearer <key>`:

**Get System Statistics**
```bash
curl -H "X-Admin-Key: your-secret-admin-key" \
  http://localhost:8080/admin/stats
```

**List All URLs (with pagination)**
```bash
curl -H "X-Admin-Key: your-secret-admin-key" \
  "http://localhost:8080/admin/urls?page=1&pageSize=20&status=active&search=example"
```

**Get URL Details (with access logs)**
```bash
curl -H "X-Admin-Key: your-secret-admin-key" \
  http://localhost:8080/admin/urls/abc123?limit=50
```

**Bulk Delete URLs**
```bash
curl -X POST \
  -H "X-Admin-Key: your-secret-admin-key" \
  -H "Content-Type: application/json" \
  -d '["url1", "url2", "url3"]' \
  http://localhost:8080/admin/urls/bulk-delete
```

**Extended System Health**
```bash
curl -H "X-Admin-Key: your-secret-admin-key" \
  http://localhost:8080/admin/system/health
```

### Security Best Practices

1. **Strong API Key**: Use a cryptographically random key (32+ characters)
   ```bash
   # Generate a secure key
   openssl rand -base64 32
   ```

2. **HTTPS Only**: Always use HTTPS in production to protect the API key

3. **Restrict Access**: Configure firewall rules to limit admin endpoint access:
   ```bash
   # Only allow from specific IP
   iptables -A INPUT -p tcp --dport 8080 -m string --string "/admin" --algo bm -s 192.168.1.100 -j ACCEPT
   iptables -A INPUT -p tcp --dport 8080 -m string --string "/admin" --algo bm -j DROP
   ```

4. **Environment Variables**: Never commit API keys to git, use environment variables

5. **Disable in Public Deployments**: Set `admin.enabled: false` if admin features aren't needed

### Dashboard Screenshots

The admin dashboard features:
- 📊 Real-time statistics with beautiful gradient cards
- 🔍 Powerful search and filtering capabilities
- 📱 Fully responsive design (mobile-friendly)
- 🎨 Modern UI with smooth animations
- 🔒 Secure API key authentication
- ⚡ Fast, single-page application (no page reloads)

## Performance

### Benchmarks

- **Request latency**: ~1-3ms (average)
- **Throughput**: ~5000 req/s (single instance)
- **Redis operations**: 1-3 per request
- **Memory**: ~50MB baseline

### Optimization Tips

1. **Disable deduplication** if you need absolute max performance
2. **Increase pool size** for high-traffic scenarios
3. **Use Redis cluster** for horizontal scaling
4. **Enable connection pooling** (already configured)

## Planned Features

See **[ROADMAP.md](ROADMAP.md)** for complete development roadmap. Highlights include:

### Coming in v2.1-2.5
- 🔗 **User-Specific URL Paths** (v2.1.0): Brand your URLs with custom user slugs
  - Format: `yourdomain.com/john_doe/promo2025`
  - User-friendly slugs for personal/corporate branding

- 🌐 **Custom Branded Domains** (v2.5.0): Use your own domain for short URLs
  - Example: `gog.le/summer-sale` instead of `yourdomain.com/abc123`
  - **Two implementation approaches available:**
    - **Approach 1 (Simple)**: 4 weeks, $50-100/month, perfect for startups
    - **Approach 2 (Advanced)**: 8 weeks, $300-1000/month, enterprise-grade with CDN
  - See **[CUSTOM_DOMAINS.md](CUSTOM_DOMAINS.md)** for complete technical analysis

- 📊 **Analytics Dashboard** (v2.2.0): Visual analytics with charts and insights
- 📁 **URL Collections** (v2.3.0): Organize URLs into folders
- 🔑 **API Rate Limiting per User** (v2.4.0): Tiered usage plans

### Future Releases (v3.0+)
- 👥 **Team/Organization Support** (v3.0.0): Multi-user collaboration
- 🔗 **Link-in-Bio** (v3.2.0): Social media landing pages
- 🔔 **Webhook Support** (v3.3.0): Event notifications

**See [ROADMAP.md](ROADMAP.md) for detailed timelines and technical specifications.**

## Documentation

- **[README.md](README.md)**: This file - Complete user guide and API reference
- **[CLAUDE.md](CLAUDE.md)**: Architecture and development guide for Claude Code
- **[DEDUPLICATION.md](DEDUPLICATION.md)**: URL deduplication feature documentation
- **[ROADMAP.md](ROADMAP.md)**: Development roadmap and planned features
- **[CUSTOM_DOMAINS.md](CUSTOM_DOMAINS.md)**: Custom domain implementation analysis (two approaches)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Write tests for all new features
- Follow Go best practices and conventions
- Update documentation for API changes
- Ensure all tests pass before submitting PR
- Regenerate Swagger docs after handler changes: `swag init`

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [Gorilla Mux](https://github.com/gorilla/mux)
- Redis client by [go-redis](https://github.com/go-redis/redis)
- Configuration management with [Viper](https://github.com/spf13/viper)
- Structured logging with [zerolog](https://github.com/rs/zerolog)

## Support

For issues, questions, or contributions, please visit:
- GitHub Issues: [https://github.com/mdsatpak/short-url-generator/issues](https://github.com/mdsatpak/short-url-generator/issues)
- Documentation: See docs/ directory
