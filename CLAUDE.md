# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A production-ready URL shortening service built with Go that uses Redis for persistence. Features include structured logging, rate limiting, CORS support, URL validation, graceful shutdown, and comprehensive error handling.

## Architecture

### Package Structure

- `main.go`: Entry point with dependency injection, middleware setup, and graceful shutdown
- `config/`: Viper-based configuration with environment variable overrides and defaults
- `model/`: Data models for `URL` and `URLLog` structs
- `handler/`: HTTP handlers using dependency injection pattern
  - `handler.go`: Main URLHandler struct with CreateShortURL, RedirectURL, HealthCheck, and CacheMetrics methods
  - `response.go`: Standardized JSON response helpers
- `cache/`: Ristretto-based in-memory cache with TTL and metrics
- `redis/`: Redis client initialization with connection pooling
- `utils/`: URL validation with security checks (blocks localhost, private IPs, invalid schemes)
- `logger/`: Zerolog-based structured logging initialization
- `middleware/`: HTTP middleware (CORS, rate limiting, request logging)

### Design Patterns

- **Dependency Injection**: URLHandler receives Redis client and config via constructor
- **Context Timeouts**: All Redis operations use context with configurable timeout (default 5s)
- **Collision Detection**: Short URL generation retries up to 5 times if collision detected
- **Graceful Shutdown**: SIGTERM/SIGINT handling with configurable timeout (default 30s)

### Redis Data Model

- **Active URLs**: Stored as JSON-marshaled `URL` structs using short URL as key
- **URL Index**: Hash `url_index` storing `SHA256(originalURL)` → `shortURL` for deduplication
- **Expired URLs**: Moved to `expired_urls` list when accessed after expiry
- **Used-up URLs**: Moved to `usedup_urls` list when usage limit exceeded
- **Access Logs**: Stored in `logs:{shortURL}` lists as JSON-marshaled `URLLog` entries

### URL Generation & Validation

- Short URLs: 8-10 character random strings using charset `a-zA-Z0-9_`
- Cryptographically secure random generation (handler/handler.go:52-58)
- Collision detection with max 5 retries (handler/handler.go:61-89)
- URL validation blocks: localhost, private IPs (10.x, 192.168.x, 172.16-31.x), link-local IPs, non-HTTP(S) schemes

### URL Deduplication

- **Feature Flag**: Controlled by `features.deduplication_enabled` (default: true)
- **Hash-Based Index**: Uses SHA256 hash of original URL as lookup key
- **Smart Matching**: Returns existing short URL only if:
  - Same original URL
  - Same expiry time (or both have no expiry)
  - Same max usage limit
- **Performance**: O(1) hash lookup via Redis HGET
- **Auto-Cleanup**: Index entries removed when URLs expire or reach usage limit
- **Behavior**: Returns 200 (vs 201) when returning existing short URL

### In-Memory Caching

- **Cache Library**: Ristretto (high-performance Go cache with TinyLFU admission policy)
- **Read-Through Pattern**: Check cache first, fall back to Redis on miss
- **Cache Key**: Short URL string
- **Cache Value**: Complete `URL` struct (cached after first Redis fetch)
- **TTL**: Configurable (default: 5 minutes)
- **Size**: Configurable max size in MB (default: 100MB)
- **Metrics**: Hit rate, miss rate, evictions, keys added (exposed via `/cache/metrics`)
- **Invalidation**: Automatic on expiry, usage limit exceeded, or TTL expiration
- **Performance**: ~100× faster for cached URLs (microseconds vs milliseconds)
- **Feature Flag**: `cache.enabled` (default: true)

**Cache Flow**:
1. Redirect request arrives
2. Check local cache → **Cache hit**: Use cached data (skip Redis GET)
3. **Cache miss**: Fetch from Redis, populate cache for future requests
4. Increment usage counter in Redis (not cached, always up-to-date)
5. Update cache with new usage count
6. Log access and redirect

### Request Flow

1. **Create Short URL** (`POST /shorten`):
   - Validate JSON → validate URL security → generate unique short URL → store in Redis → return JSON response
   - Returns 201 on success, 400 for validation errors, 500 for server errors

2. **Redirect** (`GET /{shortURL}`):
   - Check cache (if enabled) → on miss: fetch from Redis → check expiry → check usage limit → increment counter → update cache → log access → redirect (301)
   - Returns 404 if not found, 410 if expired, 403 if limit exceeded

3. **Health Check** (`GET /health`):
   - Ping Redis with 2s timeout → return JSON status

4. **Cache Metrics** (`GET /cache/metrics`):
   - Return cache performance metrics (hits, misses, hit ratio, evictions)
   - Returns 503 if cache is disabled

### Middleware Chain (Applied in Order)

1. CORS: Allows all origins, common methods
2. RequestLogger: Structured logging of all HTTP requests
3. RateLimiter: Per-IP rate limiting (configurable, default 10 req/s, burst 20)

## Common Commands

### Development

```sh
# Install dependencies
go mod tidy

# Run the application
go run main.go

# Build the application
go build -v ./...

# Run all tests
go test -v ./...

# Run tests for specific package
go test -v ./utils
go test -v ./handler

# Build for production
go build -o short-url-generator
```

### Configuration

Configuration via `config.yaml` with environment variable overrides using `SHORTURL_` prefix:

```sh
# Override Redis address via environment
export SHORTURL_REDIS_ADDRESS="redis:6379"

# Override server port
export SHORTURL_WEBSERVER_PORT="3000"

# Set custom base URL for short links
export SHORTURL_WEBSERVER_BASE_URL="https://myapp.com"
```

All configuration has defaults, so the app can run without `config.yaml` if Redis is on localhost:6379.

### API Testing

Health check:
```sh
curl http://localhost:8080/health
```

Shorten URL:
```sh
curl -X POST http://localhost:8080/shorten \
  -H "Content-Type: application/json" \
  -d '{"originalURL":"https://example.com", "expiry":"2024-12-31T23:59:59Z", "maxUsage":"10"}'
```

Access short URL:
```sh
curl -L http://localhost:8080/{shortURL}
```

## Key Implementation Details

### Security
- URL validation prevents SSRF attacks (utils/validator.go)
- Rate limiting prevents abuse (middleware/ratelimit.go)
- All Redis operations have timeouts to prevent hanging

### Error Handling
- Standardized JSON error responses across all endpoints
- Structured logging with context (zerolog)
- Graceful degradation (logging failures don't block requests)

### Performance
- Redis connection pooling (configurable: default 10 connections, 5 min idle)
- Cryptographically secure random generation
- Context cancellation propagation

### Testing
- Unit tests for URL validation (utils/validator_test.go)
- Unit tests for handler input validation (handler/handler_test.go)
- Integration tests require Redis connection (marked with t.Skip)

### Configuration Options

See config.yaml for all options:
- WebServer: port, IP, scheme (http/https), base_url, timeouts
- Redis: address, password, DB, pool size, operation timeout
- Cache: enabled, max_size_mb, ttl_seconds, counter_size
- RateLimit: requests per second, burst size
- Features: deduplication_enabled (default: true)

### Deduplication Configuration

Disable deduplication for use cases where:
- Users need different expiry/maxUsage for same URL
- Maximum performance is critical (saves 1 HGET operation)
- You want to allow unlimited short URLs for the same original URL

```yaml
features:
  deduplication_enabled: false  # Disable deduplication
```

Or via environment variable:
```sh
export SHORTURL_FEATURES_DEDUPLICATION_ENABLED=false
```

### Base URL Configuration

Configure the public URL for generated short links using the `base_url` setting. This is essential for production deployments where the service is accessed via a domain name or reverse proxy.

**Default behavior (empty string):**
- Auto-constructs URL from `scheme://ip:port`
- Example: `http://127.0.0.1:8080`

**Custom domain configuration:**
```yaml
webserver:
  base_url: "https://myapp.com"  # Your public domain
```

Or via environment variable:
```sh
export SHORTURL_WEBSERVER_BASE_URL="https://myapp.com"
```

**Common use cases:**
- Production domain: `https://short.example.com`
- Behind reverse proxy: `http://localhost:80`
- Short .ir domain: `https://lnk.ir`

### Cache Configuration

The service includes a high-performance in-memory cache (Ristretto) that dramatically improves redirect performance for frequently accessed URLs.

**Configuration:**
```yaml
cache:
  enabled: true           # Enable/disable cache
  max_size_mb: 100       # Maximum cache size (MB)
  ttl_seconds: 300       # Cache TTL (5 minutes)
  counter_size: 1000000  # Keys to track for admission policy
```

**Environment variables:**
```sh
export SHORTURL_CACHE_ENABLED="true"
export SHORTURL_CACHE_MAX_SIZE_MB="100"
export SHORTURL_CACHE_TTL_SECONDS="300"
```

**Performance characteristics:**
- **Cache hit**: ~100× faster than Redis (microseconds vs milliseconds)
- **Typical hit ratio**: 80-95% for production workloads with hot URLs
- **Memory overhead**: ~1KB per cached URL
- **Redis load reduction**: 90%+ for popular links

**When to disable cache:**
- Single-instance deployment with very low traffic
- Extremely strict consistency requirements (rare for URL shorteners)
- Memory-constrained environments

**Monitoring:**
Check cache performance via `/cache/metrics` endpoint:
```sh
curl http://localhost:8080/cache/metrics
```
