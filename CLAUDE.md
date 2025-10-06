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
  - `handler.go`: Main URLHandler struct with CreateShortURL, RedirectURL, and HealthCheck methods
  - `response.go`: Standardized JSON response helpers
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

### Request Flow

1. **Create Short URL** (`POST /shorten`):
   - Validate JSON → validate URL security → generate unique short URL → store in Redis → return JSON response
   - Returns 201 on success, 400 for validation errors, 500 for server errors

2. **Redirect** (`GET /{shortURL}`):
   - Fetch from Redis → check expiry → check usage limit → increment counter → log access → redirect (301)
   - Returns 404 if not found, 410 if expired, 403 if limit exceeded

3. **Health Check** (`GET /health`):
   - Ping Redis with 2s timeout → return JSON status

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
- WebServer: port, IP, scheme (http/https), timeouts
- Redis: address, password, DB, pool size, operation timeout
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
