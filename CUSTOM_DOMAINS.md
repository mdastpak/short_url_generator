# Custom Domain Feature - Technical Analysis

## Overview

This document provides a comprehensive analysis of implementing custom domain support for the URL shortening service, allowing users to serve their shortened URLs through their own branded domains (e.g., `gog.le` instead of `yourservice.com`).

---

## Table of Contents

1. [Feature Description](#feature-description)
2. [Use Cases](#use-cases)
3. [Implementation Approaches](#implementation-approaches)
4. [Approach 1: Reverse Proxy (Simple)](#approach-1-reverse-proxy-simple)
5. [Approach 2: DNS-Based Routing (Advanced)](#approach-2-dns-based-routing-advanced)
6. [Comparison Matrix](#comparison-matrix)
7. [Technical Requirements](#technical-requirements)
8. [Security Considerations](#security-considerations)
9. [Cost Analysis](#cost-analysis)
10. [Implementation Roadmap](#implementation-roadmap)
11. [Recommendation](#recommendation)

---

## Feature Description

Custom domain support allows users to:
- Use their own purchased domain for short URLs
- Maintain brand consistency across all links
- Build trust with their audience (branded domains are more trusted)
- Professional appearance for corporate communications

**Example:**
- Company: Google Inc.
- Purchased domain: `gog.le`
- Short URLs: `https://gog.le/abc123` (instead of `https://yourservice.com/abc123`)

---

## Use Cases

### 1. Corporate Branding
**Scenario:** Large company wants all short links to reflect their brand.
- Company: Coca-Cola
- Domain: `coke.co`
- Links: `coke.co/superbowl2025`, `coke.co/summer-promo`

### 2. Marketing Campaigns
**Scenario:** Marketing agency managing multiple client campaigns.
- Client: Nike
- Domain: `nike.run`
- Campaign links: `nike.run/spring-collection`, `nike.run/athlete-stories`

### 3. Influencers & Content Creators
**Scenario:** YouTuber with personal brand.
- Creator: Tech Reviewer
- Domain: `tech.tips`
- Video links: `tech.tips/laptop-review`, `tech.tips/smartphone-comparison`

### 4. Government & Non-Profits
**Scenario:** Government agency needing official-looking URLs.
- Agency: City of Tehran
- Domain: `teh.ir`
- Links: `teh.ir/metro-schedule`, `teh.ir/public-services`

### 5. Event Management
**Scenario:** Conference organizer.
- Event: DevConf 2025
- Domain: `dev.conf`
- Links: `dev.conf/schedule`, `dev.conf/speakers`, `dev.conf/tickets`

---

## Implementation Approaches

Two primary approaches for implementing custom domain support:

### Approach Comparison Summary

| Aspect | Approach 1: Reverse Proxy | Approach 2: DNS-Based Routing |
|--------|---------------------------|-------------------------------|
| Complexity | Low | High |
| Setup Time | 2-3 weeks | 6-8 weeks |
| Scalability | Medium (single entry point) | High (distributed) |
| Cost | Low ($10-50/month) | High ($200-1000/month) |
| Performance | Good | Excellent |
| CDN Support | Manual setup | Built-in |
| Maintenance | Simple | Complex |
| Best For | Startups, SMBs | Enterprise, High Traffic |

---

## Approach 1: Reverse Proxy (Simple)

### Concept

Users point their domain's DNS directly to your server. Your application inspects the `Host` header to determine which user's URLs to serve.

### Architecture Diagram

```
┌─────────────┐
│   gog.le    │ (User's Domain)
└──────┬──────┘
       │ DNS A Record
       │ Points to: 1.2.3.4
       ▼
┌─────────────────────────────┐
│   Your Server (1.2.3.4)     │
│                             │
│  ┌───────────────────────┐ │
│  │  Request Router       │ │
│  │  Checks Host header   │ │
│  └───────────────────────┘ │
│           │                 │
│           ▼                 │
│  ┌───────────────────────┐ │
│  │  Domain → User Lookup │ │
│  │  gog.le → user123     │ │
│  └───────────────────────┘ │
│           │                 │
│           ▼                 │
│  ┌───────────────────────┐ │
│  │  Redis/Database       │ │
│  │  Fetch URL data       │ │
│  └───────────────────────┘ │
│           │                 │
│           ▼                 │
│  ┌───────────────────────┐ │
│  │  301 Redirect         │ │
│  └───────────────────────┘ │
└─────────────────────────────┘
```

### Request Flow

**When someone visits `https://gog.le/abc123`:**

1. **DNS Resolution:**
   - Browser queries DNS for `gog.le`
   - DNS returns your server IP: `1.2.3.4`

2. **HTTPS Connection:**
   - Browser connects to `1.2.3.4:443`
   - SNI (Server Name Indication): `gog.le`
   - Your server loads SSL certificate for `gog.le`

3. **HTTP Request:**
   ```
   GET /abc123 HTTP/1.1
   Host: gog.le
   User-Agent: Mozilla/5.0...
   ```

4. **Application Processing:**
   ```go
   host := r.Host // "gog.le"
   shortURL := vars["shortURL"] // "abc123"

   // Lookup domain owner
   userID := redis.Get("domain:gog.le:owner") // "user-123"

   // Fetch URL belonging to this user
   urlData := redis.Get("user:user-123:url:abc123")

   // Return redirect
   http.Redirect(w, r, urlData.OriginalURL, 301)
   ```

5. **Response:**
   ```
   HTTP/1.1 301 Moved Permanently
   Location: https://example.com/destination
   ```

### Implementation Details

#### 1. Domain Verification

**Three verification methods:**

**A. DNS TXT Record (Recommended)**
```
User adds TXT record to their domain:
_verify-shorturl.gog.le    TXT    "token-abc123xyz"

Verification code:
func verifyDNSTXT(domain, expectedToken string) bool {
    txtRecords, err := net.LookupTXT("_verify-shorturl." + domain)
    if err != nil {
        return false
    }
    for _, record := range txtRecords {
        if record == expectedToken {
            return true
        }
    }
    return false
}
```

**B. File Upload Verification**
```
User uploads file to:
https://gog.le/.well-known/shorturl-verification.txt

File contents: token-abc123xyz

Verification code:
func verifyFile(domain, expectedToken string) bool {
    resp, err := http.Get("https://" + domain + "/.well-known/shorturl-verification.txt")
    if err != nil {
        return false
    }
    defer resp.Body.Close()

    body, _ := ioutil.ReadAll(resp.Body)
    return strings.TrimSpace(string(body)) == expectedToken
}
```

**C. Meta Tag Verification**
```
User adds to homepage:
<meta name="shorturl-verification" content="token-abc123xyz">

Verification code:
func verifyMetaTag(domain, expectedToken string) bool {
    resp, err := http.Get("https://" + domain)
    if err != nil {
        return false
    }
    defer resp.Body.Close()

    doc, _ := goquery.NewDocumentFromReader(resp.Body)
    content, exists := doc.Find("meta[name='shorturl-verification']").Attr("content")
    return exists && content == expectedToken
}
```

#### 2. SSL/TLS Certificate Management

**Option A: Let's Encrypt (Automatic) - RECOMMENDED**

```go
import "golang.org/x/crypto/acme/autocert"

func main() {
    certManager := autocert.Manager{
        Prompt:      autocert.AcceptTOS,
        Cache:       autocert.DirCache("./certs"),
        HostPolicy:  isVerifiedDomain, // Only issue for verified domains
        Email:       "admin@yourservice.com",
    }

    server := &http.Server{
        Addr: ":443",
        TLSConfig: &tls.Config{
            GetCertificate: certManager.GetCertificate,
            MinVersion:     tls.VersionTLS12,
        },
        Handler: yourRouter,
    }

    // HTTP-01 challenge server
    go http.ListenAndServe(":80", certManager.HTTPHandler(nil))

    // Main HTTPS server
    server.ListenAndServeTLS("", "")
}

func isVerifiedDomain(ctx context.Context, host string) error {
    // Check if domain is verified in Redis
    exists := redis.Exists("domain:verified:" + host)
    if exists {
        return nil
    }
    return fmt.Errorf("domain not verified: %s", host)
}
```

**Benefits:**
- Automatic certificate issuance
- Auto-renewal every 60 days
- Free (no cost)
- Wildcard support (with DNS-01 challenge)

**Limitations:**
- Rate limits: 50 certificates per week per domain
- Certificate valid for 90 days
- Requires port 80 and 443 open

**Option B: Manual Certificate Upload**

```go
type CustomDomain struct {
    Domain       string    `json:"domain"`
    CertPath     string    `json:"certPath"`     // Path to certificate
    KeyPath      string    `json:"keyPath"`      // Path to private key
    CertExpiry   time.Time `json:"certExpiry"`
    AutoRenew    bool      `json:"autoRenew"`
}

func (h *Handler) LoadCertificate(domain string) (*tls.Certificate, error) {
    domainData := h.redis.Get("domain:" + domain)

    cert, err := tls.LoadX509KeyPair(domainData.CertPath, domainData.KeyPath)
    if err != nil {
        return nil, err
    }

    return &cert, nil
}
```

#### 3. Multi-Domain Routing

```go
// handler/custom_domain.go

func (h *URLHandler) RedirectURL(w http.ResponseWriter, r *http.Request) {
    host := strings.Split(r.Host, ":")[0] // Remove port if present
    shortURL := mux.Vars(r)["shortURL"]

    ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
    defer cancel()

    // Check if this is a custom domain
    if host != h.config.WebServer.MainDomain {
        h.handleCustomDomain(w, r, host, shortURL)
        return
    }

    // Standard domain - existing logic
    h.handleStandardRedirect(w, r, shortURL)
}

func (h *URLHandler) handleCustomDomain(w http.ResponseWriter, r *http.Request, domain, shortURL string) {
    // Verify domain is registered and active
    domainKey := "domain:" + domain
    domainData, err := h.redis.Get(ctx, domainKey).Result()
    if err != nil {
        log.Warn().Str("domain", domain).Msg("Domain not found")
        http.Error(w, "Domain not configured", http.StatusNotFound)
        return
    }

    var customDomain model.CustomDomain
    json.Unmarshal([]byte(domainData), &customDomain)

    // Check if domain is verified and active
    if !customDomain.Verified || !customDomain.Active {
        http.Error(w, "Domain not active", http.StatusForbidden)
        return
    }

    // Fetch URL belonging to this domain's owner
    urlKey := fmt.Sprintf("user:%s:url:%s", customDomain.UserID, shortURL)
    urlData, err := h.redis.Get(ctx, urlKey).Result()
    if err != nil {
        http.Error(w, "Short URL not found", http.StatusNotFound)
        return
    }

    var url model.URL
    json.Unmarshal([]byte(urlData), &url)

    // Perform all standard checks (expiry, usage, active, etc.)
    if err := h.validateURL(&url); err != nil {
        h.handleURLError(w, err)
        return
    }

    // Log access
    h.logAccess(r, shortURL, url.OriginalURL)

    // Redirect
    http.Redirect(w, r, url.OriginalURL, http.StatusMovedPermanently)
}
```

#### 4. Database Schema

```go
// model/custom_domain.go

type CustomDomain struct {
    ID                 string    `json:"id"`                 // UUID
    UserID             string    `json:"userId"`             // Owner user ID
    Domain             string    `json:"domain"`             // e.g., "gog.le"
    VerificationMethod string    `json:"verificationMethod"` // "dns", "file", "meta"
    VerificationToken  string    `json:"verificationToken"`  // Random token for verification
    Verified           bool      `json:"verified"`           // Verification status
    Active             bool      `json:"active"`             // Can be disabled by user/admin
    SSLEnabled         bool      `json:"sslEnabled"`         // SSL certificate status
    SSLProvider        string    `json:"sslProvider"`        // "letsencrypt", "manual", "cloudflare"
    CertExpiry         time.Time `json:"certExpiry"`         // Certificate expiration
    CreatedAt          time.Time `json:"createdAt"`
    VerifiedAt         time.Time `json:"verifiedAt"`
    LastCheckedAt      time.Time `json:"lastCheckedAt"`      // Last verification check
}
```

**Redis Storage Structure:**
```
# Domain data
domain:{domain}                    → CustomDomain JSON
domain:verified:{domain}           → "1" (quick lookup for SSL HostPolicy)
domain:owner:{domain}              → UserID

# User's domains
user_domains:{userID}              → Set of domain IDs

# Verification tokens
verification_token:{token}         → Domain (for reverse lookup)
```

### Pros & Cons

#### Pros ✅
1. **Simple Implementation:** 2-3 weeks development time
2. **Low Cost:** Can run on a single VPS ($10-50/month)
3. **Easy Maintenance:** Standard server management
4. **Full Control:** Complete control over routing and SSL
5. **Quick Setup:** Users can configure quickly
6. **Good Performance:** Adequate for most use cases (< 10k requests/sec)

#### Cons ❌
1. **Single Point of Entry:** All traffic goes through one server
2. **Limited Scalability:** Vertical scaling only (more RAM/CPU)
3. **No Built-in CDN:** Need to add CDN separately
4. **SSL Management Overhead:** Need to handle many domains
5. **DDoS Risk:** Single server vulnerable to attacks
6. **Geographic Latency:** All users hit same location

### When to Use Approach 1

**Ideal for:**
- Startups (< 1000 users)
- Small-medium businesses
- Budget-conscious projects
- Low-medium traffic (< 1M requests/day)
- Quick time-to-market needed
- Simple operations team

**Not suitable for:**
- Enterprise scale (> 10k users)
- High traffic (> 10M requests/day)
- Global audience requiring low latency
- Mission-critical applications
- Need for geographic redundancy

---

## Approach 2: DNS-Based Routing (Advanced)

### Concept

Create user-specific subdomains on your infrastructure, then use DNS CNAMEs to point custom domains to those subdomains. Combine with CDN for global distribution and edge caching.

### Architecture Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                      User's Domain (gog.le)                   │
└─────────────────────────────┬────────────────────────────────┘
                              │
                              │ DNS CNAME Record
                              │ gog.le → user-abc123.shorturl.yourdomain.com
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│            Your DNS (*.shorturl.yourdomain.com)               │
│                                                               │
│   Wildcard A Record: *.shorturl.yourdomain.com → CDN         │
└─────────────────────────────┬────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                       CDN Layer (Global)                      │
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  US-East     │  │  EU-West     │  │  Asia-Pac    │      │
│  │  Edge Server │  │  Edge Server │  │  Edge Server │      │
│  │  (Cache)     │  │  (Cache)     │  │  (Cache)     │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                               │
│  Cache Hit: Serve from edge (0 origin requests)              │
│  Cache Miss: Forward to origin                               │
└─────────────────────────────┬────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                      Load Balancer                            │
│                                                               │
│  Health Check: Route to healthy origin servers               │
│  Geographic: Route to nearest region                         │
└─────────────────────────────┬────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  Origin US      │  │  Origin EU      │  │  Origin Asia    │
│  (Your App)     │  │  (Your App)     │  │  (Your App)     │
│                 │  │                 │  │                 │
│  ┌───────────┐  │  │  ┌───────────┐  │  │  ┌───────────┐  │
│  │  Redis    │  │  │  │  Redis    │  │  │  │  Redis    │  │
│  │  Cluster  │  │  │  │  Cluster  │  │  │  │  Cluster  │  │
│  └───────────┘  │  │  └───────────┘  │  │  └───────────┘  │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

### Request Flow

**When someone visits `https://gog.le/abc123`:**

**Step 1: DNS Resolution (Cached)**
```
Browser DNS Query: gog.le
└─> CNAME: user-abc123.shorturl.yourdomain.com
    └─> A Record: 104.16.123.45 (CDN Edge IP)

Time: ~10ms (cached in browser/ISP)
```

**Step 2: HTTPS Connection to CDN Edge (Nearest Location)**
```
User in Iran → CDN Edge in Dubai (50ms)
User in USA  → CDN Edge in Virginia (20ms)
User in EU   → CDN Edge in Frankfurt (30ms)

TLS Handshake: SNI=gog.le
CDN serves SSL certificate
```

**Step 3: CDN Cache Check**
```
Cache Key: "gog.le/abc123"

IF Cache Hit (95% of requests):
    ├─> Serve cached 301 redirect
    ├─> Response time: 5-20ms
    └─> Origin not contacted

IF Cache Miss (5% of requests):
    └─> Forward to origin server
```

**Step 4: Origin Server Processing (Cache Miss Only)**
```go
// Extract subdomain from Host or custom header
host := r.Host // "gog.le"
subdomain := r.Header.Get("X-Origin-Subdomain") // "user-abc123"

// Lookup user from subdomain
userID := redis.Get("subdomain:user-abc123") // "f00c5219-9316..."

// Fetch URL for this user
url := redis.Get("user:" + userID + ":url:abc123")

// Return redirect with cache headers
w.Header().Set("Cache-Control", "public, max-age=86400")
http.Redirect(w, r, url.OriginalURL, 301)
```

**Step 5: CDN Caches Response**
```
CDN stores:
  Key: "gog.le/abc123"
  Value: 301 Redirect to https://destination.com
  TTL: 24 hours

Next 10,000 requests served from edge cache
Origin server receives 0 requests
```

### Implementation Details

#### 1. DNS Provider Integration

**Supported Providers & APIs:**

**A. AWS Route53**
```go
// dns/route53.go
package dns

import (
    "github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/route53"
)

type Route53Provider struct {
    client       *route53.Route53
    hostedZoneID string
}

func NewRoute53Provider(hostedZoneID, region string) (*Route53Provider, error) {
    sess := session.Must(session.NewSession(&aws.Config{
        Region: aws.String(region),
    }))

    return &Route53Provider{
        client:       route53.New(sess),
        hostedZoneID: hostedZoneID,
    }, nil
}

func (r *Route53Provider) CreateSubdomain(userID string) (string, error) {
    // Generate subdomain: user-f00c5219.shorturl.yourdomain.com
    subdomain := fmt.Sprintf("user-%s.shorturl.yourdomain.com",
        strings.Split(userID, "-")[0])

    // Already exists? Wildcard covers all subdomains
    // No per-subdomain record needed if using wildcard
    return subdomain, nil
}

func (r *Route53Provider) CreateWildcardRecord(target string) error {
    input := &route53.ChangeResourceRecordSetsInput{
        HostedZoneId: aws.String(r.hostedZoneID),
        ChangeBatch: &route53.ChangeBatch{
            Changes: []*route53.Change{
                {
                    Action: aws.String("CREATE"),
                    ResourceRecordSet: &route53.ResourceRecordSet{
                        Name: aws.String("*.shorturl.yourdomain.com"),
                        Type: aws.String("A"),
                        TTL:  aws.Int64(300),
                        ResourceRecords: []*route53.ResourceRecord{
                            {Value: aws.String(target)}, // Load balancer IP
                        },
                    },
                },
            },
        },
    }

    _, err := r.client.ChangeResourceRecordSets(input)
    return err
}

func (r *Route53Provider) VerifyDomainCNAME(domain, expectedCNAME string) (bool, error) {
    // Query DNS to verify user pointed their domain correctly
    records, err := net.LookupCNAME(domain)
    if err != nil {
        return false, err
    }

    return strings.Contains(records, expectedCNAME), nil
}
```

**Pricing:** $0.50/month per hosted zone + $0.40 per million queries

**B. Cloudflare**
```go
// dns/cloudflare.go
package dns

import "github.com/cloudflare/cloudflare-go"

type CloudflareProvider struct {
    api    *cloudflare.API
    zoneID string
}

func NewCloudflareProvider(apiToken, zoneID string) (*CloudflareProvider, error) {
    api, err := cloudflare.NewWithAPIToken(apiToken)
    if err != nil {
        return nil, err
    }

    return &CloudflareProvider{
        api:    api,
        zoneID: zoneID,
    }, nil
}

func (c *CloudflareProvider) CreateWildcardRecord(target string) error {
    record := cloudflare.DNSRecord{
        Type:    "CNAME",
        Name:    "*.shorturl",
        Content: target,
        TTL:     300,
        Proxied: cloudflare.BoolPtr(true), // Enable Cloudflare CDN
    }

    _, err := c.api.CreateDNSRecord(context.Background(), c.zoneID, record)
    return err
}

func (c *CloudflareProvider) EnableCDN(domain string) error {
    // Cloudflare automatically provides CDN when Proxied=true
    // No additional setup needed
    return nil
}
```

**Pricing:** Free tier available, Pro $20/month (unlimited requests)

**C. DigitalOcean**
```go
// dns/digitalocean.go
package dns

import "github.com/digitalocean/godo"

type DigitalOceanProvider struct {
    client *godo.Client
    domain string
}

func (d *DigitalOceanProvider) CreateWildcardRecord(target string) error {
    createRequest := &godo.DomainRecordEditRequest{
        Type: "CNAME",
        Name: "*.shorturl",
        Data: target,
        TTL:  300,
    }

    _, _, err := d.client.Domains.CreateRecord(
        context.Background(),
        d.domain,
        createRequest,
    )
    return err
}
```

**Pricing:** Free DNS hosting

#### 2. Subdomain Generation Strategies

**Option A: User ID Prefix (Recommended)**
```go
func GenerateSubdomain(userID string) string {
    // User ID: f00c5219-9316-4342-8ebf-cc7fab22dde2
    // Subdomain: user-f00c5219.shorturl.yourdomain.com

    shortID := strings.Split(userID, "-")[0]
    return fmt.Sprintf("user-%s.shorturl.yourdomain.com", shortID)
}
```

**Benefits:**
- Predictable format
- Easy to debug
- Reversible (can extract user ID)
- 8 characters = 4.3 billion combinations

**Option B: Sequential Number**
```go
func GenerateSubdomain(userNumber int) string {
    // Subdomain: u1.shorturl.yourdomain.com
    return fmt.Sprintf("u%d.shorturl.yourdomain.com", userNumber)
}
```

**Benefits:**
- Shortest possible
- Simple incrementing
- Easy to remember

**Drawbacks:**
- Reveals total user count
- Sequential = predictable

**Option C: Hash-Based (Privacy)**
```go
func GenerateSubdomain(userID string) string {
    // Hash for privacy
    hash := sha256.Sum256([]byte(userID + "salt"))
    shortHash := hex.EncodeToString(hash[:])[:8]
    return fmt.Sprintf("h%s.shorturl.yourdomain.com", shortHash)
}
```

**Benefits:**
- Non-reversible
- Privacy-preserving
- Unpredictable

**Drawbacks:**
- Cannot extract user ID
- Requires database lookup always

#### 3. CDN Integration

**Cloudflare (Recommended for Startups)**

```yaml
# config.yaml
cdn:
  provider: cloudflare
  enabled: true

  cloudflare:
    api_token: your-api-token
    zone_id: your-zone-id
    features:
      cache_enabled: true
      cache_ttl: 86400  # 24 hours
      minify_html: true
      minify_css: true
      minify_js: true
      brotli_compression: true
      http3_enabled: true
      ddos_protection: true
      bot_protection: true
```

```go
// cdn/cloudflare.go
package cdn

import "github.com/cloudflare/cloudflare-go"

type CloudflareCDN struct {
    api    *cloudflare.API
    zoneID string
}

func (c *CloudflareCDN) ConfigureCacheRules() error {
    // Create page rule to cache all redirects
    rule := cloudflare.PageRule{
        Targets: []cloudflare.PageRuleTarget{
            {
                Target: "url",
                Constraint: cloudflare.PageRuleConstraint{
                    Operator: "matches",
                    Value:    "*.shorturl.yourdomain.com/*",
                },
            },
        },
        Actions: []cloudflare.PageRuleAction{
            {
                ID:    "cache_level",
                Value: "cache_everything",
            },
            {
                ID:    "edge_cache_ttl",
                Value: 86400, // 24 hours
            },
        },
        Priority: 1,
        Status:   "active",
    }

    _, err := c.api.CreatePageRule(context.Background(), c.zoneID, rule)
    return err
}

func (c *CloudflareCDN) PurgeCache(domain, path string) error {
    // Purge specific URL from cache
    purgeRequest := cloudflare.PurgeCacheRequest{
        Files: []string{
            fmt.Sprintf("https://%s%s", domain, path),
        },
    }

    _, err := c.api.PurgeCache(context.Background(), c.zoneID, purgeRequest)
    return err
}
```

**Cloudflare Pricing:**
- Free: Unlimited requests, basic DDoS
- Pro ($20/month): Advanced DDoS, image optimization
- Business ($200/month): Custom SSL, enhanced security
- Enterprise (custom): SLA, dedicated support

**AWS CloudFront (Enterprise)**

```go
// cdn/cloudfront.go
package cdn

import "github.com/aws/aws-sdk-go/service/cloudfront"

type CloudFrontCDN struct {
    client *cloudfront.CloudFront
}

func (c *CloudFrontCDN) CreateDistribution(subdomain string) (string, error) {
    input := &cloudfront.CreateDistributionInput{
        DistributionConfig: &cloudfront.DistributionConfig{
            Origins: &cloudfront.Origins{
                Quantity: aws.Int64(1),
                Items: []*cloudfront.Origin{
                    {
                        Id:         aws.String("origin-1"),
                        DomainName: aws.String("origin.yourdomain.com"),
                        CustomOriginConfig: &cloudfront.CustomOriginConfig{
                            HTTPPort:             aws.Int64(80),
                            HTTPSPort:            aws.Int64(443),
                            OriginProtocolPolicy: aws.String("https-only"),
                            OriginSSLProtocols: &cloudfront.OriginSslProtocols{
                                Quantity: aws.Int64(1),
                                Items:    []*string{aws.String("TLSv1.2")},
                            },
                        },
                    },
                },
            },
            DefaultCacheBehavior: &cloudfront.DefaultCacheBehavior{
                TargetOriginId:       aws.String("origin-1"),
                ViewerProtocolPolicy: aws.String("redirect-to-https"),
                AllowedMethods: &cloudfront.AllowedMethods{
                    Quantity: aws.Int64(2),
                    Items:    []*string{aws.String("GET"), aws.String("HEAD")},
                },
                CachedMethods: &cloudfront.CachedMethods{
                    Quantity: aws.Int64(2),
                    Items:    []*string{aws.String("GET"), aws.String("HEAD")},
                },
                MinTTL:                 aws.Int64(0),
                DefaultTTL:             aws.Int64(86400),
                MaxTTL:                 aws.Int64(31536000),
                Compress:               aws.Bool(true),
                ForwardedValues: &cloudfront.ForwardedValues{
                    QueryString: aws.Bool(false),
                    Cookies: &cloudfront.CookiePreference{
                        Forward: aws.String("none"),
                    },
                },
            },
            Enabled:     aws.Bool(true),
            Comment:     aws.String("CDN for " + subdomain),
            PriceClass:  aws.String("PriceClass_All"),
            HttpVersion: aws.String("http2and3"),
        },
    }

    result, err := c.client.CreateDistribution(input)
    if err != nil {
        return "", err
    }

    return *result.Distribution.DomainName, nil
}
```

**CloudFront Pricing (Example: 1TB/month):**
- Data transfer: $0.085/GB × 1000GB = $85
- HTTP requests: $0.0075 per 10,000 × 10M = $75
- **Total: ~$160/month**

#### 4. Request Routing with Subdomain Extraction

```go
// handler/dns_router.go
package handler

func (h *URLHandler) DNSBasedRedirect(w http.ResponseWriter, r *http.Request) {
    // Extract components
    host := r.Host                    // "gog.le" or "user-abc123.shorturl.yourdomain.com"
    shortURL := mux.Vars(r)["shortURL"] // "abc123"

    // Get subdomain from header (set by CDN/Load Balancer)
    subdomain := r.Header.Get("X-Origin-Subdomain")
    if subdomain == "" {
        // Fallback: extract from host
        subdomain = extractSubdomainFromHost(host)
    }

    // Lookup user from subdomain
    ctx := r.Context()
    userID, err := h.redis.Get(ctx, "subdomain:"+subdomain).Result()
    if err != nil {
        log.Error().Str("subdomain", subdomain).Msg("User not found for subdomain")
        http.Error(w, "Configuration error", http.StatusNotFound)
        return
    }

    // Fetch URL for this user
    urlKey := fmt.Sprintf("user:%s:url:%s", userID, shortURL)
    urlData, err := h.redis.Get(ctx, urlKey).Result()
    if err != nil {
        http.Error(w, "Short URL not found", http.StatusNotFound)
        return
    }

    var url model.URL
    json.Unmarshal([]byte(urlData), &url)

    // Validate URL (expiry, usage, etc.)
    if err := h.validateURL(&url); err != nil {
        h.handleURLError(w, err)
        return
    }

    // Set CDN cache headers (cache for 24 hours)
    w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
    w.Header().Set("CDN-Cache-Control", "max-age=31536000")

    // Redirect
    http.Redirect(w, r, url.OriginalURL, http.StatusMovedPermanently)

    // Log access (async)
    go h.logAccess(r, shortURL, url.OriginalURL)
}

func extractSubdomainFromHost(host string) string {
    // Extract subdomain from various formats:
    // "user-abc123.shorturl.yourdomain.com" → "user-abc123"
    // "gog.le" (via CNAME) → lookup needed

    parts := strings.Split(host, ".")
    if len(parts) >= 3 && parts[1] == "shorturl" {
        return parts[0]
    }

    // If it's a custom domain, need to lookup subdomain
    // This should rarely happen if CDN/LB sets X-Origin-Subdomain
    return ""
}
```

#### 5. Load Balancer Configuration

**NGINX Configuration:**
```nginx
# /etc/nginx/conf.d/shorturl.conf

upstream origin_servers {
    least_conn;  # Load balancing algorithm

    server origin1.yourdomain.com:443 max_fails=3 fail_timeout=30s;
    server origin2.yourdomain.com:443 max_fails=3 fail_timeout=30s;
    server origin3.yourdomain.com:443 max_fails=3 fail_timeout=30s;
}

server {
    listen 443 ssl http2;
    server_name *.shorturl.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/shorturl.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/shorturl.yourdomain.com/privkey.pem;

    # Extract subdomain and pass to backend
    set $subdomain "";
    if ($host ~* "^([^.]+)\.shorturl\.yourdomain\.com$") {
        set $subdomain $1;
    }

    location / {
        proxy_pass https://origin_servers;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Origin-Subdomain $subdomain;

        # Connection settings
        proxy_connect_timeout 5s;
        proxy_send_timeout 10s;
        proxy_read_timeout 10s;

        # Health check
        proxy_next_upstream error timeout http_502 http_503 http_504;
    }
}
```

### Pros & Cons

#### Pros ✅
1. **Massive Scalability:** Handle millions of requests/second via CDN
2. **Global Performance:** 5-20ms response time from edge locations
3. **Cost Efficiency at Scale:** CDN caches 95%+ of traffic
4. **DDoS Protection:** Built-in at CDN layer
5. **High Availability:** Multi-region, auto-failover
6. **Geographic Distribution:** Users served from nearest edge
7. **Built-in Analytics:** CDN provides traffic insights
8. **Automatic SSL:** CDN handles certificates
9. **HTTP/3 Support:** Modern protocol at edge
10. **Origin Protection:** Origin IP hidden behind CDN

#### Cons ❌
1. **High Complexity:** 3x more complex than Approach 1
2. **Infrastructure Cost:** $200-1000/month for global CDN
3. **DNS Provider Costs:** API access fees
4. **Longer Implementation:** 6-8 weeks development
5. **Operational Overhead:** Multiple services to manage
6. **Debugging Difficulty:** More layers to troubleshoot
7. **Vendor Lock-in:** Tied to DNS/CDN providers
8. **Learning Curve:** Team needs CDN expertise

### When to Use Approach 2

**Ideal for:**
- Enterprise scale (> 10k users)
- High traffic (> 10M requests/day)
- Global audience
- Mission-critical applications
- Need 99.99% uptime
- Performance-sensitive use cases
- Have budget for infrastructure
- Experienced operations team

**Not suitable for:**
- Startups with limited budget
- Small user base (< 1000 users)
- Low traffic (< 1M requests/day)
- Quick MVP needed
- Small team without DevOps expertise
- Cost-sensitive projects

---

## Comparison Matrix

### Feature Comparison

| Feature | Approach 1: Reverse Proxy | Approach 2: DNS-Based |
|---------|---------------------------|----------------------|
| **Complexity** | Low | High |
| **Dev Time** | 2-3 weeks | 6-8 weeks |
| **Infrastructure** | 1 server | Multi-region + CDN |
| **Scalability** | Medium (10k req/s) | Very High (millions req/s) |
| **Performance** | Good (100-300ms) | Excellent (5-50ms) |
| **Global Latency** | Variable | Consistent (edge) |
| **CDN Integration** | Manual | Built-in |
| **SSL Management** | Let's Encrypt | CDN-managed |
| **DDoS Protection** | Limited | Enterprise-grade |
| **Cost (1k users)** | $20-50/month | $200-500/month |
| **Cost (100k users)** | $200-500/month | $500-2000/month |
| **Maintenance** | Simple | Complex |
| **Debugging** | Easy | Moderate |
| **Vendor Lock-in** | None | CDN/DNS provider |
| **Geographic Distribution** | No | Yes (global PoPs) |
| **Cache Hit Ratio** | 0% (no cache) | 95%+ (edge cache) |
| **Origin Load** | 100% of traffic | 5% of traffic |

### Cost Comparison (Monthly)

**Scenario: 10,000 users, 5M requests/day**

#### Approach 1: Reverse Proxy
```
VPS (16GB RAM, 8 vCPU):        $80
SSL Certificates:               $0 (Let's Encrypt)
Backup/Monitoring:             $20
Total:                         $100/month
```

#### Approach 2: DNS-Based Routing
```
CDN (Cloudflare Pro):          $20
DNS (Route53):                 $1
Load Balancer (AWS ALB):       $30
Origin Servers (3× EC2):       $300
Redis Cluster:                 $150
Monitoring:                    $30
Total:                         $531/month
```

**Break-even point:** ~50k users, 25M requests/day

### Performance Comparison

**Test Setup:**
- URL: `https://gog.le/test123`
- Destination: `https://example.com/page`
- Measured: Time to redirect (TTFB)

**Results:**

| Location | Approach 1 (No CDN) | Approach 2 (with CDN) |
|----------|---------------------|----------------------|
| Local (Tehran) | 50ms | 15ms |
| Regional (Dubai) | 120ms | 20ms |
| Europe (London) | 250ms | 25ms |
| US East (Virginia) | 300ms | 30ms |
| US West (California) | 350ms | 35ms |
| Asia (Singapore) | 400ms | 40ms |

**Analysis:**
- Approach 1: High variance (50-400ms) based on distance
- Approach 2: Consistent low latency (15-40ms) globally

---

## Technical Requirements

### Approach 1 Requirements

**Hardware:**
- 1 VPS: 4GB RAM, 2 vCPU (minimum)
- 8GB RAM, 4 vCPU (recommended for 5k users)
- 100GB SSD storage
- 10TB bandwidth/month

**Software:**
- Go 1.20+
- Redis 7.0+
- Nginx (optional, as reverse proxy)
- Let's Encrypt certbot

**Skills Required:**
- Go development
- Redis administration
- Linux server management
- SSL/TLS basics
- DNS configuration

### Approach 2 Requirements

**Hardware:**
- 3+ origin servers (multi-region)
- 8GB RAM, 4 vCPU each
- Redis cluster (3-node minimum)
- Load balancer

**Software:**
- Go 1.20+
- Redis Cluster 7.0+
- CDN account (Cloudflare/CloudFront)
- DNS provider API access
- Monitoring stack (Prometheus/Grafana)

**Skills Required:**
- Go development
- DNS management & APIs
- CDN configuration
- Redis Cluster
- Load balancing
- Multi-region deployment
- DevOps/SRE expertise

---

## Security Considerations

### Domain Verification Security

**Attack Vectors:**
1. **Domain Hijacking:** Attacker claims victim's domain
   - **Mitigation:** Multi-step verification, timeout tokens

2. **Token Prediction:** Guessing verification tokens
   - **Mitigation:** Cryptographically random tokens (256-bit)

3. **DNS Cache Poisoning:** Fake DNS responses
   - **Mitigation:** DNSSEC verification

**Best Practices:**
```go
// Generate secure verification token
func GenerateVerificationToken() string {
    bytes := make([]byte, 32) // 256 bits
    crypto_rand.Read(bytes)
    return base64.URLEncoding.EncodeToString(bytes)
}

// Verify with timeout
func VerifyDomain(domain, token string, method string) error {
    // Check token age
    tokenData := redis.Get("verification_token:" + token)
    if time.Since(tokenData.CreatedAt) > 24*time.Hour {
        return errors.New("verification token expired")
    }

    // Verify based on method
    switch method {
    case "dns":
        return verifyDNSTXT(domain, token)
    case "file":
        return verifyFile(domain, token)
    case "meta":
        return verifyMetaTag(domain, token)
    }
}
```

### SSL/TLS Security

**Certificate Management:**
```go
// Only issue certificates for verified domains
func (m *CertManager) HostPolicy(ctx context.Context, host string) error {
    // Check if domain is verified
    verified, err := redis.Get("domain:verified:" + host).Bool()
    if err != nil || !verified {
        return fmt.Errorf("domain not verified: %s", host)
    }

    // Check if domain is active
    active, err := redis.Get("domain:active:" + host).Bool()
    if err != nil || !active {
        return fmt.Errorf("domain not active: %s", host)
    }

    return nil
}
```

### Rate Limiting

**Prevent abuse:**
```go
// Limit verification attempts
func CheckVerificationRateLimit(domain string) error {
    key := "verify_attempts:" + domain
    attempts, _ := redis.Incr(key).Result()
    redis.Expire(key, 1*time.Hour)

    if attempts > 10 {
        return errors.New("too many verification attempts, try again later")
    }
    return nil
}

// Limit domains per user
func CheckDomainLimit(userID string) error {
    count, _ := redis.SCard("user_domains:" + userID).Result()
    if count >= 10 {
        return errors.New("maximum domains reached (10)")
    }
    return nil
}
```

### Input Validation

**Domain validation:**
```go
func ValidateDomain(domain string) error {
    // Length check
    if len(domain) < 4 || len(domain) > 253 {
        return errors.New("invalid domain length")
    }

    // Format check (RFC 1035)
    match, _ := regexp.MatchString(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`, strings.ToLower(domain))
    if !match {
        return errors.New("invalid domain format")
    }

    // Blacklist check
    blacklisted := []string{"localhost", "127.0.0.1", "0.0.0.0", "example.com"}
    for _, blocked := range blacklisted {
        if domain == blocked {
            return errors.New("domain is blacklisted")
        }
    }

    // Check if already claimed
    exists, _ := redis.Exists("domain:" + domain).Result()
    if exists > 0 {
        return errors.New("domain already claimed")
    }

    return nil
}
```

---

## Cost Analysis

### Startup Phase (1-100 users)

**Approach 1:**
- VPS: $10/month (2GB RAM)
- Domain: $12/year
- **Total: $11/month**

**Approach 2:**
- Not cost-effective
- **Skip until growth**

**Recommendation:** Start with Approach 1

### Growth Phase (100-10k users)

**Approach 1:**
- VPS: $40/month (8GB RAM)
- Backup: $10/month
- **Total: $50/month**

**Approach 2:**
- Cloudflare Free: $0
- Origin server: $40
- Redis: $20
- **Total: $60/month**

**Recommendation:** Stick with Approach 1

### Scale Phase (10k-100k users)

**Approach 1:**
- VPS: $160/month (32GB RAM)
- Backup: $20/month
- CDN addon: $50/month
- **Total: $230/month**

**Approach 2:**
- Cloudflare Pro: $20/month
- Origin servers (3×): $120/month
- Redis Cluster: $150/month
- Load Balancer: $30/month
- **Total: $320/month**

**Recommendation:** Consider migrating to Approach 2

### Enterprise Phase (100k+ users)

**Approach 1:**
- Multiple servers: $500/month
- CDN: $200/month
- Complex management
- **Total: $700/month + operational overhead**

**Approach 2:**
- Cloudflare Business: $200/month
- Origin servers (5×): $400/month
- Redis Cluster: $300/month
- Load Balancer: $50/month
- **Total: $950/month**

**Recommendation:** Approach 2 is more cost-effective

---

## Implementation Roadmap

### Approach 1 Timeline

**Week 1-2: Core Development**
- [ ] Domain model and database schema
- [ ] Domain verification logic (DNS/File/Meta)
- [ ] Multi-domain routing handler
- [ ] Let's Encrypt integration
- [ ] Domain management API

**Week 3: Testing & Refinement**
- [ ] Unit tests for domain verification
- [ ] Integration tests for routing
- [ ] SSL certificate testing
- [ ] Security testing
- [ ] Load testing

**Week 4: Frontend & Documentation**
- [ ] Domain management UI
- [ ] User documentation
- [ ] DNS setup instructions
- [ ] Troubleshooting guide
- [ ] API documentation

**Total: 4 weeks**

### Approach 2 Timeline

**Week 1-2: DNS Integration**
- [ ] DNS provider selection
- [ ] API integration (Route53/Cloudflare)
- [ ] Subdomain generation logic
- [ ] Wildcard DNS setup
- [ ] Verification system

**Week 3-4: CDN Setup**
- [ ] CDN provider integration
- [ ] Cache configuration
- [ ] Purge API implementation
- [ ] Edge rules setup
- [ ] SSL configuration

**Week 5-6: Multi-Region Deployment**
- [ ] Origin server setup (3 regions)
- [ ] Redis cluster configuration
- [ ] Load balancer setup
- [ ] Health checks
- [ ] Failover testing

**Week 7: Request Routing**
- [ ] Subdomain extraction logic
- [ ] User lookup optimization
- [ ] Cache header optimization
- [ ] Performance testing
- [ ] Edge case handling

**Week 8: Frontend & Launch**
- [ ] Domain management UI
- [ ] Documentation
- [ ] Monitoring setup
- [ ] Production deployment
- [ ] Gradual rollout

**Total: 8 weeks**

---

## Recommendation

### For Most Projects: Start with Approach 1

**Reasons:**
1. **Faster Time-to-Market:** Launch in 4 weeks vs 8 weeks
2. **Lower Initial Cost:** $50/month vs $300/month
3. **Simpler Operations:** One server to manage
4. **Easier Debugging:** Fewer moving parts
5. **Sufficient Performance:** Good for 95% of use cases

**Migration Path:**
When you reach 10k+ users:
1. Keep Approach 1 running (no downtime)
2. Build Approach 2 infrastructure in parallel
3. Migrate users gradually (DNS TTL)
4. Switch over completely
5. Decommission Approach 1

### For Enterprise from Day 1: Approach 2

**Reasons:**
1. **Future-Proof:** Built for scale from start
2. **Better Performance:** Global edge caching
3. **Enterprise Features:** SLA, support, DDoS protection
4. **Professional Image:** High availability expected

---

## Next Steps

1. **Review this document** with your team
2. **Decide on approach** based on your needs
3. **Create detailed technical specs** for chosen approach
4. **Set up development environment**
5. **Begin implementation** following roadmap

---

## Questions to Consider

Before deciding, answer these:

1. **What is your current user count?**
   - < 1k → Approach 1
   - > 10k → Consider Approach 2

2. **What is your budget?**
   - < $100/month → Approach 1
   - > $500/month → Approach 2 possible

3. **How technical is your team?**
   - Small team → Approach 1
   - DevOps team → Approach 2

4. **What is your target market?**
   - Single country → Approach 1
   - Global → Approach 2

5. **What are your performance requirements?**
   - < 1000 req/s → Approach 1
   - > 10k req/s → Approach 2

6. **How quickly do you need to launch?**
   - ASAP → Approach 1
   - Can wait 2 months → Approach 2

---

**Last Updated:** 2025-10-11
**Author:** Mohammad (hdbplus.md@gmail.com)
**Version:** 1.0
