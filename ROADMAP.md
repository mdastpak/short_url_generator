# Short URL Generator - Development Roadmap

This document outlines planned features and improvements for the URL shortening service.

---

## 🚀 Planned Features

### 1. User-Specific URL Paths (High Priority)

**Status:** Planned
**Target Version:** v2.1.0

#### Overview
Add optional user-namespaced URL paths for authenticated users to create branded, memorable short URLs.

#### Feature Description
Allow users to create short URLs under their personal namespace:
- **Format:** `{domain}/{userSlug}/{shortURL}`
- **Example:** `localhost:8080/john_doe/summer_sale`
- **Backwards Compatible:** Direct URLs still work: `localhost:8080/summer_sale`

#### Implementation Options

##### Option 1: User ID (UUID-based)
- **URLs:** `localhost:8080/f00c5219-9316-4342-8ebf-cc7fab22dde2/abc123`
- **Pros:**
  - Already exists in User model
  - Guaranteed unique
  - No validation needed
- **Cons:**
  - Very long, ugly URLs
  - Not user-friendly
  - Exposes internal UUIDs
  - Not memorable or brandable

##### Option 2: User-Friendly Slug (RECOMMENDED ✅)
- **URLs:** `localhost:8080/john_doe/abc123` or `localhost:8080/mycompany/promo2025`
- **Pros:**
  - Short, clean, professional
  - Brandable and memorable
  - User identity/personal branding
  - Marketing-friendly
- **Cons:**
  - Requires new field in User model
  - Needs uniqueness validation
  - Requires slug generation logic

##### Option 3: Sequential User Number
- **URLs:** `localhost:8080/user_1/abc123`, `localhost:8080/user_2/abc123`
- **Pros:**
  - Simple implementation
  - Short and consistent
  - Auto-incrementing
- **Cons:**
  - Not memorable or meaningful
  - Reveals total user count
  - No branding value
  - Not professional

#### Recommended Implementation (Option 2)

**Database Schema Changes:**
```go
// model/user.go
type User struct {
    ID           string    `json:"id"`
    Email        string    `json:"email"`
    UserSlug     string    `json:"userSlug"`     // NEW: Unique, URL-friendly identifier
    PasswordHash string    `json:"passwordHash"`
    Verified     bool      `json:"verified"`
    CreatedAt    time.Time `json:"createdAt"`
    // ... existing fields
}
```

**Slug Validation Rules:**
- Pattern: `^[a-z0-9_-]{3,30}$`
- Lowercase letters, numbers, underscore, hyphen only
- Length: 3-30 characters
- Must be unique across all users
- Reserved slugs: `admin`, `api`, `health`, `swagger`, `preview`, `qr`

**Auto-generation Logic:**
- Extract from email: `john@example.com` → `john`
- If taken, append number: `john_1`, `john_2`, etc.
- Allow user to customize during/after registration

**Routing Changes:**
```go
// main.go - Route priority order
r.HandleFunc("/{userSlug}/{shortURL}", urlHandler.RedirectURL).Methods("GET")  // NEW: User-namespaced
r.HandleFunc("/{shortURL}", urlHandler.RedirectURL).Methods("GET")             // Existing: Direct redirect
```

**Handler Logic:**
```go
// handler/handler.go - RedirectURL updates
func (h *URLHandler) RedirectURL(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)

    // Check if request has userSlug (2 path segments)
    if userSlug, ok := vars["userSlug"]; ok {
        // User-namespaced URL: /{userSlug}/{shortURL}
        shortURL := vars["shortURL"]

        // Validate user slug exists
        userExists := h.validateUserSlug(ctx, userSlug)
        if !userExists {
            SendJSONError(w, http.StatusNotFound, errors.New("user not found"), "User slug does not exist")
            return
        }

        // Proceed with redirect using shortURL
        // ... existing redirect logic
    } else {
        // Direct URL: /{shortURL}
        shortURL := vars["shortURL"]
        // ... existing redirect logic
    }
}
```

**Frontend Updates:**
- Display user slug in profile section
- Allow editing user slug (with real-time uniqueness check)
- Show both URL formats:
  - User-namespaced: `http://localhost:8080/{userSlug}/{shortURL}`
  - Direct: `http://localhost:8080/{shortURL}`
- Add "Copy with user slug" and "Copy direct" buttons

**Configuration:**
```yaml
user_features:
  user_slug_enabled: true           # Enable/disable user slug feature
  require_unique_slug: true         # Enforce uniqueness
  allow_slug_change: true           # Allow users to change slug after registration
  reserved_slugs:                   # System-reserved slugs
    - admin
    - api
    - health
    - swagger
    - preview
    - qr
    - user
    - system
```

#### Benefits
✅ Professional, brandable URLs
✅ User identity and personal branding
✅ Easy to remember and share
✅ Marketing-friendly (companies can use brand name)
✅ Backwards compatible (direct URLs still work)
✅ Optional feature (can be disabled via config)
✅ No breaking changes to existing functionality
✅ SEO-friendly (user/brand name in URL)

#### Migration Strategy
1. Add `UserSlug` field to User model
2. Create migration script to auto-generate slugs for existing users
3. Add uniqueness validation
4. Update routing to support both patterns
5. Update frontend to display and manage user slugs
6. Add feature flag for gradual rollout

#### Example Use Cases

**Personal Branding:**
- `mysite.com/john_doe/portfolio`
- `mysite.com/john_doe/resume`
- `mysite.com/john_doe/contact`

**Company/Team:**
- `mysite.com/acme_corp/sale2025`
- `mysite.com/marketing_team/campaign`
- `mysite.com/hr/job_posting`

**Content Creators:**
- `mysite.com/tech_blogger/article1`
- `mysite.com/photographer/gallery`
- `mysite.com/youtuber/latest_video`

#### Files to Modify
1. `model/user.go` - Add UserSlug field
2. `handler/user.go` - Add slug validation, generation, CRUD operations
3. `handler/handler.go` - Update RedirectURL to handle both patterns
4. `main.go` - Add new route for `/{userSlug}/{shortURL}`
5. `handler/user_panel.html` - UI for slug management and URL display
6. `config/config.go` - Add user slug configuration options
7. `CLAUDE.md` - Document new feature architecture

#### Testing Requirements
- Unit tests for slug validation
- Unit tests for slug generation from email
- Integration tests for both redirect patterns
- Conflict handling (slug already taken)
- Reserved slug validation
- Frontend slug editing with real-time validation

---

## 📋 Other Planned Features

### 2. Analytics Dashboard (Medium Priority)
**Status:** Planned
**Target Version:** v2.2.0

- Click tracking and visualization
- Geographic data (country, city)
- Device/browser statistics
- Referrer tracking
- Time-series graphs
- Export to CSV/JSON

### 3. URL Collections/Folders (Medium Priority)
**Status:** Planned
**Target Version:** v2.3.0

- Organize URLs into collections
- Nested folder structure
- Bulk operations on collections
- Share entire collections

### 4. Team/Organization Support (Low Priority)
**Status:** Planned
**Target Version:** v3.0.0

- Multi-user organizations
- Role-based access control
- Team-wide URL management
- Usage quotas per team
- Billing integration

### 5. Custom Branded Domains (Medium-High Priority)
**Status:** Planned - Analysis Complete
**Target Version:** v2.5.0
**Documentation:** See [CUSTOM_DOMAINS.md](CUSTOM_DOMAINS.md)

Complete custom domain support allowing users to serve short URLs through their own branded domains (e.g., `gog.le` instead of the main service domain).

**Two Implementation Approaches Available:**

#### Approach 1: Reverse Proxy (Recommended for v2.5.0)
- **Timeline:** 4 weeks
- **Cost:** $50-100/month
- **Complexity:** Low
- **Best For:** Startups, SMBs, initial launch

**Features:**
- Domain verification (DNS TXT, File, Meta Tag)
- Automatic SSL with Let's Encrypt
- Multi-domain routing via Host header
- Domain ownership verification
- User-friendly management UI

**Technical Details:**
- Users point their domain DNS to your server
- Application inspects Host header to route requests
- Let's Encrypt handles SSL certificates automatically
- Single server entry point
- Performance: Good (100-300ms latency)
- Scalability: Medium (up to 10k requests/second)

#### Approach 2: DNS-Based Routing (Future Upgrade)
- **Timeline:** 8 weeks
- **Cost:** $300-1000/month
- **Complexity:** High
- **Best For:** Enterprise, high-traffic, global scale

**Features:**
- User-specific subdomains on your infrastructure
- Global CDN integration (Cloudflare/CloudFront)
- Multi-region deployment
- Edge caching (95%+ cache hit ratio)
- Built-in DDoS protection
- 99.99% uptime SLA

**Technical Details:**
- Automatic subdomain generation per user
- DNS CNAME routing to user subdomains
- CDN edge caching for global performance
- Multi-region origin servers
- Performance: Excellent (5-50ms latency globally)
- Scalability: Very high (millions of requests/second)

**Implementation Decision:**
- **Phase 1 (v2.5.0):** Launch with Approach 1 (Reverse Proxy)
- **Phase 2 (v3.1.0):** Upgrade to Approach 2 when traffic demands it

**Migration Path:**
- Start simple, upgrade when needed
- Zero downtime migration possible
- Gradual DNS cutover
- All data remains compatible

### 6. Link-in-Bio Feature (Low Priority)
**Status:** Planned
**Target Version:** v3.2.0

- Single landing page with multiple links
- Customizable themes
- Social media integration
- Analytics for each link

### 7. API Rate Limiting per User (Medium Priority)
**Status:** Planned
**Target Version:** v2.4.0

- Per-user rate limits
- Tiered plans (free/pro/enterprise)
- API key management
- Usage dashboards

### 8. Webhook Support (Low Priority)
**Status:** Planned
**Target Version:** v3.3.0

- Webhook on URL click
- Webhook on URL expiry
- Custom payload format
- Retry logic with exponential backoff

---

## 🐛 Known Issues & Improvements

### Performance Optimization
- [ ] Implement connection pooling optimization
- [ ] Add read replicas for Redis
- [ ] Optimize cache hit ratio
- [ ] Add CDN support for static assets

### Security Enhancements
- [ ] Add 2FA support
- [ ] Implement IP whitelisting for admin panel
- [ ] Add audit logs for sensitive operations
- [ ] Enhance bot detection with ML models

### DevOps & Infrastructure
- [ ] Docker Compose for local development
- [ ] Kubernetes deployment manifests
- [ ] CI/CD pipeline setup
- [ ] Automated backup and restore
- [ ] Monitoring and alerting (Prometheus/Grafana)

### Documentation
- [ ] API client libraries (Python, JavaScript, Go)
- [ ] Video tutorials
- [ ] Architecture diagrams
- [ ] Performance benchmarks
- [ ] Security best practices guide

---

## 📝 Version History

### v2.0.0 (Current)
- ✅ User authentication and registration
- ✅ JWT-based auth with refresh tokens
- ✅ Email verification (OTP)
- ✅ User panel with dark mode
- ✅ URL management (create, edit, delete)
- ✅ Advanced URL features (scheduling, password protection, max usage)
- ✅ Admin dashboard
- ✅ QR code generation
- ✅ URL preview (anti-phishing)
- ✅ Deduplication
- ✅ In-memory caching
- ✅ Bot detection
- ✅ Security scanning (malware/phishing)

### v1.0.0
- ✅ Basic URL shortening
- ✅ Redis persistence
- ✅ Rate limiting
- ✅ CORS support
- ✅ Graceful shutdown
- ✅ Swagger documentation

---

## 🤝 Contributing

We welcome contributions! If you'd like to work on any of these features:

1. Check if there's an open issue for the feature
2. Comment on the issue to claim it
3. Fork the repository
4. Create a feature branch
5. Submit a pull request

---

## 📞 Feedback

Have ideas for new features? Open an issue on GitHub with the `feature-request` label.

---

**Last Updated:** 2025-10-11
**Maintainer:** Mohammad (hdbplus.md@gmail.com)
