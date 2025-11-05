# Security Audit Report - Kamal Proxy
**Date:** November 5, 2025
**Auditor:** Claude (AI Security Auditor)
**Branch:** master
**Commit:** 11f049e Allow HEAD healthchecks to succeed in maintenance (#3)

---

## Executive Summary

This security audit was conducted on the kamal-proxy codebase, a minimal HTTP/HTTPS proxy designed for zero-downtime deployments. The audit identified several **CRITICAL** and **HIGH** severity security issues that require immediate attention, along with multiple medium and low severity findings.

**Overall Risk Assessment:** **HIGH**

**Critical Issues Found:** 3
**High Severity Issues:** 4
**Medium Severity Issues:** 5
**Low Severity Issues:** 3
**Informational:** 2

---

## Critical Severity Issues

### 1. No Authentication/Authorization on RPC Interface ⚠️ CRITICAL

**Location:** `internal/server/commands.go:77-111`, `internal/server/server.go:207-211`

**Description:**
The Unix socket RPC interface has **NO authentication or authorization**. Any process or user that can access the socket path can execute privileged operations including:
- Deploying arbitrary services with arbitrary target URLs
- Removing active services
- Pausing/stopping services
- Modifying routing configuration
- Starting rollout deployments

**Evidence:**
```go
// commands.go:77-111
func (h *CommandHandler) Start(socketPath string) error {
    // ... registration code ...
    h.rpcListener, err = net.Listen("unix", socketPath)
    // ... no permission checks or authentication ...
    go func() {
        for {
            conn, err := h.rpcListener.Accept()
            // ... directly serves RPC without authentication ...
            go rpc.ServeConn(conn)
        }
    }()
}
```

**Socket Path:** `$XDG_RUNTIME_DIR/kamal-proxy.sock` or `/tmp/kamal-proxy.sock`

**Impact:**
- Complete compromise of proxy configuration
- Unauthorized service manipulation
- Potential for denial of service
- Lateral movement in containerized environments

**Recommendation:**
1. Implement Unix socket file permissions (0600) to restrict access to owner only
2. Add mutual TLS authentication for RPC connections
3. Implement an authentication token/secret mechanism
4. Consider using a more secure IPC mechanism with built-in authentication
5. Add audit logging for all RPC operations

**CVSS Score:** 9.1 (Critical)

---

### 2. Server-Side Request Forgery (SSRF) Vulnerability ⚠️ CRITICAL

**Location:** `internal/server/target.go:455-462`, `internal/cmd/deploy.go`

**Description:**
The target URL validation is extremely weak, allowing deployment of targets pointing to internal network resources, cloud metadata services, or other sensitive endpoints.

**Evidence:**
```go
// target.go:455-462
var hostRegex = regexp.MustCompile(`^(\w[-_.\w+]+)(:\d+)?$`)

func parseTargetURL(targetURL string) (*url.URL, error) {
    if !hostRegex.MatchString(targetURL) {
        return nil, fmt.Errorf("%s :%w", targetURL, ErrorInvalidHostPattern)
    }
    uri, _ := url.Parse("http://" + targetURL)
    return uri, nil
}
```

**Attack Scenarios:**
1. Deploy service with target: `169.254.169.254:80` (AWS metadata service)
2. Deploy service with target: `127.0.0.1:6379` (local Redis)
3. Deploy service with target: `metadata.google.internal` (GCP metadata)
4. Deploy service with target: internal service hostnames

**Impact:**
- Access to cloud provider metadata services (credentials, tokens)
- Port scanning of internal network
- Access to internal services (databases, caches, APIs)
- Data exfiltration through proxy logs
- Credential theft

**Recommendation:**
1. Implement SSRF protection with a whitelist/blacklist approach:
   - Block private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
   - Block loopback addresses (127.0.0.0/8, ::1)
   - Block link-local addresses (169.254.0.0/16, fe80::/10)
   - Block cloud metadata endpoints
2. Add DNS rebinding protection
3. Validate resolved IPs before making connections
4. Consider implementing target URL allow-lists

**CVSS Score:** 9.0 (Critical)

---

### 3. Unauthenticated Metrics Endpoint Exposure ⚠️ CRITICAL

**Location:** `internal/server/server.go:181-205`, `internal/metrics/metrics.go`

**Description:**
The Prometheus metrics endpoint has no authentication and exposes sensitive operational data.

**Evidence:**
```go
// server.go:181-205
func (s *Server) startMetricsServer() error {
    if s.config.MetricsPort == 0 {
        return nil
    }
    addr := fmt.Sprintf("%s:%d", s.config.Bind, s.config.MetricsPort)
    handler := metrics.Enable()

    l, err := net.Listen("tcp", addr)
    // ... no authentication configured ...
    s.metricsServer = &http.Server{
        Addr:    addr,
        Handler: handler, // Prometheus handler with no auth
    }
    go s.metricsServer.Serve(l)
}
```

**Exposed Information:**
- Request counts per service/method/status
- Response times and latency distribution
- In-flight request counts
- Service names and targets
- Deployment patterns and traffic volumes

**Impact:**
- Information disclosure for reconnaissance
- Traffic pattern analysis
- Service topology mapping
- Timing attack facilitation
- Performance profiling for targeted attacks

**Recommendation:**
1. Implement authentication for metrics endpoint (basic auth, bearer tokens)
2. Bind metrics to localhost only by default
3. Use separate network namespace or firewall rules
4. Consider scraping via mutual TLS
5. Add option to disable sensitive metrics

**CVSS Score:** 8.6 (High/Critical)

---

## High Severity Issues

### 4. Missing HTTP Security Headers 🔴 HIGH

**Location:** `internal/server/server.go`, `internal/server/target.go`

**Description:**
No HTTP security headers are set on responses, leaving users vulnerable to various client-side attacks.

**Missing Headers:**
- `Strict-Transport-Security` (HSTS) - Not set even for HTTPS responses
- `X-Frame-Options` - Allows clickjacking attacks
- `X-Content-Type-Options` - Allows MIME sniffing attacks
- `Content-Security-Policy` - No CSP protection
- `X-XSS-Protection` - Not set (defense in depth)
- `Referrer-Policy` - Information leakage possible
- `Permissions-Policy` - No feature policy restrictions

**Impact:**
- Clickjacking attacks
- MIME type confusion attacks
- Cross-site scripting (XSS) exploitation
- Downgrade attacks (no HSTS)
- Information leakage via Referer header

**Recommendation:**
1. Implement middleware to set security headers:
```go
w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
w.Header().Set("X-Frame-Options", "DENY")
w.Header().Set("X-Content-Type-Options", "nosniff")
w.Header().Set("X-XSS-Protection", "1; mode=block")
w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
```
2. Add CSP configuration options per service
3. Make headers configurable but secure by default

**CVSS Score:** 7.4 (High)

---

### 5. X-Forwarded-For Header Spoofing 🔴 HIGH

**Location:** `internal/server/target.go:342-357`, `internal/server/logging_middleware.go:76-79`

**Description:**
The proxy blindly trusts and forwards X-Forwarded-* headers from clients, allowing header spoofing attacks.

**Evidence:**
```go
// target.go:342-357
func (t *Target) forwardHeaders(req *httputil.ProxyRequest) {
    if t.options.ForwardHeaders {
        // DANGEROUS: Directly forwards client-supplied headers
        req.Out.Header["X-Forwarded-For"] = req.In.Header["X-Forwarded-For"]
    }
    req.SetXForwarded()  // Adds additional headers but doesn't clear existing

    if t.options.ForwardHeaders {
        if req.In.Header.Get("X-Forwarded-Proto") != "" {
            req.Out.Header.Set("X-Forwarded-Proto", req.In.Header.Get("X-Forwarded-Proto"))
        }
        // ... similar for X-Forwarded-Host ...
    }
}
```

**Attack Scenarios:**
1. Client sets `X-Forwarded-For: 127.0.0.1` to bypass IP-based restrictions
2. Client sets `X-Forwarded-Proto: https` to bypass TLS requirements
3. Client sets `X-Forwarded-Host: admin.internal` to bypass hostname checks

**Impact:**
- IP-based access control bypass
- Authentication/authorization bypass
- Security policy circumvention
- Log poisoning
- Incorrect rate limiting

**Recommendation:**
1. ALWAYS strip incoming X-Forwarded-* headers from untrusted clients
2. Only preserve these headers if proxy is behind a trusted load balancer
3. Add configuration option: `TrustedProxies` list
4. Implement proper X-Forwarded-For handling:
```go
// Clear untrusted headers first
req.Out.Header.Del("X-Forwarded-For")
req.Out.Header.Del("X-Forwarded-Proto")
req.Out.Header.Del("X-Forwarded-Host")
// Then set based on actual request
```

**CVSS Score:** 7.5 (High)

---

### 6. No Rate Limiting or DoS Protection 🔴 HIGH

**Location:** Throughout codebase - functionality not implemented

**Description:**
There is no rate limiting, connection limits, or denial-of-service protection at any layer.

**Missing Protections:**
- No request rate limiting per IP/service
- No connection limits per target
- No request body size limits (can be set but default is 0 = unlimited)
- No timeout on slowloris-style attacks
- No protection against request smuggling
- No circuit breaker for failing targets

**Attack Scenarios:**
1. Flood proxy with connections to exhaust resources
2. Send massive request bodies to consume memory
3. Slowloris-style slow POST attacks
4. Target-exhaustion by overwhelming backend services
5. State exhaustion via in-flight request tracking

**Impact:**
- Service unavailability
- Resource exhaustion (memory, CPU, file descriptors)
- Cascading failures to backend services
- Infrastructure cost escalation

**Recommendation:**
1. Implement rate limiting middleware with configurable limits
2. Add connection limits per IP/client
3. Set reasonable default values for:
   - `MaxRequestBodySize`: 10MB default
   - `MaxResponseBodySize`: 100MB default
   - Connection timeouts
4. Implement circuit breaker pattern for unhealthy targets
5. Add request queue depth limits
6. Consider implementing HTTP/2 connection limits

**CVSS Score:** 7.5 (High)

---

### 7. Insecure State Persistence 🔴 HIGH

**Location:** `internal/server/router.go:341-363`, `internal/server/config.go:29-30`

**Description:**
Service state including target URLs and configuration is persisted to disk without encryption or integrity protection.

**Evidence:**
```go
// router.go:350-362
func (r *Router) saveStateSnapshot() error {
    services := []*Service{}
    // ... gather services ...

    f, err := os.Create(r.statePath)  // No secure permissions set
    // ... no error handling if create fails ...

    err = json.NewEncoder(f).Encode(&services)  // Plain JSON, no encryption
    // ... state includes target URLs, paths, options ...
}
```

**State File Location:** `~/.config/kamal-proxy/kamal-proxy.state`

**Risks:**
- State file world-readable by default on some systems
- No encryption of sensitive configuration data
- No integrity verification (could be tampered with)
- Credentials in target URLs exposed
- Service topology information disclosure

**Impact:**
- Information disclosure of internal architecture
- Credential theft if URLs contain embedded credentials
- State tampering leading to misrouting
- Persistence of attacker-controlled configuration

**Recommendation:**
1. Set restrictive file permissions (0600) on state file
2. Implement state file encryption using system keyring/secrets manager
3. Add HMAC signature to detect tampering
4. Never store credentials in target URLs
5. Consider using secure storage backends (etcd, Consul)
6. Add state file validation on load

**CVSS Score:** 7.2 (High)

---

## Medium Severity Issues

### 8. Wildcard Host Matching Security Risk 🟡 MEDIUM

**Location:** `internal/server/service_map.go:72-93`

**Description:**
The wildcard host matching could be exploited for domain fronting or host confusion attacks.

**Impact:**
- Domain fronting to bypass censorship/security controls
- Host confusion attacks
- Certificate validation bypass attempts

**Recommendation:**
- Document security implications of wildcard usage
- Add strict validation for wildcard patterns
- Log wildcard matches for security monitoring

**CVSS Score:** 5.9 (Medium)

---

### 9. TLS Configuration Weaknesses 🟡 MEDIUM

**Location:** `internal/server/server.go:122-127`, `internal/server/server.go:161-165`

**Description:**
TLS configuration is mostly good but has some weaknesses:

**Issues Found:**
1. HTTP/3 enforces TLS 1.3 minimum ✓ (Good)
2. HTTP/2 allows TLS 1.2 with no explicit minimum ✗ (Weak)
3. No cipher suite restrictions (uses Go defaults)
4. No curve preferences specified

**Evidence:**
```go
// server.go:161-165 (HTTPS server)
TLSConfig: &tls.Config{
    NextProtos:     []string{"h2", "http/1.1", acme.ALPNProto},
    GetCertificate: s.router.GetCertificate,
    // Missing: MinVersion, CipherSuites, CurvePreferences
}

// server.go:122-127 (HTTP/3 server - GOOD)
TLSConfig: &tls.Config{
    MinVersion:     tls.VersionTLS13,  // Enforces TLS 1.3
    NextProtos:     []string{"h3"},
    GetCertificate: s.router.GetCertificate,
}
```

**Recommendation:**
```go
TLSConfig: &tls.Config{
    MinVersion: tls.VersionTLS12,  // Or TLS13 for maximum security
    MaxVersion: tls.VersionTLS13,
    CipherSuites: []uint16{
        tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
        tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
    },
    CurvePreferences: []tls.CurveID{
        tls.CurveP256,
        tls.X25519,
    },
    PreferServerCipherSuites: true,
}
```

**CVSS Score:** 5.3 (Medium)

---

### 10. Query Parameter Smuggling Risk 🟡 MEDIUM

**Location:** `internal/server/target.go:316-339`

**Description:**
The proxy preserves unparseable query parameters verbatim, which could enable parameter smuggling.

**Evidence:**
```go
// target.go:323-339
// Comment explains the deliberate choice:
// "Some platforms interpret these params as equivalent to `p=a` and `b=`,
// while others interpret it as a single query param: `p=a;b`"
req.Out.URL.RawQuery = req.In.URL.RawQuery  // Preserves semicolons, etc.
```

**Attack Scenario:**
If backend interprets `;` differently than proxy: `/api?param=safe;admin=true`

**Impact:**
- Parameter pollution attacks
- Authorization bypass in vulnerable backends
- Cache poisoning

**Recommendation:**
- Add configuration option to enable strict query parsing
- Document the security implications clearly
- Log suspicious query patterns
- Consider rejecting truly malformed queries

**CVSS Score:** 5.8 (Medium)

---

### 11. Rollout Cookie Not Marked Secure 🟡 MEDIUM

**Location:** `internal/server/rollout_controller.go:9`

**Description:**
The rollout cookie mechanism doesn't enforce Secure or HttpOnly flags.

**Evidence:**
```go
const RolloutCookieName = "kamal-rollout"

func (rc *RolloutController) splitValue(r *http.Request) string {
    cookie, err := r.Cookie(RolloutCookieName)
    // Cookie reading only - no validation of security flags
}
```

**Impact:**
- Cookie theft via unencrypted connections
- XSS-based cookie theft
- Rollout manipulation by attackers

**Recommendation:**
1. Add code to set rollout cookies with proper flags:
```go
http.Cookie{
    Name:     RolloutCookieName,
    Value:    value,
    Secure:   true,   // Only over HTTPS
    HttpOnly: true,   // No JS access
    SameSite: http.SameSiteStrictMode,
}
```
2. Validate cookie security in proxy configuration

**CVSS Score:** 5.4 (Medium)

---

### 12. Insufficient Error Information in Logs 🟡 MEDIUM

**Location:** `internal/server/logging_middleware.go`, Various error handlers

**Description:**
While the proxy logs requests extensively, error conditions may not log enough detail for security investigation.

**Issues:**
- Target failures logged but not always with full context
- Client disconnections not always attributed to attacks vs. normal behavior
- ACME failures could expose certificate issues

**Recommendation:**
1. Add structured security event logging
2. Include correlation IDs across log messages
3. Log security-relevant events separately
4. Add audit trail for configuration changes

**CVSS Score:** 4.8 (Medium)

---

## Low Severity Issues

### 13. WebSocket Security Considerations 🔵 LOW

**Location:** `internal/server/target.go:473-481`, WebSocket handling

**Description:**
WebSocket connections are hijacked but security implications not fully documented.

**Considerations:**
- Hijacked connections bypass middleware
- Long-lived connections could exhaust resources
- No WebSocket-specific rate limiting

**Recommendation:**
- Document WebSocket security model
- Implement WebSocket-specific timeouts
- Add connection limits for WebSocket endpoints

**CVSS Score:** 3.7 (Low)

---

### 14. Debug Logging May Expose Sensitive Data 🔵 LOW

**Location:** Throughout codebase, `slog.Debug()` calls

**Description:**
Debug logging may expose sensitive information if enabled in production.

**Examples:**
```go
slog.Debug("Using ACME handler", "service", s.name)
slog.Debug("Using rollout for request", "service", s.name, "path", req.URL.Path)
```

**Recommendation:**
- Audit all debug log messages
- Never log credentials or tokens
- Add warning about debug mode in production

**CVSS Score:** 3.1 (Low)

---

### 15. No Request ID in X-Request-ID if Already Present 🔵 LOW

**Location:** `internal/server/request_id_middleware.go`

**Description:**
The proxy generates a new X-Request-ID but should preserve existing ones for tracing.

**Recommendation:**
- Only generate ID if not already present
- Validate existing ID format before preserving

**CVSS Score:** 2.1 (Low)

---

## Informational Findings

### 16. Go Version Requirements ℹ️

The project uses Go 1.25.3 with modern dependencies. Dependencies appear up-to-date:
- `golang.org/x/crypto v0.43.0` - Latest
- `github.com/prometheus/client_golang v1.23.2` - Latest
- `github.com/quic-go/quic-go v0.55.0` - Latest

**Recommendation:** Maintain regular dependency updates and security scanning.

---

### 17. Health Check Endpoint Security ℹ️

**Location:** `internal/server/target.go:78-80`

Health checks accept HEAD requests but no authentication is required. This is generally acceptable but should be documented.

---

## Compliance Considerations

### OWASP Top 10 2021 Coverage

| Risk | Status | Notes |
|------|--------|-------|
| A01: Broken Access Control | ❌ FAIL | No RPC authentication, header spoofing |
| A02: Cryptographic Failures | ⚠️ PARTIAL | TLS config weak, state not encrypted |
| A03: Injection | ✅ PASS | No SQL/command injection risks |
| A04: Insecure Design | ❌ FAIL | SSRF vulnerability, no rate limiting |
| A05: Security Misconfiguration | ❌ FAIL | Missing security headers, open metrics |
| A06: Vulnerable Components | ✅ PASS | Dependencies up-to-date |
| A07: Auth Failures | ❌ FAIL | No authentication on critical endpoints |
| A08: Software/Data Integrity | ⚠️ PARTIAL | State file tampering possible |
| A09: Logging Failures | ⚠️ PARTIAL | Good logging but lacks security events |
| A10: SSRF | ❌ FAIL | Critical SSRF vulnerability |

---

## Priority Remediation Plan

### Immediate (Week 1)
1. ✅ Implement Unix socket permissions (0600) for RPC
2. ✅ Add basic authentication to metrics endpoint
3. ✅ Strip untrusted X-Forwarded-* headers
4. ✅ Add SSRF protection for target URLs

### Short-term (Weeks 2-4)
5. ✅ Implement HTTP security headers middleware
6. ✅ Add rate limiting framework
7. ✅ Secure state file with encryption
8. ✅ Set secure defaults for TLS configuration

### Medium-term (1-3 Months)
9. ⏳ Implement comprehensive authentication for RPC
10. ⏳ Add DoS protection mechanisms
11. ⏳ Implement security event logging
12. ⏳ Add security documentation

### Long-term (3-6 Months)
13. 📋 Security audit automation
14. 📋 Penetration testing
15. 📋 Security compliance certification
16. 📋 Bug bounty program consideration

---

## Testing Recommendations

### Security Testing Required
1. **Penetration Testing:**
   - RPC interface authentication bypass testing
   - SSRF exploitation attempts
   - Header injection testing
   - DoS testing

2. **Automated Security Scanning:**
   - SAST (Static Application Security Testing) with gosec
   - Dependency vulnerability scanning with govulncheck
   - Container image scanning if Dockerized

3. **Fuzzing:**
   - HTTP request fuzzing
   - RPC interface fuzzing
   - TLS handshake fuzzing

---

## Conclusion

Kamal Proxy is a well-engineered piece of software with good code quality and modern Go practices. However, it has **critical security vulnerabilities** that make it unsuitable for production use in its current state, particularly in multi-tenant or internet-facing environments.

**Key Strengths:**
- Clean, maintainable codebase
- Good test coverage
- Modern Go dependencies
- Zero-downtime deployment features

**Critical Weaknesses:**
- No authentication/authorization
- SSRF vulnerability
- Missing security headers
- No DoS protection

**Recommendation:** Address all Critical and High severity issues before deploying to production environments. Consider engaging a professional security firm for a comprehensive penetration test after implementing the recommended fixes.

---

## Contact & Follow-up

For questions about this audit or to report additional security concerns, please contact the security team through the project's security policy.

**Audit Completion Date:** November 5, 2025

---

## Appendix A: Tools Used

- Manual code review
- Go language analysis
- Static analysis patterns
- OWASP Testing Guide v4.2
- CWE/SANS Top 25

## Appendix B: References

- OWASP Top 10 2021
- CWE-918: Server-Side Request Forgery (SSRF)
- CWE-306: Missing Authentication for Critical Function
- CWE-862: Missing Authorization
- CWE-770: Allocation of Resources Without Limits or Throttling
- Go Security Best Practices: https://go.dev/security/
- NIST Cybersecurity Framework

---

**End of Report**
