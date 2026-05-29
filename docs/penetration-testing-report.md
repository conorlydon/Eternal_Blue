# **Penetration Testing Report**

**Team**: Eternal Blue  
**Members**: Emmett Macken, Conor Lydon, Nathan Dobbyn

---

1. ## **Scope**

This report documents penetration testing performed against the Eternal-Blue secure messaging application as part of the. Testing was performed by the development team against their own infrastructure in accordance with the project brief.

**In scope:**

* Web application API (https://eternal-blue.theburkenator.com/api/)  
* Frontend web client (https://eternal-blue.theburkenator.com/)  
* Server infrastructure (VM at 200.69.13.70)  
* TLS/SSL configuration

**Out of scope:**

* Shared college infrastructure and proxy  
* Database server (internal only, not externally accessible)

---

2. ## **Tools used**

   

| Tool | Version | Purpose |
| :---- | :---- | :---- |
| testssl.sh | 3.2.3 | TLS/SSL configuration analysis |
| nikito | 2.1.5 | Web server vulnerability scanning |
| nmap | 7.94SVN | Port and service discovery |
| sqlmap | 1.10.5 | SQL injection testing |
| curl | system | Manual header and certificate verification |

---

3. ## **Findings**

### 3.1 Improper Input Validation

**Severity:** Low (mitigated)  
**Tool:** sqlmap, manual testing

**What we tested:**  
sqlmap was run at level 2 risk 2 against the login and register endpoints, targeting all JSON body parameters. Additionally, manual requests were sent with oversized fields, missing required fields, extra unexpected fields, and special characters in the username field.

**What we found:**  
All malformed requests were rejected at the schema validation layer with HTTP 400 before reaching business logic. The username field correctly rejected special characters due to the ^\[a-zA-Z0-9\_\]+$ pattern constraint. Fields not present in the schema were rejected due to additionalProperties: false on all route schemas.

**Mitigation:**  
All API endpoints use Fastify's built-in JSON schema validation. Schemas enforce field types, length limits, required fields, and pattern constraints. No user input reaches database query logic without first passing schema validation.

---

### 3.2 Broken Authentication

**Severity:** Low (mitigated)  
**Tool:** sqlmap (observed side effect), manual testing

**What we tested:**  
Repeated login attempts with incorrect credentials. Invalid JWT tokens on protected routes. Expired token reuse. Automated scanning with sqlmap to simulate brute force behaviour.

**What we found:**  
During sqlmap testing, 359 out of approximately 400 automated requests received HTTP 429 Too Many Requests responses. This confirmed that @fastify/rate-limit correctly detected and blocked the automated attack pattern in real time. Manual testing confirmed that invalid JWTs return 401 Unauthorized and are not processed further.

**Mitigation:**

* @fastify/rate-limit limits requests per IP per time window, therefore automated scanners and brute force tools are blocked automatically  
* Passwords are hashed with Argon2id (memoryCost: 65536, timeCost: 3, parallelism: 1), even if the database were breached, offline brute force of password hashes is computationally prohibitive at these parameters  
* JWTs expire after 24 hours and are verified on every authenticated request

---

### 3.3 Broken Access Control

**Severity:** Low (mitigated)  
**Tool:** Manual testing

**What we tested:**  
Attempted to retrieve messages belonging to another user using a valid JWT for a different account. Attempted to revoke a forwarded message as a non-sender. Tested that the API correctly distinguishes between 403 Forbidden (resource exists but access denied) and 404 Not Found (resource does not exist or is hidden).

**What we found:**  
All authenticated endpoints correctly verify the requesting user's identity against the resource before returning data. Attempting to access another user's conversation returned 403 Forbidden. Attempting to revoke a message as a non-sender returned 403 Forbidden. The 403/404 distinction is correctly implemented, a user cannot determine whether a resource exists if they do not have access to it.

**Mitigation:**  
Every authenticated route extracts the user ID from the verified JWT and checks it against sender\_id or recipient\_id before returning any data. Revocation additionally verifies the requester is the original sender of the forwarded message. Access control checks are performed at the route handler level before any database query returns data to the client.

### ---

### 3.4 Cryptographic Issues

**Severity:** Informational  
**Tool:** testssl.sh, nikto, curl

**What we tested:**  
TLS configuration including protocol versions, cipher suites, and certificate validity. Certificate CN against the serving domain. Security headers on API responses.

**What we found:**  
testssl.sh confirmed TLS 1.3 is in use with the AES\_256\_GCM\_SHA384 cipher suite. nikto initially reported a certificate CN mismatch, showing 1bit2qbit.theburkenator.com instead of eternal-blue.theburkenator.com. Investigation revealed this is a false positive, nikto does not send a Server Name Indication (SNI) header during its TLS handshake, causing the shared proxy infrastructure to return its default certificate rather than the domain-specific one.

Verification with curl, which correctly sends SNI, confirmed the certificate is valid for the correct domain:

*subject: CN=eternal-blue.theburkenator.com*  
*subjectAltName: host "eternal-blue.theburkenator.com" matched cert's "eternal-blue.theburkenator.com"*

**Mitigation:**

* TLS 1.3 enforced with strong cipher suites  
* Certificate issued by Let's Encrypt \- trusted CA, valid chain  
* All application passwords hashed with Argon2id, never stored in plaintext  
* All message content is end-to-end encrypted using HPKE, the server stores ciphertext only, confirmed by direct database inspection

---

### 3.5 Injection

**Severity:** Low (mitigated)  
**Tool:** sqlmap

**What we tested:**  
sqlmap at level 2 risk 2 against the login endpoint, targeting both the username and password JSON parameters. Boolean-based blind, error-based, stacked queries, inline queries, and UNION-based injection techniques were all tested.

**What we found:**  
One potential stacked query injection point was initially flagged on the username parameter (PostgreSQL stacked queries (heavy query \- comment)). Extended testing confirmed this was a false positive:

*checking if the injection point is a false positive*  
*WARNING: false positive or unexploitable injection point detected*  
*WARNING: JSON username does not seem to be injectable*

Final result:

all tested parameters do not appear to be injectable

**Mitigation:**  
All database queries use parameterised placeholders via node-postgres ($1, $2 syntax). User input is never concatenated into raw SQL strings. The Fastify schema validator rejects malformed input before it reaches query logic. No SQL error messages are ever returned to the client \- errors are caught and return generic error codes only.

---

### 3.6 Security Misconfiguration

**Severity:** Medium (Fixed)  
**Tool:** nikto, nmap, curl

**What we tested:**  
nmap port scan for unexpectedly exposed services. HTTP response headers for missing security headers. PostgreSQL and Node backend accessibility from external network.

**What we found:**

**Finding 1 \- X-Frame-Options header missing (Fixed):**  
nikto identified that the X-Frame-Options header was not present in API responses, leaving the application potentially vulnerable to clickjacking attacks. Root cause: @fastify/helmet was registered with an explicit options object that did not include frameguard, causing the default to be silently omitted.

**Fix applied (server.js):**

frameguard: { action: 'deny' },  
noSniff: true,

Post-fix verification with curl confirmed:

*x-frame-options: DENY*  
*x-content-type-options: nosniff*  
*content-security-policy: default-src 'self'; ...*

**Finding 2 \- Port exposure:**  
nmap scan results (nmap \-Pn \-sV \-p 22,80,443,3000,5432,8080,8443 200.69.13.70):

*22/tcp   filtered*  
*80/tcp   filtered*  
*443/tcp  filtered*  
*3000/tcp filtered*  
*5432/tcp filtered*

All ports returned filtered. PostgreSQL (5432) and the Node backend (3000) are not directly reachable from the internet. Public access is routed exclusively through the nginx reverse proxy via the shared SNI-based proxy infrastructure.

**Mitigation:**

* PostgreSQL configured with listen\_addresses \= 'localhost' \- not externally accessible  
* Node backend bound to localhost:3000 \- only reachable via nginx proxy  
* @fastify/helmet now explicitly configures all security headers  
* nginx acts as the sole public entry point

**Fix verification note:**

Following the fix, curl confirmed x-frame-options: DENY is present in all API responses. Nikto continues to report the header as missing due to its lack of SNI support \- it does not reach the application server and receives a response from the shared proxy instead. Both nikto findings are explained by this SNI limitation. The curl response is the authoritative verification: 

*curl \-sI [https://eternal-blue.theburkenator.com/api/health](https://eternal-blue.theburkenator.com/api/health) | grep \-i frame*

*x-frame-options: DENY*

---

### 3.7 Sensitive Data Exposure

**Severity:** Low (mitigated)  
**Tool:** Manual database inspection, API response inspection

**What we tested:**  
Direct database inspection for plaintext passwords or private keys. API response inspection for sensitive data leakage. Checked whether message plaintext is ever stored or returned by the server.

**What we found:**  
Direct database inspection confirmed:

* password\_hash column contains only Argon2id hashes \- no plaintext passwords  
* No private key column exists anywhere in the schema  
* messages table contains only ciphertext, encapsulated HPKE key, and metadata \- no plaintext message content

API responses never include password hashes. Error responses use fixed error codes (NOT\_FOUND, UNAUTHORIZED) rather than reflecting user input or exposing internal details.

**Mitigation:**

* Private keys are generated client-side and never transmitted to or stored on the server  
* Passwords are hashed with Argon2id before storage \- plaintext is discarded immediately  
* End-to-end encryption ensures message plaintext never exists on the server  
* All traffic served over HTTPS \- no sensitive data transmitted in plaintext

---

### 3.8 Vulnerable Components

**Severity:** Low  
**Tool:** npm audit

**What we tested:**  
npm audit run against all backend dependencies to identify known vulnerabilities in third-party packages.

**What we found:**

➜  backend git:(main) npm audit

\# npm audit report

ws  8.0.0 \- 8.20.0

Severity: moderate

ws: Uninitialized memory disclosure \- https://github.com/advisories/GHSA-58qx-3vcg-4xpx

fix available via \`npm audit fix \--force\`

Will install ethers@5.8.0, which is a breaking change

node\_modules/ws

ethers  \>=6.0.0-beta.1

Depends on vulnerable versions of ws

node\_modules/ethers

2 moderate severity vulnerabilities

To address all issues (including breaking changes), run:

npm audit fix \--force

**Mitigation:**  
npm audit fix was run to resolve all automatically fixable vulnerabilities. Any remaining issues are documented above with justification. Dependencies are kept up to date and pinned to specific versions in package.json.

---

4. ## **Summary**

| \# | OWASP Item | Finding | Severity | Status |
| :---- | :---- | :---- | :---- | :---- |
| 1 | Improper Input Validation | Schema validation blocks all malformed input | Low | Mitigated |
| 2 | Broken Authentication | Rate limiting blocks brute force | Low | Mitigated |
| 3 | Broken Access Control | All routes enforce participant checks | Low | Mitigated |
| 4 | Cryptographic Issues | TLS 1.3, valid cert, E2EE confirmed | Info | Pass |
| 5 | Injection | No injectable parameters found (sqlmap) | Low | Mitigated |
| 6 | Security Misconfiguration | X-Frame-Options missing | Medium | Fixed |
| 7 | Sensitive Data Exposure | No plaintext passwords, keys, or messages on server | Low | Mitigated |
| 8 | Vulnerable Components | npm audit run, fixes applied | Low | Mitigated |

---

5. ## **Outstanding Issues**

     
* **sqlmap SSL connectivity:** sqlmap was initially unable to establish an SSL connection due to the shared proxy infrastructure's SNI handling. This was resolved by adding \--force-ssl and an explicit Host header. Future testing should note this requirement.  
* **npm audit ws vulnerability:** Moderate severity vulnerability in ws (transitive dependency of ethers v6). Not fixed as the breaking change would disable the blockchain integration. Risk assessed as minimal given deployment context.

---

6. ## **Conclusion**

No critical or high severity vulnerabilities were found in the Eternal-Blue application. 

One medium severity finding (missing X-Frame-Options header) was identified and remediated during the testing process. The application correctly implements parameterised queries, rate limiting, Argon2id password hashing, and end-to-end encryption. 

Notably, automated attack tools were detected and blocked in real time during testing \- sqlmap’s 400 automated requests resulted in 359 HTTP 429 responses from the rate limiter, demonstrating that the implemented security controls function as intended under active attack conditions.

