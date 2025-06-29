# OWASP Top 10 : 2021

| Vuln                   | Process                     | Tools                        | Mitigation                         |
| ---------------------- | --------------------------- | ---------------------------- | ---------------------------------- |
| SQL Injection          | Inject payloads in inputs   | sqlmap, BurpSuite            | Prepared statements                |
| Broken Access Control  | Test IDOR, missing checks   | BurpSuite, manual review     | RBAC, deny by default              |
| Cryptographic Failures | Review encryption           | SSL Labs, code review        | Use TLS 1.2+, strong algorithms    |
| SSRF                   | Input URL → access metadata | BurpSuite, curl              | Whitelist URLs, block internal IPs |
| Outdated Components    | Inventory, CVE scan         | Snyk, OWASP Dependency-Check | Patch regularly                    |
| Logging Failures       | Review logs & alerts        | SIEM (Splunk, ELK)           | Centralize logs, alert rules       |



## A1 - Broken Access Control
- **Core Concept** Failure to enforce proper restrictions on authenticated users actions.
- Process:
    - Attackers manipulates parameters/URLs to access unauthorized resources.
    - Exploits missing role checks to perform privileged actions.

| Type | Description |
|----------------------------------|---------------------------------------------------------------------------------|
| IDOR | Accessing others' resources via ID manipulation (e.g., /user?id=123 → 124) |
| Missing Function-Level Control | Accessing admin pages without authorization (e.g., /admin without admin role) |
| CSRF | Forcing users to execute unwanted actions via authenticated sessions |
| Privilege Escalation | User → Admin via flawed permission checks |
| Misconfigured Access Controls | Allowing open access by Mistake |

#### Finding - Broken Access Control
- Change IDs URLs/parameters.
- Access privileged endpoints without proper roles.
- Test with different user accounts.
    - **How to find**: Manual testing with tools (Burp Suite), reviewing authorization checks, fuzzing parameters.

#### Mitigations -  Broken Access Control
- Implement RBAC with server-side enforcement. 
    - Instead of directly granting permissions to individual users, you group users into roles (e.g., administrator, editor, guest).
- Use UUIDs(Universally Unique Identifiers) instead of sequential IDs. 
    - 128-bit numbers that are designed to be globally unique. They are randomly generated or based on timestamps and other unique identifiers, making them unpredictable and difficult for attackers to guess or enumerate.
- Add CSRF token and ```SameSite=Strict``` cookies.
    - cookie attribute instructs the browser to only send the cookie with requests that originate from the same site.

