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


## A3 - 
- **Core Concept** 
- Process:
    - 
   

#### Finding - 
   - **How to find**: 

#### Mitigations -  

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
