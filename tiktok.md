# TikTok — 2-Day Interview Study Plan
**Role focus:** Web, Mobile & Security Concepts, Privacy, Adversarial Testing, Source Code Review  
**Time until interview:** 2 days

---

##  Quick instructions
1. Follow the schedule below strictly—prioritize hands-on practice and active recall.
2. After each topic, go through the **How I’ll judge completion** checklist.
3. On Day 2, run two mock interviews: one deep technical dive, one rapid Q&A.
4. Use the **Resources** section for reading and labs.

---

##  Key canonical resources (live links)
- **OWASP Top 10 (Web Application Security Risks, 2021)**  
  https://owasp.org/Top10/
- **OWASP MASVS (Mobile Application Security Verification Standard)**  
  https://mas.owasp.org/MASVS/
- **OWASP Code Review Guide (v2 PDF)**  
  https://owasp.org/www-project-code-review-guide/assets/OWASP_Code_Review_Guide_v2.pdf
- **NIST Privacy Engineering Program overview**  
  https://www.nist.gov/privacy-engineering
- **Secureworks paper on Adversarial Testing (PDF)**  
  https://www.secureworks.com/-/media/files/us/white-papers/secureworks_n1_dangerousassumptionadversarialtestingimperative_v2.pdf
- **Sample OWASP interview questions (web)**  
  https://mindmajix.com/owasp-interview-questions
- **Sample Mobile testing interview questions**  
  https://testrigor.com/blog/mobile-testing-interview-questions/

---

##  Day 0 — Prep (Evening before Day 1)
- Install necessary tools: Burp Suite, APKTool/jadx, Frida, MobSF or Drozer, Android emulator or test device, Git + code editor.
- Clone a deliberately vulnerable app (e.g. OWASP Juice Shop).
- Draft 4–6 STAR-format anecdotes:
  - A web vulnerability you found or mitigated.
  - A mobile security assessment insight.
  - A privacy vs security trade-off.
  - A code review finding and how you fixed it.

---

##  Day 1 — Foundations & Mobile

### 09:00 – 11:30 — OWASP Top 10 (Web)
**Goal:** Explain, identify, and mitigate each OWASP Top 10 item.  
**Tasks:**
- Read the OWASP Top 10 pages.
- For each vulnerability: write
  - One-line definition
  - Example exploit
  - Practical mitigation
- Practice in Juice Shop or WebGoat: find an XSS and an Access Control bypass.  
**How I’ll judge completion:**
- I can list all Top 10 by heart.
- I can demo XSS and ACL bypass locally.
- I can explain why two mitigations work & their limitations.  
**Rapid example answers:**
- *Q: What is Cross-Site Scripting (XSS)?*  
  **A:** “XSS is when attackers inject scripts into web pages viewed by users. For example, inserting `<script>alert(1)</script>` into a comment field. We mitigate it by context-sensitive output encoding (e.g., `encodeForHTML()`) plus a strict Content Security Policy (CSP) that disallows inline scripts.”
- *Q: How would you test for Broken Access Control?*  
  **A:** “I’d review endpoints and manipulate roles or object IDs. For instance, I’d change the user-ID parameter to another user’s ID and see if unauthorized data returns. Mitigate with enforced server-side authorization checks, not just UI gating.”

---

### 11:45 – 14:00 — Source Code Review (Web)
**Goal:** Spot insecure patterns and link them to vulnerabilities using the OWASP Code Review Guide.  
**Tasks:**
- Read key sections of the Code Review Guide (e.g., auth, crypto, logging).
- Review a login/session code snippet; note flaws and suggest fixes.
- Build a quick checklist: input validation, error handling, secrets management, auth logic.  
**How I’ll judge completion:**
- In 5 minutes, I locate 3 issues in ~150 lines and map them to fixes/tests.  
**Rapid example answer:**
- *Q: What would you look for in a PR that changes authentication?*  
  **A:** “I’d check if they log sensitive data like passwords or tokens, verify proper error handling so no stack traces leak, ensure secure cookie flags (HttpOnly, Secure, SameSite), and that the session token lifecycle (expiration, revocation) is maintained. Also watch for plaintext storage of credentials.”

---

### 14:30 – 17:00 — Mobile Testing (Android/iOS)
**Goal:** Understand mobile threat models and perform basic static/dynamic tests using OWASP MASVS.  
**Tasks:**
- Read MASVS checklist sections: storage, network, auth, platform APIs.
- Decompile an APK (via jadx) and search for hardcoded secrets.
- Intercept app traffic using Burp and Android emulator; test TLS pinning.
- Optional: use Frida to bypass client checks.  
**How I’ll judge completion:**
- I can explain MASVS levels.
- I found a key or insecure storage in an APK.
- I understand TLS pinning bypass methods.  
**Rapid example answer:**
- *Q: What is MASVS and how do you use it?*  
  **A:** “MASVS is a standard that defines security requirements for mobile apps. It covers storage, communication, authentication, cryptography, etc. I’d use it to guide both static and dynamic testing: e.g., check that sensitive data isn’t stored improperly (MASVS-L1: encrypt or isolate), and that network communication uses TLS with pinning (MASVS-L2).”
- *Q: How do you extract secrets from an APK?*  
  **A:** “I’d decompile with jadx, search for strings like API keys, hardcoded credentials, or endpoints. If obfuscated, I might hook string-load functions with Frida at runtime. Discovering a base URL or token constant could expose vulnerabilities or misuse.”

---

### 17:15 – 19:00 — Privacy & Security Alignment
**Goal:** Learn privacy engineering fundamentals and align security measures without over-collecting user data.  
**Tasks:**
- Read NIST Privacy Engineering overview.
- Quickly scan a GDPR compliance checklist (e.g., data minimization, lawful basis).
- Prepare two examples:
  - Logging for security without infringing privacy (e.g., pseudonymize user IDs).
  - Telemetry that balances diagnostics and privacy (e.g., aggregate stats).  
**How I’ll judge completion:**
- I can explain data minimization and privacy design.
- I can outline a privacy review structure (data mapping, retention, consent).  
**Rapid example answer:**
- *Q: How do you balance security telemetry with user privacy?*  
  **A:** “You can collect aggregate, anonymized logs—like failed login counts—rather than raw IPs or usernames. Use differential privacy or hashing/pseudonymization. Store detailed IDs only transiently, then strip or anonymize them once security thresholds are computed.”

---

### 19:30 – 21:00 — Adversarial Testing
**Goal:** Understand the concept of adversarial (red-teaming style) testing vs standard pentest.  
**Tasks:**
- Read the Secureworks adversarial testing whitepaper.
- Draft a mini adversarial testing plan for a TikTok-like service (e.g., rate-limit bypass, ML poisoning, data exfil).  
**How I’ll judge completion:**
- I can define adversarial testing and distinguish it from vulnerability scanning.
- I can outline three adversarial checks for a social media backend.  
**Rapid example answer:**
- *Q: What is adversarial testing vs pentesting?*  
  **A:** “Adversarial testing simulates a strategic attacker aiming to break systems assuming defenders are alert. It goes beyond scanning: you might fuzz endpoints to bypass rate limits, craft ML inputs to poison content filters, or test lateral movement within the infra. It’s about breaking assumptions and validating controls under active threat.”

---

##  Day 2 — Deep reviews, mocks & code practice

### 09:00 – 11:00 — Hands-On Code Review
- Choose a small web + mobile repo. Spend 90 minutes identifying security flaws.
- Produce a mini-report: 5 issues, ranking by severity + suggested fixes.  
**Goal:** Done within time with actionable findings.

---

### 11:15 – 13:00 — Mock Interview #1 (Technical Deep Dive)
- Simulate or time yourself: dive into one web vulnerability, one mobile test, and a privacy/security scenario.
- Make sure your answers are structured, trade-off aware, and succinct.

---

### 14:00 – 16:00 — Rapid-Fire Q&A Practice
- Use sample questions below; aim for crisp 1–2 minute responses. Focus on clarity, trade-offs, and examples.

---

### 16:30 – 18:00 — Mock Interview #2 (Live Code Review)
- Perform a live code review of a short file, articulate your reasoning, annotate findings, and propose improvements.

---

### 18:30 – 20:00 — Final Review & Mental Prep
- Revisit any weak spots.
- Prepare thoughtful questions for your interviewer—especially around threat modeling cadence, privacy-security collaboration, and bug bounty workflows.

---

##  Sample Interview Questions & Rapid Answers

### Web & OWASP
- **Q:** Explain an OWASP Top 10 vulnerability and how to find & fix it.  
  **A:** “Take SQL Injection: it occurs when user input is embedded directly in a SQL query, e.g., `…WHERE id = '${userId}'`. To test, input `' OR '1'='1'` to bypass filters. Mitigate by using parameterized queries (prepared statements) and ORM APIs. Validate numerics on the client and sanitize inputs server-side.”
- **Q:** How would you test for broken access control?  
  **A:** “I’d attempt to access another user’s data by modifying the user ID in requests. For instance, change `/api/user/123` to `/api/user/124`. If it returns data, access control is broken. Proper fix: enforce server-side authorization checks based on session or JWT claims.”

### Mobile
- **Q:** What is MASVS, and which areas matter most?  
  **A:** “MASVS defines mobile app security requirements: storage, network, crypto, authentication. I’d first test storage and network—these are critical. For example, ensure that sensitive data is encrypted in secure storage (see MASVS-L1) and that network calls use TLS with pinning (MASVS-L2).”
- **Q:** How to bypass TLS pinning in an app?  
  **A:** “Use Frida to hook the certificate validation function at runtime, and override it to always return true. Alternatively, patch the app to remove the pinning code and recompile.”

### Privacy & Alignment
- **Q:** How do you do a privacy review for a feature that collects location and contacts?  
  **A:** “Map the data flow: where location and contacts go, how they’re used, stored, shared. Use data minimization: collect only absolute necessary data, store it briefly, and delete regularly. Ensure consent is explicit, and store pseudonymized data unless attribution is essential. Retain logs only long enough for diagnostic needs.”
- **Q:** Give an example where security violates privacy and how to fix it.  
  **A:** “Centralized logging of IP addresses helps trace abuse but may infringe privacy. Mitigate by anonymizing or hashing IPs, or using geolocation granularity (e.g., coarse IP blocks) instead of full addresses.”

### Adversarial Testing
- **Q:** Define adversarial testing and how it differs from standard scans.  
  **A:** “Adversarial testing simulates a motivated attacker under realistic constraints—it's not just scanning for vulnerabilities, but trying to break assumptions: bypass rate limits, manipulate ML models, evade detection. It’s more adaptive and strategic than traditional pen-testing.”
- **Q:** Suggest adversarial tests for an ML content moderation system.  
  **A:** “We’d craft misspelled or visually obfuscated abusive content to evade detection. Test boundary cases around image classification (e.g. slight pixel noise that flips a label). Try model poisoning—like feeding benign content with bad actors’ metadata to bias retraining.”

### Source Code Review
- **Q:** What do you look for in a login module during a code review?  
  **A:** “Check for hardcoded credentials or secret keys, ensure proper input validation, secure session generation and cookies (Secure, HttpOnly, SameSite), error handling (no stack traces), rate limiting, and logging that doesn’t expose usernames or tokens.”

---

##  Readiness Checklist
- [ ] Explain OWASP Top 10 vulnerabilities and mitigations from memory.  
- [ ] Demonstrate finding and exploiting an XSS and access control bypass.  
- [ ] Decompile an APK and locate insecure storage or secrets.  
- [ ] Conduct a live code review with prioritized findings and fixes.  
- [ ] Articulate privacy-security trade-offs and mitigation strategies.  
- [ ] Completed two mock interviews with actionable feedback.

---

##  Additional Resources & Labs
- OWASP Top 10: https://owasp.org/Top10/  
- OWASP MASVS: https://mas.owasp.org/MASVS/  
- OWASP Code Review Guide (PDF): https://owasp.org/www-project-code-review-guide/assets/OWASP_Code_Review_Guide_v2.pdf  
- NIST Privacy Engineering: https://www.nist.gov/privacy-engineering  
- Secureworks Adversarial Testing Whitepaper: https://www.secureworks.com/-/media/files/us/white-papers/secureworks_n1_dangerousassumptionadversarialtestingimperative_v2.pdf  
- OWASP Interview Qs: https://mindmajix.com/owasp-interview-questions  
- Mobile Testing Interview Qs: https://testrigor.com/blog/mobile-testing-interview-questions/

---

##  Final Advice
- Always structure your answers: **What**, **Why**, **How**, and **Trade-offs**.
- For vulnerability questions, cover: detection, exploitation, mitigation.
- For privacy, speak in terms of data flow, minimization, and embedding privacy in design.
- If unsure, shift to general security engineering principles and how you’d validate unknowns.

---

**Best of luck!** Let me know if you’d like:
- To convert this into a downloadable `.md` file now, or  
- To kick off some live mock Q&A rounds and get feedback.

Just say the word!
::contentReference[oaicite:0]{index=0}
