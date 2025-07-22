# External Vendor Vulnerability Assessments Lead — 3-Day Technical Interview Prep Plan

## Target Role: External Vendor Vulnerability Assessments Lead

**Company:** Citi
**Job URL:** [View Job Description](https://jobs.citi.com/job/irving/external-vendor-vulnerability-assessments-lead/287/83014917328)
**Candidate:** Ashok R M
**Interview Date:** In 3 Days

---

## 🔍 Job Description Highlights (Extracted & Mapped)

### Core Responsibilities:

* **Assess vendor systems** for vulnerabilities (Web, APIs, Cloud, Mobile, Infra).
* **Vendor Risk Assessments** — including technical questionnaire reviews, pentest reviews, and compliance mappings.
* **Engage with internal/external stakeholders** to validate, explain, and mitigate vulnerabilities.
* **Guide vendors** in remediation using OWASP/NIST best practices.
* **Track remediation status** using tools like Jira or internal GRC platforms.
* **Use VA tools** like Qualys, Nessus, Burp Suite, Nmap, etc.
* **Document risk reports, findings, and control gaps** aligned with frameworks (NIST 800-53, CIS, etc.).

### Key Skills Sought:

* Vulnerability Management / Risk Triage / Threat Analysis
* Strong understanding of AppSec & Cloud Security
* Vendor Risk Management / External Security Posture Evaluation
* Excellent documentation, reporting, communication skills
* Technical leadership & security architecture knowledge

---

## 🧠 Prep Summary Overview

**Total Time Available:** 3 Days x 6 Hours = **18 Hours**

### Daily Focus Themes:

* **Day 1:** Vendor Risk Assessment, Vulnerability Lifecycle, Security Frameworks
* **Day 2:** Technical Deep Dive — VA Tools, CVSS, Cloud/Web/App/API Risks
* **Day 3:** Mock Interview, Documentation, Communication Practice, War-Room Fixes

### Metrics to Measure:

* Can I explain vendor vulnerability workflow?
* Can I classify vulnerabilities & rate them using CVSS?
* Can I walk through how I would guide a vendor to fix a finding?
* Can I write/verbally present a risk-based executive report?
* Am I confident in all OWASP Top 10, NIST 800-53 mappings?

---

## 📅 Day 1 Plan – Risk Assessments + Frameworks (6 Hours)

### Session 1: External Vendor Security Lifecycle (2 hours)

* Stages: Vendor onboarding → Questionnaire → VA → Remediation → Validation
* Key topics:

  * Vendor Tiering (Critical/Non-critical)
  * Reviewing SOC 2, SIG, CAIQ, and pentest reports
  * Involving legal, procurement, and security in vendor security

✅ **Metrics:** Can you walk through this lifecycle verbally with confidence?

---

### Session 2: Framework Mapping (2 hours)

* NIST 800-53 → SA-11, CA-7, RA-5 mappings for vendor testing
* CIS Benchmarks for AWS, Linux, Windows (just top 10 controls)
* OWASP SAMM, BSIMM for maturity-level mapping

✅ **Metrics:** Can you match a finding to a framework and justify risk?

---

### Session 3: Risk Classification & Remediation Handling (2 hours)

* CVSS v3.1 — Base score breakdown (Attack Vector, Scope, etc.)
* Examples of:

  * Critical RCE (Score 9.8+)
  * Medium XSS (Score \~5)
* Risk acceptance vs. mitigation vs. compensating controls

✅ **Metrics:** Can you calculate CVSS for a sample vuln + suggest mitigation?

---

## 📅 Day 2 Plan – Tools + Vuln Types + Triage Process (6 Hours)

### Session 1: Tool Mastery (2 hours)

* Burp Suite (Repeater, Scanner, Extender)
* Nessus vs. Qualys vs. Nexpose: Use cases
* Nmap + NSE scripts for service enumeration
* Mapping tool output to actionable vulnerabilities

✅ **Metrics:** Can you describe what each tool is best for and interpret findings?

---

### Session 2: Deep Dive: Vulnerability Scenarios (2 hours)

* OWASP Top 10: IDOR, SSRF, Broken Auth, etc.
* Cloud-specific misconfigs (open S3 buckets, public IAM)
* API security flaws (insecure tokens, lack of rate limiting)
* Hands-on recap: past bugs you found/fixed

✅ **Metrics:** Can you explain impact + remediation for any given vuln?

---

### Session 3: Triage & Ticketing Workflows (2 hours)

* How to file findings in Jira (Severity, Repro, Steps, Fix)
* Writing mitigation guidance using secure coding + framework
* Vendor communication examples: polite, direct, evidence-based

✅ **Metrics:** Can you write a sample ticket/email to vendor?

---

## 📅 Day 3 Plan – Mock Interview + Communication + Reporting (6 Hours)

### Session 1: Mock Interview (1.5 hours)

* Self-practice / with friend / ChatGPT-style Q\&A:

  * How do you handle a vendor refusing to fix an RCE?
  * Describe the last time you triaged a vulnerability
  * What is your process for reviewing a pentest report?

✅ **Metrics:** Do you confidently answer all role-specific behavioral + technical questions?

---

### Session 2: Report Writing & Presentation (2.5 hours)

* Executive summary writing: business risk focus
* Remediation tracker format
* Technical report format: Table of vulns, CVSS, Proof-of-Concept, Remediation
* Create 1 dummy report from an old finding

✅ **Metrics:** Does your report clearly separate business vs technical sections?

---

### Session 3: Communication Drills + Final Gaps (2 hours)

* Vendor calls simulation: "Explain SQLi impact in non-technical terms"
* Cross-functional communication practice (Legal, IT, GRC)
* Revise weak areas from Days 1–2

✅ **Metrics:** Can you switch between technical and non-technical explanations?

---

## ❓ Possible Interview Questions (Technical + Behavioral)

### Risk & VA Process:

* Walk me through your external vendor VA workflow.
* How do you handle a vulnerability that a vendor disagrees with?
* What’s your process for validating pentest reports from vendors?

### Vulnerability Management:

* How do you assign risk scores to findings?
* Explain how CVSS scoring works.
* When is it acceptable to accept a risk instead of mitigating it?

### Technical:

* What are the top 5 issues you’d expect in an exposed API?
* Explain SSRF and how to detect it.
* What’s your process when you find an S3 bucket misconfigured?
* How would you guide a vendor in fixing an IDOR vulnerability?

### Tools:

* What are the key differences between Qualys and Nessus?
* How do you use Burp Suite for auth testing?
* What is your favorite recon/NSE script in Nmap?

### Reporting & Communication:

* Can you write a remediation ticket for a stored XSS?
* How do you present findings to non-technical stakeholders?
* Describe a time when a vendor pushed back on a finding.

---

## ✅ Final Checklist Before Interview

| Area                                  | Status |
| ------------------------------------- | ------ |
| Vendor VA Process Flow                | ☐      |
| Framework Mapping (NIST/CIS)          | ☐      |
| Tool Proficiency (Burp, Nessus, etc.) | ☐      |
| OWASP + Cloud Vulns Explained         | ☐      |
| CVSS Scoring + Examples               | ☐      |
| Sample Report Ready                   | ☐      |
| Mock Questions Practiced              | ☐      |
| Communication/Soft Skills             | ☐      |

---

## 📘 References / Practice Resources

* [NIST 800-53 Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
* [OWASP Top 10](https://owasp.org/www-project-top-ten/)
* [CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3.1)
* [Cloud Security Misconfig Labs – Flaws.cloud](https://flaws.cloud/)
* [Pentest Report Template (Github)](https://github.com/juliocesarfort/public-pentesting-reports)

---

Good luck Ashok! You have a strong foundation — focus on stakeholder scenarios, real examples, and cross-functional clarity to shine in this leadership-oriented role.





# Q / A

- **Can you explain what a vulnerability assessment is and how it differs from a penetration test?**
    - A vulnerability assessment is a systematic process of identifying and evaluating vulnerabilities in a system. It typically involves automated scanning tools and manual analysis to detect potential security issues. The primary goal is to provide a comprehensive list of vulnerabilities and recommendations for remediation.
    - A penetration test, on the other hand, goes a step further by actively attempting to exploit identified vulnerabilities to determine their real-world impact. Penetration testing simulates an attacker’s actions to assess the effectiveness of security measures and identify weaknesses that may not be apparent in a vulnerability assessment. While vulnerability assessments focus on breadth, penetration tests focus on depth.

- **How do you stay updated with the latest vulnerabilities and threats?**
    - **Subscribing to Security Bulletins**: Receiving updates from vendors, security organizations, and government agencies.
    - **Participating in Security Communities**: Engaging with online forums, security conferences, and professional networks.
    - **Using Threat Intelligence Feeds**: Leveraging commercial or open-source threat intelligence services.
    - **Continuous Learning**: Taking courses, certifications, and attending webinars to stay informed about the latest trends and technologies.
