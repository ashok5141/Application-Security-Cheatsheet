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
    * SOC2 - System and Organization Controls 2. This is a type of audit report focusing on a service organization's controls related to the Trust Services Criteria (security, availability, processing integrity, confidentiality, and privacy). 
    * SIG - Standardized Information Gathering. This refers to a comprehensive set of questions used to assess the cybersecurity, IT, and data privacy risks of third-party service providers and vendors.
    * CAIQ - Consensus Assessments Initiative Questionnaire. This is a questionnaire developed by the Cloud Security Alliance to help organizations document and assess the security controls of cloud providers.
    * Pentest - Penetration Testing. This is a simulated cyberattack on a system, network, or application to identify vulnerabilities that could be exploited by malicious actors. It's a security exercise where ethical hackers attempt to find and exploit weaknesses in a computer system. 
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

- ****

##### Citi-specific questions
- **8. What interests you specifically about this External Vendor Vulnerability Assessments Lead role at Citi?**
    - **Situation**: Career has been focused on cybersecurity, with a particular emphasis on vulnerability management and securing third-party relationships, where extensive experience in identifying, assessing, and mitigating risks was gained.
    - **Task**: Actively seeking a leadership role where skills and experience can be applied to a larger, more complex environment, contributing to the security of a globally recognized financial institution.
    - **Action**: Citi's strong commitment to cybersecurity and its proactive approach to vendor risk management was followed, which aligns with professional values and expertise. The opportunity to lead a dedicated team, leveraging experience in developing and implementing robust vulnerability assessment programs and driving automation initiatives to enhance efficiency, is of particular interest.
    - **Result**: It is believed that the skills and passion for securing external vendor ecosystems will enable a significant contribution to Citi's mission of safeguarding its assets and maintaining the trust of its clients.

- **9. How do you envision leveraging automation to improve the Vendor Vulnerability Assessments program at Citi?**
    - **Situation**: In the experience, manual processes in vulnerability assessments can introduce inefficiencies and potential human error, especially in complex environments with numerous vendors.
    - **Task**: A future where the Vendor Vulnerability Assessments program is significantly more efficient and effective through the strategic application of automation is envisioned.
    - **Action**: It would start by identifying repetitive tasks in the assessment lifecycle, such as initial data gathering from vendors, scheduling assessments, report generation, and tracking remediation efforts. Then, exploring integrating existing tools, such as vulnerability scanners and GRC platforms, to automate these steps, potentially leveraging scripting for custom integrations, such as with collaboration tools like Atlassian. The focus would be on creating a seamless workflow that reduces manual intervention, provides real-time visibility into the assessment status, and automates communication with vendors and internal stakeholders.
    - **Result**: The expected outcome would be a more streamlined and scalable program, reducing the time and resources spent on routine tasks, increasing the accuracy of the data, and allowing the team to focus on more complex analysis and strategic initiatives, ultimately enhancing Citi's overall security posture.




# Key Terms and Concepts from the Job Description


### 1. Third-party Penetration Testing Vendors

* **What it is:** These are external cybersecurity firms hired by Citi to simulate cyberattacks on its systems, applications, and networks. They are independent specialists, not Citi employees.
* **How it works:** Citi contracts with these vendors. Their ethical hackers use various tools and techniques to find security vulnerabilities, with the goal of helping Citi fix them before malicious attackers can exploit them.
* **Example:** Citi hires a firm like **NCC Group** to conduct a penetration test on a new online banking application. The vendor will perform checks on the web application, network, or mobile app to identify weaknesses.

---

### 2. Citi's Requirements

* **What it is:** These are the specific rules, standards, and policies that Citi mandates for any security activity, ensuring all assessments meet the company's internal security posture and regulatory obligations.
* **How it works:** These requirements cover key aspects of the testing process, including:
    * **Scope Definition:** What will be tested (e.g., specific URLs, IP ranges).
    * **Methodology:** The specific testing approaches and tools the vendor must use (e.g., OWASP Top 10 focus, PTES methodology).
    * **Reporting Standards:** The required format, content, and detail for the final report, including vulnerability severity ratings (e.g., CVSS scores).
    * **Legal & Compliance:** Adherence to data privacy and financial industry regulations.
* **Example:** A requirement might state: "All web application penetration tests must follow the OWASP Testing Guide v4 principles and provide a final report with vulnerabilities ranked by CVSSv3.1 score, submitted within 2 weeks."

---

### 3. The Central Liaison

* **What it is:** As the "External Vendor Vulnerability Assessments Lead," you are the primary point of contact and facilitator between internal Citi departments (the "businesses") and external penetration testing vendors. Your role is to be the communication bridge.
* **How it works:**
    * **Translating Needs:** You translate business needs into technical scopes for vendors and simplify complex technical findings into business risks for internal teams.
    * **Information Flow:** You ensure all necessary information (access, documentation) flows from Citi's internal teams to the vendor, and all vendor deliverables (reports, updates) flow back to Citi.
    * **Problem Resolution:** You mediate any issues that arise during testing.
* **Example:** A new mobile banking feature needs a penetration test. You would meet with the **Mobile App Development Team (Citi Business)** to get details, then engage a **Third-Party Vendor** with a defined scope. If the vendor has a question, they contact you, and you relay the message to the development team to get the answer.

---

### 4. Orchestrating Penetration Testing

* **What it is:** This phrase describes the core objective of the role: to manage the entire penetration testing process, ensuring every test is conducted according to Citi's standards and delivers high-quality, actionable results.
* **How it works:** This is a continuous cycle of:
    * **Planning:** Defining what needs to be tested and when.
    * **Vendor Engagement:** Selecting the right vendor for the job.
    * **Monitoring & Oversight:** Actively tracking the test's progress and ensuring the vendor follows the plan.
    * **Quality Control:** Verifying that the final report is accurate, comprehensive, and meets all of Citi's reporting standards.
* **Example:** Before an application update goes live, you (the Lead) ensure the **Application Owner (Internal Client)** provides all necessary documentation, the **Third-Party Vendor** uses approved testing methods, and the final report is delivered on time with all required details.

---

### 5. Vulnerability Disclosure & Automation

This section covers a second major responsibility, focusing on managing vulnerabilities reported by independent security researchers and using automation to improve the process.

* **Vulnerability Disclosure (VD) Vendors:** These are platforms (like **HackerOne** or **Bugcrowd**) that facilitate the secure reporting of vulnerabilities by independent researchers. You work with them to set up and manage these programs.
* **Onboard Applications:** This means integrating a specific Citi application into the VD program by defining its scope and rules for researchers.
* **Triage:** The initial process of evaluating and prioritizing newly submitted vulnerability reports. You'll reproduce the vulnerability, confirm its existence, and assess its severity.
* **Report:** Documenting confirmed vulnerabilities in an internal tracking system (like Jira or RSA Archer) and assigning them to the relevant teams for remediation.
* **Research:** Deep diving into the technical details of a reported vulnerability to understand its full impact and how similar issues might arise.
* **Drive Root Cause Analysis (RCA):** Leading the effort to determine the fundamental reason a vulnerability occurred, preventing similar issues from happening in the future.
* **Vulnerabilities identified by External Researchers:** Security flaws found and reported by independent cybersecurity professionals, often through bug bounty programs.
* **Developing automation with collaboration software:** Creating scripts or tools (e.g., in Python) that automate tasks and integrate with communication platforms like **Microsoft Teams** or **Slack**, making workflows more efficient.

---

### Teams Involved in the Orchestration Paragraph

The paragraph you provided mentions four distinct teams and their roles:

1.  **Internal Clients (Citi Businesses / Application Owners)**
    * **What they do:** They own and are responsible for specific Citi applications, systems, or business processes. They are the "customers" of the security assessment services.
    * **How the Lead interacts:** The Lead coordinates with them to define the scope of assessments, ensures they provide necessary information for testing, and works with them to fix vulnerabilities.
    * **Example:** The **"Retail Banking Division"** is an internal client. You work with them to get a new mobile app feature tested and communicate the results back to them.

2.  **Third-party Penetration Testing Vendors**
    * **What they do:** External firms hired by Citi to conduct formal penetration tests.
    * **How the Lead interacts:** The Lead coordinates with them to ensure testing meets Citi's requirements, provides them with the scope and technical details, and manages their engagement.
    * **Example:** You hire **PenTestPro Inc.** to test a new payment gateway, providing them with the scope and test accounts.

3.  **Vulnerability Disclosure Vendors**
    * **What they do:** Platforms that facilitate the secure reporting of vulnerabilities by independent researchers.
    * **How the Lead interacts:** The Lead uses their platform to onboard applications, receive reports, and manage the flow of information from researchers.
    * **Example:** You use **BugBountyCorp.io**'s platform to set up a bug bounty program for a new customer portal.

4.  **External Researchers**
    * **What they do:** Independent ethical hackers who proactively find and report vulnerabilities in organizations' systems.
    * **How the Lead interacts:** The Lead interacts with them indirectly through the VD vendor's platform to triage their reports, ask for clarifications, and manage rewards.
    * **Example:** A freelance researcher named "CyberNinja" reports a bug in the mobile app. You receive the report and communicate with CyberNinja via the platform to confirm the details.