# Web Vulnerabilities Explained

This document provides detailed explanations of common web vulnerabilities, categorized by complexity, for both technical and non-technical audiences.

---

### **Complex Vulnerabilities**

These often involve subtle interactions between different components or complex data processing.

#### 1. Server-Side Request Forgery (SSRF)

* **Technical Explanation:**
    SSRF is a vulnerability where an attacker can trick a server-side application into making requests to an arbitrary domain of the attacker's choosing. This request is initiated by the vulnerable server itself, not the attacker's browser. The server might have access to internal networks, cloud metadata services (e.g., AWS EC2 metadata), or other systems not directly exposed to the internet. An attacker can manipulate input (e.g., a URL parameter) that the server processes, causing it to fetch data from internal IP addresses or specific ports. The server then acts as a proxy for the attacker, revealing sensitive internal information or performing actions on internal services.
    * **How it's exploited:** An attacker finds an endpoint that accepts a URL as input (e.g., an image loading service, a PDF renderer, a webhook). Instead of an external URL, they provide an internal IP address (e.g., `http://169.254.169.254/latest/meta-data/` for AWS or `http://127.0.0.1:8080/admin`). The server fetches this internal resource, and if the response is then returned to the attacker (even partially or implicitly), they gain access to information they shouldn't have, or trigger internal actions.
    * **Impact:** Disclosure of internal network architecture, sensitive data from internal services (e.g., database credentials, API keys), access to cloud provider metadata, or even triggering actions on internal systems (e.g., internal administrative panels).

* **Non-Technical Explanation:**
    Imagine a friendly assistant (the company's server) whose job is to fetch things for you from the internet, like getting a picture from a website you provide. An SSRF vulnerability is like tricking this assistant into going to places *inside* the company's private office building that they normally wouldn't show to outsiders, or even making them do things there.
    * **Analogy:** You ask the assistant to get a photo from "Google.com." But instead, you secretly tell them to go to "the locked filing cabinet in the server room" or "the CEO's private safe." Because the assistant is *inside* the office, they might be able to get sensitive documents or even unlock something, and then report back to you about what they found or did, even though you're outside.
    * **Real-World Impact:** This can lead to sensitive internal company information being stolen (like secret documents, internal network maps), or even private functions being activated that should only be available to employees. It's like an outsider gaining an insider's view and control without ever setting foot inside the company building themselves.

#### 2. Insecure Deserialization

* **Technical Explanation:**
    Serialization is the process of converting an object (e.g., a class instance, a data structure) into a format that can be stored or transmitted (e.g., JSON, XML, or a binary stream). Deserialization is the reverse: reconstructing the original object from that format. Insecure deserialization occurs when an application deserializes untrusted data without proper validation. If an attacker can control the serialized data, they can craft malicious objects that, when deserialized by the application, can lead to arbitrary code execution, denial of service, or authentication bypass. This is often due to the deserialization process calling methods or constructors within the deserialized object that have unintended side effects.
    * **How it's exploited:** The attacker identifies a point where the application deserializes data (e.g., from a cookie, a hidden form field, or an API request body). They then craft a specially malformed serialized object payload. When the vulnerable application attempts to reconstruct this object, it triggers unintended code execution, often by invoking "gadget chains" – sequences of legitimate methods in the application's dependencies that can be chained together to achieve malicious behavior (like running system commands).
    * **Impact:** Complete compromise of the application server, including arbitrary code execution, privilege escalation, data exfiltration, or denial of service.

* **Non-Technical Explanation:**
    Think of a blueprint for building something, like a LEGO model. "Serialization" is like taking a fully built LEGO model and carefully writing down instructions on how to build it piece by piece. "Deserialization" is taking those instructions and building the model exactly as described. An Insecure Deserialization vulnerability is like someone giving the builder (the company's software) a set of trick instructions.
    * **Analogy:** You give a builder instructions for a LEGO house. But a hacker sneaks in a page that says, "After step 10, instead of adding a window, go to the control panel and shut down the factory." Because the builder (software) blindly follows all instructions without questioning, it might unintentionally perform a dangerous action.
    * **Real-World Impact:** This can allow attackers to completely take over the company's servers, steal all data, or even shut down parts of the system. It's a very powerful attack because it leverages the trust the system has in its own internal instructions.

---

### **Medium Vulnerabilities**

These are common and can have significant impact, but often require more specific conditions or user interaction.

#### 3. Cross-Site Scripting (XSS) - Stored

* **Technical Explanation:**
    Stored XSS occurs when an attacker injects malicious client-side scripts (usually JavaScript) directly into a web application's database or persistent storage. When other users access the affected web page, the malicious script is retrieved from the database along with legitimate content and executed in their browsers. This allows the attacker to bypass the Same-Origin Policy.
    * **How it's exploited:** An attacker submits data containing a malicious script (e.g., `<script>alert('You are hacked!');</script>` or a more complex script to steal cookies) to a field that is stored and later displayed to other users (e.g., a comment section, a forum post, a profile bio). When a victim's browser loads the page containing the attacker's stored content, the browser executes the injected script as if it were legitimate code from the website.
    * **Impact:** Session hijacking (stealing user cookies to impersonate them), defacement of the website, redirecting users to malicious sites, phishing attacks, or performing actions on behalf of the victim within the application.

* **Non-Technical Explanation:**
    Imagine a public bulletin board where anyone can pin up notes. Stored XSS is like a malicious person pinning up a note that, when someone *reads* it, secretly makes their own pen write something else on their notepad without them knowing.
    * **Analogy:** A hacker writes a "note" (malicious code) and pins it to a website's comment section. When you (the victim) visit the page and load the comments, your web browser sees the hacker's note and, instead of just displaying it, it executes a secret instruction hidden inside that note. This instruction might tell your browser to quietly send your private login cookie to the hacker, or to show you a fake login page.
    * **Real-World Impact:** This can lead to your personal information being stolen (like your login details for that website), your account being taken over, or being tricked into giving up sensitive information. It's dangerous because the malicious content is stored on the legitimate website itself, making it seem trustworthy.

#### 4. SQL Injection - Error-based

* **Technical Explanation:**
    SQL Injection is a code injection technique where an attacker manipulates or injects malicious SQL statements into an application's input fields (e.g., login forms, search bars). In an *error-based* SQL Injection, the attacker crafts input that causes the database to throw an error message. This error message inadvertently includes parts of the database query results or structural information, allowing the attacker to deduce information about the database schema, table names, and even extract data.
    * **How it's exploited:** An application constructs SQL queries using user-supplied input without proper sanitization or parameterized queries. An attacker inputs a string like `' OR 1=1 --` into a username field, which might change a query like `SELECT * FROM users WHERE username = 'input' AND password = 'password'` into `SELECT * FROM users WHERE username = '' OR 1=1 --' AND password = 'password'`. For error-based, the attacker injects specific functions or clauses (e.g., `UNION SELECT NULL, NULL, @@version --`) that cause a syntax error or a type conversion error, and the database error message reveals part of the database's internal state or query results.
    * **Impact:** Full database compromise, including data exfiltration (stealing sensitive customer data, credentials), data manipulation (changing records), or even denial of service. Error-based specifically leaks information incrementally.

* **Non-Technical Explanation:**
    Imagine a very strict librarian (the database) who only understands precise instructions (SQL queries) written on request slips. A SQL Injection is like a hacker writing a trick instruction on their request slip that makes the librarian get confused and, in their confusion, accidentally blurt out some secret information while explaining their mistake.
    * **Analogy:** You ask the librarian for "books by Author X." A hacker instead writes a request slip that says something like "books by Author Y OR tell me the full list of all secret shelves and tell me *why* you can't give me that, and make sure you show me any numbers related to those shelves." Because the librarian tries to process *all* the instructions, they might encounter an error trying to show secret shelves, and in their error message, they accidentally reveal the names or numbers of those secret shelves.
    * **Real-World Impact:** This allows attackers to bypass login screens, steal entire lists of customer data (like names, addresses, credit card numbers), change records in the company's database, or even delete important information. It's a direct attack on the company's core data storage.

---

### **Low Vulnerabilities**

These might not directly lead to immediate compromise but can contribute to more severe attacks or reveal information that aids attackers.

#### 5. Information Disclosure (e.g., Directory Listing, Verbose Error Messages)

* **Technical Explanation:**
    Information disclosure refers to an application or server revealing sensitive information that should not be publicly accessible.
    * **Directory Listing:** A web server configuration allows directory Browse, meaning if a user navigates to a directory without a default index file (like `index.html`), the server lists all files and subdirectories within it. This can reveal source code, backup files, configuration files, or other sensitive assets.
    * **Verbose Error Messages:** Applications display highly detailed error messages to users (e.g., full stack traces, database connection strings, internal IP addresses, server versions) when an error occurs. This information is invaluable to an attacker for understanding the system's architecture, technologies used, and potential attack vectors.
    * **How it's exploited:**
        * **Directory Listing:** An attacker simply browses to a common directory name (e.g., `/config/`, `/backup/`, `/dev/`) and finds that the server lists its contents.
        * **Verbose Error Messages:** An attacker provides malformed input to an application (e.g., invalid characters in a numeric field, non-existent URLs) specifically to trigger an error and observe the detailed response.
    * **Impact:** Reconnaissance for future attacks, discovery of sensitive files, debugging information, internal network details, intellectual property (source code), or identifying specific software versions that are vulnerable to known exploits.

* **Non-Technical Explanation:**
    This is like someone leaving important clues lying around for a thief.
    * **Analogy (Directory Listing):** Imagine a private office where the door is unlocked, and instead of a 'No Entry' sign, there's a list on the door detailing every file in every cabinet inside, even the ones marked "Confidential." A thief doesn't have to guess; they just read the list and know exactly what's inside.
    * **Analogy (Verbose Error Messages):** Imagine a bank's ATM that, when you enter the wrong PIN, doesn't just say "Incorrect PIN" but instead prints a message saying "Error Code 404: Database connection failed from server 192.168.1.5, trying to access table 'customer_accounts', column 'PIN_hashes'." This gives a potential thief way too much information about how the system works and where to look for weaknesses.
    * **Real-World Impact:** While not a direct break-in, it's like providing a detailed map and instructions to a hacker. It makes it much easier for them to plan and execute a more serious attack by knowing exactly where to find valuable information or how the system is structured.

#### 6. Missing Security Headers (e.g., X-Frame-Options)

* **Technical Explanation:**
    Web security headers are HTTP response headers that a web server sends along with a web page to instruct the user's browser on how to behave securely. Missing these headers leaves the browser vulnerable to certain client-side attacks.
    * **X-Frame-Options:** This header prevents a website from being loaded in an `<iframe>`, `<frame>`, or `<object>` tag on another domain. If missing, it enables **Clickjacking**.
    * **How it's exploited (Clickjacking via missing X-Frame-Options):** An attacker creates a malicious website. On this site, they load the victim's legitimate website (which is missing X-Frame-Options) invisibly within an `<iframe>`. The attacker then overlays deceptive elements (e.g., a fake button or image) on top of the iframe. When the victim clicks on the deceptive element, they are actually clicking on a button or link on the *hidden* legitimate website, performing an action without their knowledge (e.g., transferring money, changing settings, making a purchase).
    * **Impact:** User interface (UI) redress attacks like Clickjacking, where users are tricked into performing unintended actions. While it doesn't directly compromise the server, it compromises user trust and can lead to financial loss or account manipulation.

* **Non-Technical Explanation:**
    Think of a web page as a window display in a store. Security headers are like special instructions you give to the window pane itself, telling it how to protect the store from certain tricks.
    * **Analogy (Missing X-Frame-Options for Clickjacking):** Imagine a store window (your website) where you can place items. If you forget to put a special "Don't cover me!" instruction on the window, a sneaky salesperson (hacker) from another store (malicious website) could put their own transparent plastic sheet over your window, paint a fake "SALE!" sign on *their* sheet, and trick customers into touching something on *your* display behind it, thinking they're just pointing at the fake sign.
    * **Real-World Impact:** This means you could be tricked into doing things on a legitimate website (like confirming a purchase, changing your password, or sending money) just by clicking on something seemingly innocent on a *different*, malicious website. It makes you perform actions you never intended, without you even realizing you're interacting with the real website.