# WhoAmI Burp Extension

**WhoAmI** is a Burp Suite extension designed to automate basic manual penetration testing checks by injecting common vulnerability payloads into every parameter of proxied requests. It helps testers save time, increase parameter coverage, and get real-time notifications about vulnerabilities and server errors(500) during manual testing.

---

###  **Problem Statement**

During manual penetration testing of modern web applications, we often deal with a **large number of API endpoints**. Each endpoint may contain **many parameters**, sometimes **20 to 30 or more** — in **query strings**, **JSON bodies**, or even nested objects.

Manually testing each parameter across all these APIs is:

* **Time-consuming**
* **Repetitive**
* And often leads to **human error or missed vulnerabilities**

With this challenge, testers waste time repeating the same steps like:

* Inserting basic payloads for **SQL Injection**, **XSS**, **NoSQL Injection**, **Command Injection**, etc.
* Analyzing responses for each change manually
* Repeating the process across hundreds of API endpoints

This slows down testing and reduces the efficiency of the overall penetration test.

---

### ✅ **Solution Provided by WhoAmI Extension**

The WhoAmI extension automates the injection of basic test payloads for common vulnerabilities into every parameter of each proxied request within your testing scope. While crawling or testing the application.

* Automatically identifies all **parameters across all requests**
* Injects basic payloads for **SQLi**, **XSS**, **NoSQLi**, **CMDi**, and other common vulnerabilities into **every parameter**
* Works across different content types like **query parameters**, **JSON**, and **nested structures**
* Flags **successful injections** by detecting changes in response or behavior
* Also detects **HTTP 500 errors** that may indicate unhandled exceptions or crash points
* Gives a quick view of potentially vulnerable parameters for further manual testing

---

### Benefits

* Saves **significant time** in large-scope applications with **many APIs and parameters**
* Increases **testing coverage**
* Helps **quickly spot** parameters that may be vulnerable
* Improves overall **productivity and accuracy** in manual penetration testing
---

## Features

### 1. Injecting Basic Payloads into Every Parameter
- Supports Query Parameters, Form Data, JSON bodies, Cookies, and Headers.
- Injects example payloads for common vulnerabilities and analyzes responses to notify on positive findings:

  - **SQL Injection (SQLi):**  
    Payload: `'`  
    If the server returns a **500 Internal Server Error**, the extension retries with `''` (two single quotes).  
    If the response is **200 OK** it notifies as SQL Injection.

  - **Cross-Site Scripting (XSS):**  
    Payload examples: `<h1>hai</h1>`, `'-prompt(1)-'`, `" onmouseover="alert(1)`  
    If these payloads are reflected in the response **without encoding or sanitization**, the extension notifies as XSS.

  - **Command Injection:**  
    Uses different command combinations (e.g., `nslookup` pointing to a Burp Collaborator URL).  
    If the Collaborator receives DNS or HTTP interactions from the target, the extension notifies as Command Injection.

  - **Server-Side Request Forgery (SSRF):**  
    Injects URLs using protocols like `http`, `https`, `file` with Burp Collaborator payloads.  
    If any out-of-band interaction is received, the extension notifies as SSRF.

  - **Server-Side Template Injection (SSTI):**  
    Payloads like `{{7*7}}` are injected.  
    If the response contains the evaluated result (e.g., `49`), the extension notifies as SSTI.

  - **XML External Entity (XXE):**  
    Injects external entity payloads with out-of-band Burp Collaborator URLs.  
    If any collaborator interaction occurs, it notifies as XXE.

  - **NoSQL Injection:**  
    Injects operators like `$eq` and `$ne` into JSON parameters.  
    Based on response behavior differences. it notifies as NoSQL Injection.

### 2. 500 Error Notification
- Flags HTTP 500 Internal Server Errors returned by the application during payload injection.  
- Such errors often indicate server crashes, misconfigurations, or underlying vulnerabilities.  
- When the extension injects a payload that triggers a 500 error, it immediately notifies the tester.  
- The extension stores the full request-response pair for easy manual follow-up and deeper analysis.  
- This feature helps testers identify unstable or poorly handled inputs that require further investigation.

### 3. HTTP Method Filtering
- Allows testers to limit scans to specific HTTP methods (GET, POST, etc.).

### 5. Extension On/Off Toggle
- Easily enable or disable extension functionality during testing.

### 6. Context Menu Integration
- Right-click menu to manually trigger scans.

### 7. Duplication Prevention
- Tracks scanned requests with a SQLite database to avoid redundant testing.

### 8. Cookie Parameter Testing
- Injects payloads into cookies to find server-side logic vulnerabilities.

### 9. Excluded File Extensions
- Skips static files like .css, .js, images to focus on dynamic content.

## Technical Details

- Developed in Java using Burp Suite Extender API.
- Uses SQLite for scan history and duplication prevention.
- Detailed logging for debugging and audit.

---

## Installation

1. Download the entire zip file of the extension.  
2. Unzip the downloaded file to a desired location.  
3. Locate the `WhoAmIExtension.jar` file inside the `out` directory.  
4. Load the `WhoAmIExtension.jar` file in Burp Suite via **Extenaions > Extensions > Add**.  
5. Add the `libs` directory path to the Java environment settings in Burp Suite.  


---

## Usage

- Enable the extension using the toggle button in the extension's UI.  
- Set the HTTP methods you want the extension to process (e.g., GET, POST).  
- Select the vulnerabilities you want to check (e.g., SQLi, XSS, SSRF).  
- Browse or crawl your target application as usual.  
- Watch for vulnerability alerts and 500 error notifications in real time.  
- Use the context menu (right-click) to manually trigger scans on specific requests when needed.

---


