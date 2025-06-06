# WhoAmI Burp Extension

**WhoAmI** is a Burp Suite extension designed to automate basic manual penetration testing checks by injecting common vulnerability payloads into every parameter of proxied requests. It helps testers save time, increase parameter coverage, and get real-time notifications about vulnerabilities and server errors during manual testing.

---

## Problem Statement

During manual penetration testing, applications often have many API endpoints with numerous parameters (JSON, query, form data, cookies, headers). Manually injecting basic test payloads for vulnerabilities like SQLi, XSS, SSRF, Command Injection, etc., into each parameter is very time-consuming and error-prone.

---

## Solution

The WhoAmI extension automates the injection of basic test payloads for common vulnerabilities into every parameter of each proxied request within your testing scope. While crawling or testing the application, it performs simple but effective vulnerability checks automatically, including:

- SQL Injection payloads
- Cross-site Scripting (XSS) payloads
- Server-Side Request Forgery (SSRF) payloads
- Command Injection payloads
- NoSQL Injection payloads
- And more

It also notifies the tester instantly if a vulnerability is detected or if the server returns an HTTP 500 Internal Server Error (which is important for further manual analysis).

---

## Features

### 1. Injecting Basic Payloads into Every Parameter
- Supports Query Parameters, Form Data, JSON bodies (including nested), Cookies, and Headers.
- Example payloads for SQLi, XSS, SSRF, Command Injection, SSTI, XXE, NoSQL Injection.
- Uses Burp Suite API for seamless parameter detection and request modification.

### 2. Real-Time Response Monitoring and Notifications
- Detects reflected payloads, error messages, and HTTP 500 errors.
- Alerts via Burp Suite UI and logs for immediate attention.

### 3. 500 Error Notification
- Flags server errors indicating crashes, misconfigurations, or vulnerabilities.
- Stores request-response pairs for manual follow-up.

### 4. HTTP Method Filtering
- Allows testers to limit scans to specific HTTP methods (GET, POST, etc.).

### 5. Extension On/Off Toggle
- Easily enable or disable extension functionality during testing.

### 6. Context Menu Integration
- Right-click menu to manually trigger scans or add requests to scope.

### 7. Duplication Prevention
- Tracks scanned requests with a SQLite database to avoid redundant testing.

### 8. Cookie Parameter Testing
- Injects payloads into cookies to find server-side logic vulnerabilities.

### 9. Excluded File Extensions
- Skips static files like .css, .js, images to focus on dynamic content.

---

## Benefits

- **Time Savings:** Automates repetitive manual payload injections.
- **Comprehensive Coverage:** Tests all parameters including complex and nested ones.
- **Early Vulnerability Detection:** Immediate alerts help prioritize deeper testing.
- **Error Flagging:** Highlights HTTP 500 errors that could expose hidden issues.
- **Optimized Performance:** Filtering and duplication checks reduce unnecessary scans.
- **Easy to Use:** UI toggle and context menu integrate smoothly with Burp Suite workflows.

---

## Technical Details

- Developed in Java using Burp Suite Extender API.
- Utilizes asynchronous processing to maintain UI responsiveness.
- Uses SQLite for scan history and duplication prevention.
- Detailed logging for debugging and audit.
- Robust error handling for malformed requests and network issues.

---

## Installation

1. Download the latest `.jar` file from the [Releases](#) section.
2. Open Burp Suite and go to the Extender tab.
3. Click `Add` and select the downloaded `.jar` file.
4. Configure extension settings as needed.

---

## Usage

- Enable the extension using the toggle button.
- Set the HTTP methods and excluded extensions.
- Browse or crawl your target application.
- Watch for alerts and 500 error notifications.
- Use the context menu to manually trigger scans or add to scope.

---

## Contributing

Contributions, issues, and feature requests are welcome! Feel free to open a pull request or issue.

---

## License

[MIT License](LICENSE)

---

## Contact

For questions or support, please open an issue or contact me directly.

---

*WhoAmI helps manual penetration testers automate basic vulnerability checks with high coverage and efficiency, making your testing faster and more thorough.*
