# Project 1 - Cyber Security Base
The task is to create a web application that has at least five different
 flaws from the OWASP top ten list as well as their fixes
CSRF is missing from the list as it is more rare nowadays 
due to the more secure frameworks. However, due to its fundamental nature it is allowed as a flaw.

## OWASP Top 10 Web App Security risks
https://owasp.org/www-project-top-ten/
### [A01:2021-Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)



    Violation of the principle of least privilege or deny by default, where access should only be granted for particular capabilities, roles, or users, but is available to anyone.

    Bypassing access control checks by modifying the URL (parameter tampering or force browsing), internal application state, or the HTML page, or by using an attack tool modifying API requests.

    Permitting viewing or editing someone else's account, by providing its unique identifier (insecure direct object references)

    Accessing API with missing access controls for POST, PUT and DELETE.

    Elevation of privilege. Acting as a user without being logged in or acting as an admin when logged in as a user.

    Metadata manipulation, such as replaying or tampering with a JSON Web Token (JWT) access control token, or a cookie or hidden field manipulated to elevate privileges or abusing JWT invalidation.

    CORS misconfiguration allows API access from unauthorized/untrusted origins.

    Force browsing to authenticated pages as an unauthenticated user or to privileged pages as a standard user.

### [A02:2021-Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

    Is any data transmitted in clear text? This concerns protocols such as HTTP, SMTP, FTP also using TLS upgrades like STARTTLS. External internet traffic is hazardous. Verify all internal traffic, e.g., between load balancers, web servers, or back-end systems.

    Are any old or weak cryptographic algorithms or protocols used either by default or in older code?

    Are default crypto keys in use, weak crypto keys generated or re-used, or is proper key management or rotation missing? Are crypto keys checked into source code repositories?

    Is encryption not enforced, e.g., are any HTTP headers (browser) security directives or headers missing?

    Is the received server certificate and the trust chain properly validated?

    Are initialization vectors ignored, reused, or not generated sufficiently secure for the cryptographic mode of operation? Is an insecure mode of operation such as ECB in use? Is encryption used when authenticated encryption is more appropriate?

    Are passwords being used as cryptographic keys in absence of a password base key derivation function?

    Is randomness used for cryptographic purposes that was not designed to meet cryptographic requirements? Even if the correct function is chosen, does it need to be seeded by the developer, and if not, has the developer over-written the strong seeding functionality built into it with a seed that lacks sufficient entropy/unpredictability?

    Are deprecated hash functions such as MD5 or SHA1 in use, or are non-cryptographic hash functions used when cryptographic hash functions are needed?

    Are deprecated cryptographic padding methods such as PKCS number 1 v1.5 in use?

    Are cryptographic error messages or side channel information exploitable, for example in the form of padding oracle attacks?

FLAW {
    Not setting CSRF_COOKIE_SECURE = True
    Not setting SESSION_COOKIE_SECURE = True
    config/badsession.py
    settings.py:
    line 54 SESSION_ENGINE = 'src.config.badsession' 
    line 23: SECRET_KEY = 'password23'
}
The first two prevent transmitting cookies over HTTP instead of HTTPS accidentally.
badsession.py is a bad attempt in inventing ones own cryptographic session cookie, and very easily guessable, which could lead to session hijacking.
SECRET_KEY should not be checked into the source repo, and the password itself is very simple.
m
fix:    Add the first two True lines to settings.py . Remove the bad sessionid attempt and use default django sessionid handling.
SECRET_KEY, instead of hardcoding it, load it from an environment variable. The key should also be a large random value.
### [A03:2021-Injection](https://owasp.org/Top10/A03_2021-Injection/)


    User-supplied data is not validated, filtered, or sanitized by the application.

    Dynamic queries or non-parameterized calls without context-aware escaping are used directly in the interpreter.

    Hostile data is used within object-relational mapping (ORM) search parameters to extract additional, sensitive records.

    Hostile data is directly used or concatenated. The SQL or command contains the structure and malicious data in dynamic queries, commands, or stored procedure

### [A04:2021-Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
Scenario #1: A credential recovery workflow might include “questions and answers,” which is prohibited by NIST 800-63b, the OWASP ASVS, and the OWASP Top 10. Questions and answers cannot be trusted as evidence of identity as more than one person can know the answers, which is why they are prohibited. Such code should be removed and replaced with a more secure design.

Scenario #2: A cinema chain allows group booking discounts and has a maximum of fifteen attendees before requiring a deposit. Attackers could threat model this flow and test if they could book six hundred seats and all cinemas at once in a few requests, causing a massive loss of income.

### [A05:2021-Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)


    Missing appropriate security hardening across any part of the application stack or improperly configured permissions on cloud services.

    Unnecessary features are enabled or installed (e.g., unnecessary ports, services, pages, accounts, or privileges).

    Default accounts and their passwords are still enabled and unchanged.

    Error handling reveals stack traces or other overly informative error messages to users.

    For upgraded systems, the latest security features are disabled or not configured securely.

    The security settings in the application servers, application frameworks (e.g., Struts, Spring, ASP.NET), libraries, databases, etc., are not set to secure values.

    The server does not send security headers or directives, or they are not set to secure values.

    The software is out of date or vulnerable (see A06:2021-Vulnerable and Outdated Components).



### [A06:2021-Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
FLAW { settings.py: import os; to use os.path
} The os module gives a lot of access to the system if commands are misconfigured compared to Pathlib.
fix: using Pathlib instead
### [A07:2021-Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks. There may be authentication weaknesses if the application:

    Permits automated attacks such as credential stuffing, where the attacker has a list of valid usernames and passwords.

    Permits brute force or other automated attacks.

    Permits default, weak, or well-known passwords, such as "Password1" or "admin/admin".

    Uses weak or ineffective credential recovery and forgot-password processes, such as "knowledge-based answers," which cannot be made safe.

    Uses plain text, encrypted, or weakly hashed passwords data stores (see A02:2021-Cryptographic Failures).

    Has missing or ineffective multi-factor authentication.

    Exposes session identifier in the URL.

    Reuse session identifier after successful login.

    Does not correctly invalidate Session IDs. User sessions or authentication tokens (mainly single sign-on (SSO) tokens) aren't properly invalidated during logout or a period of inactivity.

How to Prevent

    Where possible, implement multi-factor authentication to prevent automated credential stuffing, brute force, and stolen credential reuse attacks.

    Do not ship or deploy with any default credentials, particularly for admin users.

    Implement weak password checks, such as testing new or changed passwords against the top 10,000 worst passwords list.

    Align password length, complexity, and rotation policies with National Institute of Standards and Technology (NIST) 800-63b's guidelines in section 5.1.1 for Memorized Secrets or other modern, evidence-based password policies.

    Ensure registration, credential recovery, and API pathways are hardened against account enumeration attacks by using the same messages for all outcomes.

    Limit or increasingly delay failed login attempts, but be careful not to create a denial of service scenario. Log all failures and alert administrators when credential stuffing, brute force, or other attacks are detected.

    Use a server-side, secure, built-in session manager that generates a new random session ID with high entropy after login. Session identifier should not be in the URL, be securely stored, and invalidated after logout, idle, and absolute timeouts.

### [A08:2021-Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
### [A09:2021-Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)


    Auditable events, such as logins, failed logins, and high-value transactions, are not logged.

    Warnings and errors generate no, inadequate, or unclear log messages.

    Logs of applications and APIs are not monitored for suspicious activity.

    Logs are only stored locally.

    Appropriate alerting thresholds and response escalation processes are not in place or effective.

    Penetration testing and scans by dynamic application security testing (DAST) tools (such as OWASP ZAP) do not trigger alerts.

    The application cannot detect, escalate, or alert for active attacks in real-time or near real-time.

FLAW {
settings.py:
            line 26: DEBUG = True
Auditable events are not logged       
}
DEBUG = True, leaks information such as excerpt of source code, variables, libraries used and so on, and should be turned off for production.
Auditable events such as high-value transactions are not logged.
fix: DEBUG = False, and suitable values for ALLOWED_HOST to protect site against some CSRF attacks. Also in the web server, incorrect hosts should return e.g. "444 No Response" and not forward requests to django.
Logging should be implemented, and made sure that sensitive parameters such as passwords and credit card numbers are not logged, e.g via djangos sensitive_post_parameter decorator for POST parameters or by custom error reports.

### [A10:2021-Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL

From Application layer:

    Sanitize and validate all client-supplied input data

    Enforce the URL schema, port, and destination with a positive allow list

    Do not send raw responses to clients

    Disable HTTP redirections

    Be aware of the URL consistency to avoid attacks such as DNS rebinding and “time of check, time of use” (TOCTOU) race conditions


Scenario #2: Sensitive data exposure – Attackers can access local files or internal services to gain sensitive information such as file:///etc/passwd and http://localhost:28017/