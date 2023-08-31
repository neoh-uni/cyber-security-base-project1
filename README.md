# Project 1 - Cyber Security Base
Project work for [[1]](https://cybersecuritybase.mooc.fi/) where the given task is to create a web application that has at least five different flaws from the OWASP top ten list as well as their fixes
CSRF is missing from the OWASP list as it is more rare nowadays 
due to the more secure frameworks. However, due to its fundamental nature it is allowed as a flaw.

## OWASP Top 10 Web App Security risks
https://owasp.org/www-project-top-ten/

# Installation and running
1. Install dependencies
```bash
pip install -r requirements.txt
```
2. Run the server with:
```
python manage.py runserver
```
3. Default accounts:
   | Username | Password |
   |:--------:|:--------:|
   | admin   | abcabcabc |
   | alice    | redqueen |
   | bob   | squarepants |
4. Admin page: '/admin'. Normally server starts at `http://127.0.0.1:8000`

# Vulnerabilities

## FLAW 1: A01:2021-Broken Access Control
[views.py line 22](src/pages/views.py#22)

`DESCRIPTION:` The decorator @csrf_exempt on top of transferViews function allows with the combination of a badly cryptographed sessionid to transfer user funds easily. The session can be hijacked with the provided `hijacksession.py` script, and funds can be transferred to another User by using the request.post method. @csrf_exempt ignores the csrf cookies.

`FIX:` remove @csrf_exempt from code (sessionid fix looked at next), so django will default it to @csrf_protected .


## FLAW 2: A01:2021-Broken Access Control / A02:2021-Cryptographic Failures
[badsession.py](src/config/badsession.py)
<br> 
[settings.py line 54](src/config/settings.py#54)

`DESCRIPTION:` badsession.py is a bad attempt in inventing ones own cryptographic sessionid cookie. The seasionid values can be guessed e.g. by looking at the cookies via chrome dev tools. This can lead to session hijacking provided as an example in hijacksession.py in combination with the csrf_exempt above.

`FIX:` Using djangos default sessonid handling or another proven method, removing badsession.py and line 54 with the custom session engine.


## FLAW 3: A02:2021-Cryptographic Failures 
[settings.py](src/config/settings.py)

`DESCRIPTION:` 
```
    Not setting CSRF_COOKIE_SECURE = True
    Not setting SESSION_COOKIE_SECURE = True
```
These two lines prevent transmitting cookies over HTTP instead of HTTPS accidentally. When the cookies are sent over http the data is seen in plain text.
This allows for session hijacking, and man-in-the-middle attacks where data transmission is intercepted between the user and the server, which allows for data tampering.

`FIX:` Adding them to settings.py


## FLAW 4: A02:2021-Cryptographic Failures / A07:2021-Identification and Authentication Failures
[settings.py line 23](src/config/settings.py#23)


`DESCRIPTION:` : SECRET_KEY = 'password23' . The secret_key should not be checked into the source repo hardcoded. Leaking SECRET_KEY leads to a number of vulnerabilities: creating fake session and CSRF tokens allowing the impersonation of other users to transact balance, password resets, and so on.

`FIX:` The key should be loaded from an environment variable. The keyvalue itself is very simple and should be a large random value instead.


## FLAW 5 (ish): A06:2021-Vulnerable and Outdated Components
[config/*.py](src/config/); import os

`DESCRIPTION:` The os module gives a lot of access to the system if commands are misconfigured compared to Pathlib.

`FIX:` using Pathlib instead


## FLAW 6: A07:2021-Identification and Authentication Failures
default password validation in django
[settings.py line 96](src/config/settings.py#96)


`DESCRIPTION:` the default password validation allows for minimal eight character lower case passwords like 'abcabca', which can be easily guessable. [2](https://www.passwordmonster.com/)

`FIX:` Since there are no quick fixes to implement symbols and uppercase checks [[3](https://docs.djangoproject.com/en/2.0/_modules/django/contrib/auth/password_validation/)], we will simply extend minimum password length to 16 characters for new users, by uncommenting the lines after 97-99.


## FLAW 7: A07:2021-Identification and Authentication Failures
[views.py line 41](src/pages/views.py#41),
[config/urls.py line 24](src/config/urls.py#24),
[pages/urls.py line 9](src/pages/urls.py#9)


`DESCRIPTION:` the default LoginView implementation did not prevent brute force login attempts, but allowed continuous password attempts. So the attacker could just attempt to login to the username with different passwords continuously. LoginView also cached the previously attempted username.

`FIX:` The new implementation ratelimits login attempts using django_ratelimit module. After a certain amount failed attempts the user is redirect to a 403 error page, in our case after three attempts per hour amount using the `@ratelimit` decorator. These requests should also be configured limited/blocked from the webserver, and DDOS protection e.g. 'cloudflare' could be considered. Note that the admin page is not rate limited from the backend. One should also consider adding multi-factor authentification.
`@never_cache` decorator was used to remove username cache with each page load.


## FLAW 8: A09:2021-Security Logging and Monitoring Failures
[settings.py line 26](src/config/settings.py#26)


`DESCRIPTION:` DEBUG = True, leaks information such as excerpt of source code, variables, libraries used and so on, and should be turned off for production. This can be simply tested by going to a link that doesnt exist within the server and the urls are displayed in the error report.

`FIX:` DEBUG = False, and suitable values for ALLOWED_HOST to protect site against some CSRF attacks. No hosts are currently added to the list, since it is not hosted anywhere. Also in the web server, incorrect hosts should return e.g. "444 No Response" and not forward requests to the backend.

## FLAW 9: A09:2021-Security Logging and Monitoring Failures
[views.py](src/pages/views.py#39)

`DESCRIPTION:` Auditable events such as high-value transactions should be logged.

`FIX`: Implemented simple logging for transactions with transaction time and from which account to which.
Additional considerations: The logs should be cryptographically secured. The names should be replaced by identification hashes that cannot be guessed and thus be traced by outsiders. Other events such as log in, log out, time active and failed transactions should also be considered to be logged.


## FLAW 10: Sensitive data exposure
db.sqlite3

`DESCRIPTION`: Since the data is stored locally and unencrypted, an attacker could change the balance of any account with a simple script as provided in `unsecuresql.py` when having local server access. The attacker could also see all the users and balances.

`FIX:` The database should be encrypted. It could be wise to host a separate SQL server for security and scalability if slightly larger latency is not a problem. Keeping the server and database separate provides an extra layer of security incase one or the other is compromised. SQLite does not have built-in encryption, so information on tables and key logic would still be seen even if the row values were encrypted. We could encrypt values by overriding the default `def save()` function under module.py in class Accounts:
```Python
class Account(models.Model):
	user = models.OneToOneField(User, on_delete=models.CASCADE)
	balance = models.IntegerField()

    def my_encryption():
        ...

    def save(self, *args, **kwargs):
        self.user = self.my_encryption(self.user)
        self.balance =  self.my_encryption(self.balance)
        super().save(*args, **kwargs)
```
Implementing this would currently break a lot of stuff in the current project, as decryption logic would need to be implemented, and a much easier solution would simply be to use e.g. PostgreSQL that offers encryption built-in. 

There are multiple things that could still be made better and less vulnerable and here we explored only a subset of problems; e.g. uncommon admin page url (urls.py line 22), admin alerts, logging out users automatically, https, transactions by account number, and so on. In this project I used the exercise 'bad-configuration' [1] as a django framework to introduce problems and to solve them.

## References
[1] https://cybersecuritybase.mooc.fi/ <br>
[2] https://www.passwordmonster.com/ <br>
[3] https://docs.djangoproject.com/en/2.0/_modules/django/contrib/auth/password_validation/ <br>