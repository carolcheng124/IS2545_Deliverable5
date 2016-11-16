## Vulnerability 1: Cross-Site Scripting/XSS (Reflected)

####1. What part of the InfoSec Triad does this vulnerability attack (confidentiality, integrity, or availability)?
Cross-site scripting vulnerability has no impact to confidentiality or availability, and partial impact to integrity, as hackers may write data on the compromised websites by this vulnerability.

####2. What kind of security attack can exploit this vulnerability (interruption, interception, modification, or fabrication)?
*Modification and Fabrication(attack on integrity)*: For compromised website, the attackers use known vulnerabilities in web-based applications, exploiting one of these, attackers fold malicious content into the content being delivered from the compromised site.


*Interception(attack on confidentiality)*: For end user, the malicious script can access end-users’ any cookies, session tokens, or other sensitive information retained by the browser and used with that site.


####3. Are attacks that exploit this vulnerability active or passive?

Passive. Attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user. The end user’s browser has no way to know that the script should not be trusted, and will execute the script. Because it thinks the script came from a trusted source, the malicious script can access any cookies, session tokens, or other sensitive information retained by the browser and used with that site, without modifying system in any way. 


####4. What business value would be lost due to exploiting this vulnerability (data loss, unauthorized access, denial of service, etc)?
The end user’s browser will execute the malicious script from compromised website, and the malicious script can access any cookies, session tokens, or other sensitive information, even worse, malware may be loaded by script.


####5. What steps should the development team take to fix this vulnerability?
*Safely validating end-users’ input*: Limit users to utilize HTML markup. Untrusted HTML input must be run through an HTML sanitization engine to ensure that it does not contain XSS code.


*Contextual output encoding/escaping of string input*: Most web applications that do not need to accept rich data can use escaping to largely eliminate the risk of XSS attacks in a fairly straightforward manner.


*Well-written code*: XSS attack occurs when hackers found vulnerabilities in web-based applications, and exploits it. Therefore, a well-written code is also a efficient preventive measure.


####The URL of the website with the described vulnerability
http://demo.testfire.net/bank/login.aspx


####Steps taken to exploit the vulnerability:
1. Open Login page at http://demo.testfire.net/bank/login.aspx 
2. Enter `“><script>alert(1);</script>` in the userID field
3. Enter “123” in the password field
4. Click “login” button


####A screenshot (if applicable) of the vulnerability
![](https://github.com/carolcheng124/IS2545_Deliverable5/blob/master/screenshots/xss_1.png)
![](https://github.com/carolcheng124/IS2545_Deliverable5/blob/master/screenshots/xss_2.png)

## Vulnerability 2: SQL Injection

####1. What part of the InfoSec Triad does this vulnerability attack (confidentiality, integrity, or availability)?
SQL Injection vulnerability has impact to confidentiality and integrity, as hackers may read and modify sensitive data in database without authorization by this vulnerability.

####2. What kind of security attack can exploit this vulnerability (interruption, interception, modification, or fabrication)?
*Interception(attack on confidentiality)*: read sensitive data from the database
*Modification(attack on integrity)*: modify database data (Insert/Update/Delete)

####3. Are attacks that exploit this vulnerability active or passive?

Active. Hackers modify the database by insertion or "injection" of a SQL query via the input data from the client to the application.

####4. What business value would be lost due to exploiting this vulnerability (data loss, unauthorized access, denial of service, etc)?
Data loss, unauthorized access, execute administration operations on the database (such as shutdown the DBMS), and in some cases issue commands to the operating system.

####5. What steps should the development team take to fix this vulnerability?
*Pattern check*: Integer, float or boolean,string parameters can be checked if their value is valid representation for the given type. Strings that must follow some strict pattern (date, UUID, alphanumeric only, etc.) can be checked if they match this pattern.

*Parameterized statements*: instead of embedding user input in the statement, parameterized statements that work with parameters can be used. Hence the SQL injection would simply be treated as a strange (and probably invalid) parameter value.


*Escaping*: prevent injections is to escape characters that have a special meaning in SQL


*Database permissions*: Limiting the permissions on the database login used by the web application.


*User training*: training users not to type in restricted inputs in input areas.


####The URL of the website with the described vulnerability
http://demo.testfire.net/bank/login.aspx


####Steps taken to exploit the vulnerability:
1. Open login page at http://demo.testfire.net/bank/login.aspx
2. Enter “ZAP' OR '1'='1' --” in the userID field
3. Enter “ZAP' OR '1'='1' --” in the password field
4. Click “login” button

####A screenshot (if applicable) of the vulnerability
![](https://github.com/carolcheng124/IS2545_Deliverable5/blob/master/screenshots/SQL_injection_1.png)
![](https://github.com/carolcheng124/IS2545_Deliverable5/blob/master/screenshots/SQL_injection_2.png)

## Vulnerability 3: Remote OS Command Injection

####1. What part of the InfoSec Triad does this vulnerability attack (confidentiality, integrity, or availability)?
Remote OS Command Injection vulnerability has impact to confidentiality and integrity, as hackers may execution of arbitrary commands on the host operating system via a vulnerable application, which allows them to read and modify sensitive data without authorization.

####2. What kind of security attack can exploit this vulnerability (interruption, interception, modification, or fabrication)?
*Interception(attack on confidentiality)*: read sensitive data in compromised computers
*Modification(attack on integrity)*:  modify data in compromised computers

####3. Are attacks that exploit this vulnerability active or passive?

Active. Hackers modify host system by unauthorized execution of operating system commands.

####4. What business value would be lost due to exploiting this vulnerability (data loss, unauthorized access, denial of service, etc)?
Issue commands to the operating system, leading data loss, unauthorized access, execute administration operations with the elevated privilege.

####5. What steps should the development team take to fix this vulnerability?
*Use existed library or API*: a developer should use existing API or library calls rather than external processes to recreate the desired functionality for their language.

*Input validation*: If no such available API exists, the developer should check all input for malicious characters. Define the legal characters of input.

####The URL of the website with the described vulnerability
http://www.webscantest.com/osrun/whois.php


####Steps taken to exploit the vulnerability:
1. Open web page at http://www.webscantest.com/osrun/whois.php 
2. Enter “ZAP&cat /etc/passwd&” in the domain/lookup field
3. Click “lookup” button


####A screenshot (if applicable) of the vulnerability
![](https://github.com/carolcheng124/IS2545_Deliverable5/blob/master/screenshots/remote_1.png)
![](https://github.com/carolcheng124/IS2545_Deliverable5/blob/master/screenshots/remote_2.png)
