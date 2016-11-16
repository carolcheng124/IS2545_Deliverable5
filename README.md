

## **SECURITY TESTING**



IS 2545 - DELIVERABLE 5: Detect Security Vulnerabilities













Hanwei Cheng, Zhirun Tian

Fall 2016







**Vulnerability 1: Cross-Site Scripting/XSS (Reflected)**

**1. What part of the InfoSec Triad does this vulnerability attack (confidentiality, integrity, or availability)?**

Cross-site scripting vulnerability has no impact to confidentiality or availability, and partial impact to integrity, as hackers may write data on the compromised websites by this vulnerability.

**2. What kind of security attack can exploit this vulnerability (interruption, interception, modification, or fabrication)?**

**M**** odification and**
 ****Fabrication**** (attack on integrity)**: For compromised website, the attackers use known vulnerabilities in web-based applications, exploiting one of these, attackers fold malicious content into the content being delivered from the compromised site.

**Interception(attack on confidentiality)**: For end user, the malicious script can access end-users&#39; any cookies, session tokens, or other sensitive information retained by the browser and used with that site.

**3. Are attacks that exploit this vulnerability active or passive?**

Passive. Attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user. The end user&#39;s browser has no way to know that the script should not be trusted, and will execute the script. Because it thinks the script came from a trusted source, the malicious script can access any cookies, session tokens, or other sensitive information retained by the browser and used with that site, without modifying system in any way.

**4. What business value would be lost due to exploiting this vulnerability (data loss, unauthorized access, denial of service, etc)?**

The end user&#39;s browser will execute the malicious script from compromised website, and the malicious script can access any cookies, session tokens, or other sensitive information, even worse, malware may be loaded by script.

**5. What steps should the development team take to fix this vulnerability?**

**Safely validating end-users&#39; input:** Limit users to utilize HTML markup. Untrusted HTML input must be run through an [HTML sanitization](https://en.wikipedia.org/wiki/HTML_sanitization) engine to ensure that it does not contain XSS code.

**Contextual output encoding/escaping of string input:** Most web applications that do not need to accept rich data can use escaping to largely eliminate the risk of XSS attacks in a fairly straightforward manner.

**Well-written code:** XSS attack occurs when hackers found vulnerabilities in web-based applications, and exploits it. Therefore, a well-written code is also a efficient preventive measure.

**The URL of the website with the described vulnerability**

http://demo.testfire.net/bank/login.aspx

**Steps taken to exploit the vulnerability:**

1. Open Login page at [http://demo.testfire.net/bank/login.aspx](http://demo.testfire.net/bank/login.aspx)
2. Enter &quot; &quot;&gt;&lt;script&gt;alert(1);&lt;/script&gt;&quot; in the userID field
3. Enter &quot;123&quot; in the password field
4.


**A screenshot (if applicable) of the vulnerability**

 ![](https://github.com/carolcheng124/IS2545_Deliverable5/blob/master/screenshots/xss_1.png)
 ![](https://github.com/carolcheng124/IS2545_Deliverable5/blob/master/screenshots/xss_3.png)


**Vulnerability 2:  SQL Injection**

**1. What part of the InfoSec Triad does this vulnerability attack (confidentiality, integrity, or availability)?**

SQL Injection vulnerability has impact to confidentiality and integrity, as hackers may read and modify sensitive data in database without authorization by this vulnerability.

**2. What kind of security attack can exploit this vulnerability (interruption, interception, modification, or fabrication)?**

**Interception(attack on confidentiality):** read sensitive data from the database

**Modification(attack on integrity):** modify database data (Insert/Update/Delete)

**3. Are attacks that exploit this vulnerability active or passive?**

Active. Hackers modify the database by insertion or &quot;injection&quot; of a SQL query via the input data from the client to the application.

**4. What business value would be lost due to exploiting this vulnerability (data loss, unauthorized access, denial of service, etc)?**

Data loss, unauthorized access, execute administration operations on the database (such as shutdown the DBMS), and in some cases issue commands to the operating system.

**5. What steps should the development team take to fix this vulnerability?**

**Pattern check** : Integer, float or boolean,string parameters can be checked if their value is valid representation for the given type. Strings that must follow some strict pattern (date, UUID, alphanumeric only, etc.) can be checked if they match this pattern.

**Parameterized statements** : instead of embedding user input in the statement, parameterized statements that work with parameters can be used. Hence the SQL injection would simply be treated as a strange (and probably invalid) parameter value.

**Escaping** : prevent injections is to escape characters that have a special meaning in SQL

**Database permissions** : Limiting the permissions on the database login used by the web application.

**User training:** training users not to type in restricted inputs in input areas.

**The URL of the website with the described vulnerability**

[http://demo.testfire.net/bank/login.aspx](http://demo.testfire.net/bank/login.aspx)

**Steps taken to exploit the vulnerability:**

1. Open login page at [http://demo.testfire.net/bank/login.aspx](http://demo.testfire.net/bank/login.aspx)
2. Enter &quot;ZAP&#39; OR &#39;1&#39;=&#39;1&#39; --&quot; in the userID field
3. Enter &quot;ZAP&#39; OR &#39;1&#39;=&#39;1&#39; --&quot; in the password field
4. Click &quot;login&quot; button

**A screenshot (if applicable) of the vulnerability.**

 ![](https://github.com/carolcheng124/IS2545_Deliverable5/blob/master/screenshots/SQL_injection_2.png)

**Vulnerability 3: Remote OS Command Injection**

**1. What part of the InfoSec Triad does this vulnerability attack (confidentiality, integrity, or availability)?**

Remote OS Command Injection vulnerability has impact to confidentiality and integrity, as hackers may execution of arbitrary commands on the host operating system via a vulnerable application, which allows them to read and modify sensitive data without authorization.

**2. What kind of security attack can exploit this vulnerability (interruption, interception, modification, or fabrication)?**

**Interception:** read sensitive data in compromised computers

**Modification:** modify data in compromised computers

**3. Are attacks that exploit this vulnerability active or passive?**

Active. Hackers modify host system by _unauthorized execution of operating system commands._

**4. What business value would be lost due to exploiting this vulnerability (data loss, unauthorized access, denial of service, etc)?**

Issue commands to the operating system, leading data loss, unauthorized access, execute administration operations _with the elevated privilege_.

**5. What steps should the development team take to fix this vulnerability?**

**Use existed library or API** : a developer should use existing API or library calls rather than external processes to recreate the desired functionality for their language.

**Input validation:** If no such available API exists, the developer should check all input for malicious characters. Define the legal characters of input.

**The URL of the website with the described vulnerability**

http://www.webscantest.com/osrun/whois.php

**Steps taken to exploit the vulnerability:**

1. Open web page at [http://www.webscantest.com/osrun/whois.php](http://www.webscantest.com/osrun/whois.php)
2. Enter &quot;ZAP&amp;cat /etc/passwd&amp;&quot; in the domain/lookup field
3. Click &quot;lookup&quot; button

**A screenshot (if applicable) of the vulnerability.
 ![](https://github.com/carolcheng124/IS2545_Deliverable5/blob/master/screenshots/remote_2.png)

**Vulnerability 4: Cleartext submission of password**

**1. What part of the InfoSec Triad does this vulnerability attack (confidentiality, integrity, or availability)?**

Cleartext submission of password have impact to confidentiality and availability, as hackers may read sensitive data such as submited password without authorization by this vulnerability.

**2. What kind of security attack can exploit this vulnerability (interruption, interception, modification, or fabrication)?**

**Interception:** read sensitive data from the post

**3. Are attacks that exploit this vulnerability active or passive?**

Passive. Only when the user try to log in, the hacker could get the uncoded password data.

**4. What business value would be lost due to exploiting this vulnerability (data loss, unauthorized access, denial of service, etc)?**

After the hacker get the admin&#39;s password, the hacker could get into the system, then try to upload some trojans to seduce the visitor of the website download the trojans. What&#39;s more, the hacker could also find some exploit to get superuser privilege from the original privilege(of the role of the web engine).

**5. What steps should the development team take to fix this vulnerability?**

**Use HTTPS (SSL/TLS)**:hacker in the same LAN network could difficult sniff the data crypted by Secure Socket Layer.

**Use encrypted data** : original password is not necessary, only the md5 or similar hash is enough.

**Add activeX controller** : the website could develop a activeX controller in IE to prevent other software use proxy(then the website could only be allowed to used with IE and the activeX).

**The URL of the website with the described vulnerability**

[http://demo.testfire.net/bank/login.aspx](http://demo.testfire.net/bank/login.aspx)

**Steps taken to exploit the vulnerability:**

1. Open login page at [http://demo.testfire.net/bank/login.aspx](http://demo.testfire.net/bank/login.aspx)
2. Open burpsuite and configure the proxy to make the browser use Burp Suite as proxy
3. Open intercept on in Burp Suite
4. Enter &quot;111&quot; in the userID field
5. Enter &quot;222&quot; in the password field
6. Click &quot;login&quot; button

**A screenshot (if applicable) of the vulnerability.**

 ![](https://github.com/carolcheng124/IS2545_Deliverable5/blob/master/screenshots/4ClearPassword1.png)
**Vulnerability 5: CSRF(Cross Site Request Forgery) attack not prevented**

**1. What part of the InfoSec Triad does this vulnerability attack (confidentiality, integrity, or availability)?**

CSRF attack vulnerabilities have impact to integrity, as hackers may modify user to operate sensitive data in database without authorization by this vulnerability.

**2. What kind of security attack can exploit this vulnerability (interruption, interception, modification, or fabrication)?**

**Modification:** modify user operation.

**3. Are attacks that exploit this vulnerability active or passive?**

Passive. Hackers have to wait user load a external webpage so the CSRF attack would work.

**4. What business value would be lost due to exploiting this vulnerability (data loss, unauthorized access, denial of service, etc)?**

Hacker could make the user do any operation if the user have the privilege. For example, change password, transfer some money to another person&#39;s account.



**5. What steps should the development team take to fix this vulnerability?**

**Add nonce** : A nonce(a random number or string built each several minutes)  is a identifer to make sure all the operation is made by the user. A csrf request could not get the newest nonce.

**The URL of the website with the described vulnerability**

[http://demo.testfire.net/bank/login.aspx](http://demo.testfire.net/bank/login.aspx)

**Steps taken to exploit the vulnerability:**

1. Open login page at [http://demo.testfire.net/bank/login.aspx](http://demo.testfire.net/bank/login.aspx)
2. Enter &quot;ZAP&#39; OR &#39;1&#39;=&#39;1&#39; --&quot; in the userID field
3. Enter &quot;ZAP&#39; OR &#39;1&#39;=&#39;1&#39; --&quot; in the password field
4. Open a config page [http://demo.testfire.net/bank/customize.aspx](http://demo.testfire.net/bank/customize.aspx)
5. Open a modified CSRF PoC ([https://github.com/carolcheng124/IS2545_Deliverable5/blob/master/csrf1.html](https://github.com/carolcheng124/IS2545_Deliverable5/blob/master/csrf1.html))
6. Click &quot;Submit request&quot; button



**The PoC HTML Source code:**

~~~~
&lt;html&gt;
  &lt;body&gt;
    &lt;form action=&quot;http://demo.testfire.net/bank/customize.aspx&quot;&gt;
      &lt;input type=&quot;hidden&quot; name=&quot;lang&quot; value=&quot;international&quot; /&gt;
      &lt;input type=&quot;submit&quot; value=&quot;Submit request&quot; /&gt;
    &lt;/form&gt;
  &lt;/body&gt;
&lt;/html&gt;
~~~~

**A screenshot (if applicable) of the vulnerability.**

![](https://github.com/carolcheng124/IS2545_Deliverable5/blob/master/screenshots/5CSRF1.png)
--------------------------------------------------------------------------------






Reference:

[https://en.wikipedia.org/wiki/Cross-site\_scripting](https://en.wikipedia.org/wiki/Cross-site_scripting)

[https://www.owasp.org/index.php/Cross-site\_Scripting\_(XSS)](https://www.owasp.org/index.php/Cross-site_Scripting_(XSS))

[https://en.wikipedia.org/wiki/SQL\_injection](https://en.wikipedia.org/wiki/SQL_injection)

[https://www.owasp.org/index.php/SQL\_Injection](https://www.owasp.org/index.php/SQL_Injection)

[https://www.owasp.org/index.php/Command\_Injection](https://www.owasp.org/index.php/Command_Injection)

https://www.owasp.org/index.php/Command\_Injection

