# IS2545_Deliverable5

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
1.Open Login page at http://demo.testfire.net/bank/login.aspx 
2.Enter “ "><script>alert(1);</script>” in the userID field
3.Enter “123” in the password field
4. Click “login” button


####A screenshot (if applicable) of the vulnerability
![](http://ww4.sinaimg.cn/bmiddle/aa397b7fjw1dzplsgpdw5j.jpg)
