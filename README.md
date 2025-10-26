Scanning local machine for vulnerabilities using nessus

1) Installed nessus and used basic scan

   <img width="1096" height="571" alt="image" src="https://github.com/user-attachments/assets/ca48481b-8d0f-47a2-bdc3-876d39526e6f" />

2) Found local host IP using ipconfig and created a new scan.
   
3)  Ran the scan
   
   <img width="1189" height="573" alt="image" src="https://github.com/user-attachments/assets/cbb5721b-5404-42b3-8190-cfa9bc122936" />

4) Analyze the generated reports
   
   <img width="1142" height="576" alt="image" src="https://github.com/user-attachments/assets/750241df-633d-4639-80c0-a88fa882c4ef" />

   Full report attached as pdf

Mitigation for 2 found vulnerabilities

1. SMB Signing Not Required

Severity: Medium (CVSS 5.3)
Description:
SMB signing is a security feature that helps prevent man-in-the-middle (MITM) attacks by digitally signing SMB communications. When SMB signing is not required, an attacker on the same network could intercept or modify SMB traffic.

Mitigation Steps:

Enable SMB signing on all servers and clients where possible.

On Windows:

Open Local Security Policy (secpol.msc).

Go to:
Security Settings > Local Policies > Security Options.

Enable:

“Microsoft network client: Digitally sign communications (always)”

“Microsoft network server: Digitally sign communications (always)”

Alternatively, set via Group Policy:

Path: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options

Restart SMB services or the system for the change to take effect.

Ensure domain controllers have signing required (they usually do by default).

2. SSL (Multiple Issues)

Severity: Mixed (varies depending on sub-issues)
Description:
This typically means Nessus found several SSL/TLS weaknesses (e.g., weak ciphers, outdated protocols, self-signed certificates, or missing intermediate CA certificates).

Possible Mitigation Steps:
Depending on the specific SSL findings (you can expand this in Nessus for details), apply these general fixes:

Disable weak SSL/TLS versions:

Disable SSLv2, SSLv3, and TLS 1.0 / 1.1.

Use TLS 1.2 or TLS 1.3 only.

Disable weak ciphers:

Remove RC4, DES, 3DES, MD5, or NULL ciphers.

Use AES-GCM or ChaCha20-based ciphers.

Update certificates:

Ensure certificates are valid, not self-signed, and use SHA-256 or stronger signatures.

Renew expired certificates.

Enable Perfect Forward Secrecy (PFS):

Prioritize ECDHE or DHE ciphers.

  **Questions**
  
1. What is vulnerability scanning?
   
Vulnerability scanning is an automated process used to find security weaknesses in computers, networks, or applications. It checks for outdated software, missing patches, weak configurations, and other flaws that attackers could exploit.

2. Difference between vulnerability scanning and penetration testing
   
Vulnerability scanning identifies known weaknesses automatically, while penetration testing actively tries to exploit them to see how serious they are. Scanning is broad and non-intrusive, while penetration testing is deeper, more manual, and simulates real attacks.

3. What are some common vulnerabilities in personal computers?
   
Common vulnerabilities include outdated operating systems, weak passwords, open ports, unpatched software, malware infections, and improperly configured firewalls or security settings.

4. How do scanners detect vulnerabilities?
   
Scanners compare system details like software versions and configurations against known vulnerability databases. They check for open ports, missing patches, default passwords, and insecure settings using automated tests and signature-based detection.

5. What is CVSS?
    
CVSS stands for Common Vulnerability Scoring System. It provides a standardized score from 0 to 10 to indicate how severe a vulnerability is, helping organizations decide which issues to fix first.

6. How often should vulnerability scans be performed?
    
Vulnerability scans should be done regularly, such as monthly or quarterly, and also after major system changes, new software installations, or network updates. They should also be done before audits or compliance reviews.

7. What is a false positive in vulnerability scanning?
    
A false positive happens when a scanner reports a vulnerability that isn’t actually present. For example, a scanner might flag a patched system as still vulnerable.

8. How do you prioritize vulnerabilities?

Vulnerabilities are prioritized based on their severity (using CVSS scores), the importance of the affected system, whether an exploit is publicly available, and the potential impact on business operations.

  

   

