# EDR Investigation Write Up 

## Objective

This investigation involved analyzing endpoint and email-based threats using tools like CrowdStrike and Proofpoint to detect suspicious activity across user devices and communication channels. The investigation focused on identifying the source of the threat, containing the affected systems, and implementing preventative measures to reduce future risk.

### Skills Learned

- Ability to analyze endpoint activity to detect malicious behavior
- Gained experience using CrowdStrike for real-time threat detection and incident investigation
- Learned how to use Proofpoint to identify phishing attempts and email-based threats
- Developed skills in triaging alerts and determining the severity of security incidents
- Strengthened ability to trace the origin of threats and understand attack patterns
- Practiced documenting findings and communicating investigation results clearly
- Improved decision-making in containing threats and preventing further impact



### Tools Used

- Proofpoint – to detect and analyze phishing emails, malicious links, and attachments targeting users
- SentinelOne – for real-time endpoint detection, threat containment, and forensic analysis
- VirusTotal – to scan and verify suspicious files, URLs, and hash values using multiple antivirus engines
- Hybrid Analysis – for dynamic malware analysis and behavior profiling of potentially malicious files
- IBM X-Force Exchange – to gather threat intelligence, research indicators of compromise (IOCs), and correlate activity with known threat actors

## Steps

1. Initial Detection and Alert Triage

Reviewed alerts from SentinelOne and Proofpoint for unusual endpoint activity and potential phishing attempts.

Prioritized incidents based on severity and potential impact.

2. Isolate Affected Endpoints

Used SentinelOne to isolate compromised endpoints from the network to prevent lateral movement and further infection.

3. Analyze Suspicious Files and Activities

Uploaded suspicious files or URLs to VirusTotal and Hybrid Analysis for deeper analysis, looking for malware signatures and behavioral patterns.

Correlated findings from endpoint logs with external threat intelligence.

4. Conduct Root Cause Analysis

Investigated the source and delivery method of the attack using IBM X-Force Exchange and cross-referenced IOCs with known threat actor tactics.

5.Contain and Mitigate Threats

Used SentinelOne to quarantine malicious processes and remove threats from the affected systems.

Implemented security measures to block the attack’s entry points, such as blocking malicious IPs and Hashs.

6. Communicate Findings and Document the Incident

Documented the investigation process, actions taken, and lessons learned.

7. Post-Incident Review and Prevention

Analyzed the attack to identify security gaps and recommended changes to improve defenses, such as stronger email filtering and endpoint hardening.
Example below.

Below i have attached the Full Write up

(https://docs.google.com/document/d/1pI0oDN8dOeyLHXy8wfl0xIsCnzorLfUDjVzWG6xgU_A/edit?usp=sharing)
