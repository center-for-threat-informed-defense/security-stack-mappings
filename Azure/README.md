
Azure Controls
==============

Contents
========

* [Introduction](#introduction)
* [Controls](#controls)
	* [1. Adaptive Application Controls](#1-adaptive-application-controls)
	* [2. Advanced Threat Protection for Azure SQL Database](#2-advanced-threat-protection-for-azure-sql-database)
	* [3. Alerts for Azure Cosmos DB](#3-alerts-for-azure-cosmos-db)
	* [4. Alerts for DNS](#4-alerts-for-dns)
	* [5. Alerts for Windows Machines](#5-alerts-for-windows-machines)
	* [6. Azure AD Identity Protection](#6-azure-ad-identity-protection)
	* [7. Azure AD Identity Secure Score](#7-azure-ad-identity-secure-score)
	* [8. Azure AD Multi-Factor Authentication](#8-azure-ad-multi-factor-authentication)
	* [9. Azure AD Password Policy](#9-azure-ad-password-policy)
	* [10. Azure AD Privileged Identity Management](#10-azure-ad-privileged-identity-management)
	* [11. Azure Active Directory Password Protection](#11-azure-active-directory-password-protection)
	* [12. Azure Alerts for Network Layer](#12-azure-alerts-for-network-layer)
	* [13. Azure Automation Update Management](#13-azure-automation-update-management)
	* [14. Azure Backup](#14-azure-backup)
	* [15. Azure DDOS Protection Standard](#15-azure-ddos-protection-standard)
	* [16. Azure DNS Alias Records](#16-azure-dns-alias-records)
	* [17. Azure DNS Analytics](#17-azure-dns-analytics)
	* [18. Azure Dedicated HSM](#18-azure-dedicated-hsm)
	* [19. Azure Defender for App Service](#19-azure-defender-for-app-service)
	* [20. Azure Defender for Container Registries](#20-azure-defender-for-container-registries)
	* [21. Azure Defender for Key Vault](#21-azure-defender-for-key-vault)
	* [22. Azure Defender for Kubernetes](#22-azure-defender-for-kubernetes)
	* [23. Azure Defender for Resource Manager](#23-azure-defender-for-resource-manager)
	* [24. Azure Defender for Storage](#24-azure-defender-for-storage)
	* [25. Azure Firewall](#25-azure-firewall)
	* [26. Azure Key Vault](#26-azure-key-vault)
	* [27. Azure Network Traffic Analytics](#27-azure-network-traffic-analytics)
	* [28. Azure Policy](#28-azure-policy)
	* [29. Azure Private Link](#29-azure-private-link)
	* [30. Azure Security Center Recommendations](#30-azure-security-center-recommendations)
	* [31. Azure Sentinel](#31-azure-sentinel)
	* [32. Azure VPN Gateway](#32-azure-vpn-gateway)
	* [33. Azure Web Application Firewall](#33-azure-web-application-firewall)
	* [34. Cloud App Security Policies](#34-cloud-app-security-policies)
	* [35. Conditional Access](#35-conditional-access)
	* [36. Continuous Access Evaluation](#36-continuous-access-evaluation)
	* [37. Docker Host Hardening](#37-docker-host-hardening)
	* [38. File Integrity Monitoring](#38-file-integrity-monitoring)
	* [39. Integrated Vulnerability Scanner Powered by Qualys](#39-integrated-vulnerability-scanner-powered-by-qualys)
	* [40. Just-in-Time VM Access](#40-just-in-time-vm-access)
	* [41. Linux auditd alerts and Log Analytics agent integration](#41-linux-auditd-alerts-and-log-analytics-agent-integration)
	* [42. Managed identities for Azure resources](#42-managed-identities-for-azure-resources)
	* [43. Microsoft Antimalware for Azure](#43-microsoft-antimalware-for-azure)
	* [44. Microsoft Defender for Identity](#44-microsoft-defender-for-identity)
	* [45. Network Security Groups](#45-network-security-groups)
	* [46. Passwordless Authentication](#46-passwordless-authentication)
	* [47. Role Based Access Control](#47-role-based-access-control)
	* [48. SQL Vulnerability Assessment](#48-sql-vulnerability-assessment)
* [Control Tags](#control-tags)
	* [1. Adaptive Network Hardening](#1-adaptive-network-hardening)
	* [2. Analytics](#2-analytics)
	* [3. Azure Active Directory](#3-azure-active-directory)
	* [4. Azure Defender](#4-azure-defender)
	* [5. Azure Defender for SQL](#5-azure-defender-for-sql)
	* [6. Azure Defender for Servers](#6-azure-defender-for-servers)
	* [7. Azure Security Center](#7-azure-security-center)
	* [8. Azure Security Center Recommendation](#8-azure-security-center-recommendation)
	* [9. Containers](#9-containers)
	* [10. Credentials](#10-credentials)
	* [11. DNS](#11-dns)
	* [12. Database](#12-database)
	* [13. Identity](#13-identity)
	* [14. Linux](#14-linux)
	* [15. MFA](#15-mfa)
	* [16. Microsoft 365 Defender](#16-microsoft-365-defender)
	* [17. Network](#17-network)
	* [18. Passwords](#18-passwords)
	* [19. Threat Hunting](#19-threat-hunting)
	* [20. Windows](#20-windows)

# Introduction


This page enumerates the native security controls available on the Azure platform that have been mapped to [MITRE ATT&CK](https://attack.mitre.org/).  <br>Most controls included in scope were derived from the [Azure Security Benchmark (v2)](https://docs.microsoft.com/en-us/azure/security/benchmarks/overview) and our own independent research.

[Aggregate Navigator Layer For All Controls](layers/platform.json) ([JSON](layers/platform.json))
# Controls

## 1. Adaptive Application Controls


Security Center's Adaptive Application Controls uses machine learning to analyze the applications running on machines and create a list of known-safe software. Allow lists are based on specific Azure workloads and can be further customized. They are based on trusted paths, publishers, and hashes. When Adaptive Application Controls are enabled, security alerts are generated when applications are run that have not been defined as safe.

- [Mapping File](AdaptiveApplicationControls.yaml) ([YAML](AdaptiveApplicationControls.yaml))
- [Navigator Layer](layers/AdaptiveApplicationControls.json) ([JSON](layers/AdaptiveApplicationControls.json))

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1036 - Masquerading](https://attack.mitre.org/techniques/T1036/)|Detect|Partial|This control provides detection for some of this technique's sub-techniques and procedure examples and therefore its coverage score is Partial, resulting in a Partial score. Its detection occurs once every twelve hours, so its temporal score is also Partial.|
|[T1204 - User Execution](https://attack.mitre.org/techniques/T1204/)|Detect|Partial|This control only provides detection for one of this technique's sub-techniques while not providing any detection capability for its other sub-technique, and therefore its coverage score is Partial, resulting in a Partial score.|
|[T1553 - Subvert Trust Controls](https://attack.mitre.org/techniques/T1553/)|Detect|Minimal|This control only provides detection for one of this technique's sub-techniques while not providing any detection capability for the remaining sub-techniques, and therefore its coverage score is Minimal, resulting in a Minimal score.|
|[T1554 - Compromise Client Software Binary](https://attack.mitre.org/techniques/T1554/)|Detect|Partial|Once this control is activated, it generates alerts for any executable that is run and is not included in an allow list. While name and publisher-based allow lists may fail to detect malicious modifications to executable client binaries, hash-based rules will still detect untrusted executables. Events are calculated once every twelve hours, so its temporal score is Partial.|
  


### Tag(s)
- [Azure Defender for Servers](#6-azure-defender-for-servers)
- [Azure Security Center](#7-azure-security-center)
- [Azure Security Center Recommendation](#8-azure-security-center-recommendation)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/security-center-adaptive-application>
  

  [Back to Table Of Contents](#contents)
## 2. Advanced Threat Protection for Azure SQL Database


This control provides alerts for Azure SQL Database, Azure SQL Managed Instance, and Azure Synapse Analytics. An alert may be generated on suspicious database activities, potential vulnerabilities, and SQL injection attacks, as well as anomalous database access and query patterns.

- [Mapping File](ATPForAzureSQLDatabase.yaml) ([YAML](ATPForAzureSQLDatabase.yaml))
- [Navigator Layer](layers/ATPForAzureSQLDatabase.json) ([JSON](layers/ATPForAzureSQLDatabase.json))

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Detect|Minimal|This control only provides alerts for a set of Azure database offerings. Databases that have been deployed to endpoints within Azure or third-party databases deployed to Azure do not generate alerts for this control.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Detect|Minimal|This control covers the majority of sub-techniques for this parent technique and may cover both successful and unsuccessful brute force attacks. This control only provides alerts for a set of Azure database offerings. Databases that have been deployed to endpoints within Azure or third-party databases deployed to Azure do not generate alerts for this control.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Detect|Minimal|This control may alert on usage of faulty SQL statements. This generates an alert for a possible SQL injection by an application. Alerts may not be generated on usage of valid SQL statements by attackers for malicious purposes.|
|[T1213 - Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)|Detect|Minimal|This control may alert on extraction of a large amount of data to an unusual location. No documentation is provided on the logic for determining an unusual location.|
  


### Tag(s)
- [Azure Defender](#4-azure-defender)
- [Azure Defender for SQL](#5-azure-defender-for-sql)
- [Azure Security Center](#7-azure-security-center)
- [Azure Security Center Recommendation](#8-azure-security-center-recommendation)
- [Database](#12-database)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/azure-sql/database/threat-detection-overview>
- <https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-sql-db-and-warehouse>
  

  [Back to Table Of Contents](#contents)
## 3. Alerts for Azure Cosmos DB


The Azure Cosmos DB alerts are generated by unusual and potentially harmful attempts to access or exploit Azure Cosmos DB accounts.

- [Mapping File](AlertsForAzureCosmosDB.yaml) ([YAML](AlertsForAzureCosmosDB.yaml))
- [Navigator Layer](layers/AlertsForAzureCosmosDB.json) ([JSON](layers/AlertsForAzureCosmosDB.json))

### Mapping Comments


This control is still in preview, so its coverage will likely expand in the future. This mapping is based on its current (preview) state.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Detect|Minimal|This control's detection is specific to the Cosmos DB and therefore provides minimal overall detection coverage for Valid Accounts resulting in a Minimal score. A relevant alert is "Access from an unusual location to a Cosmos DB account".|
|[T1213 - Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)|Detect|Minimal|This control triggers an alert when an unusually large amount of data is extracted from/by an account compared to recent activity. False positives are fairly likely and extraction in quantities below the control's threshold is not detected, so score is Minimal. Neither of the sub-techniques are relevant in this context, since they are repository-specific.  Relevant alert is "Unusual amount of data extracted from a Cosmos DB account"|
  


### Tag(s)
- [Azure Security Center](#7-azure-security-center)
- [Database](#12-database)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/alerts-reference>
- <https://docs.microsoft.com/en-us/azure/security-center/other-threat-protections>
- <https://docs.microsoft.com/en-us/azure/cosmos-db/cosmos-db-advanced-threat-protection>
  

  [Back to Table Of Contents](#contents)
## 4. Alerts for DNS


Azure Defender for DNS provides an additional layer of protection for your cloud resources by continuously monitoring all DNS queries from your Azure resources and running advanced security analytics to alert you about suspicious activity


- [Mapping File](AlertsForDNS.yaml) ([YAML](AlertsForDNS.yaml))
- [Navigator Layer](layers/AlertsForDNS.json) ([JSON](layers/AlertsForDNS.json))

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)|Detect|Minimal|Can detect anomalous use of DNS.  Because this detection is specific to DNS, its coverage score is Minimal resulting in an overall Minimal score.|
|[T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)|Detect|Minimal|Can detect potential DNS protocol misuse/anomalies. Technique coverage is restricted to DNS and therefore results in a Minimal score.|
|[T1090 - Proxy](https://attack.mitre.org/techniques/T1090/)|Detect|Minimal|Can detect DNS activity to anonymity networks e.g. TOR.  Because this detection is specific to DNS, its coverage score is Minimal resulting in an overall Minimal score.|
|[T1568 - Dynamic Resolution](https://attack.mitre.org/techniques/T1568/)|Detect|Partial|Can identify "random" DNS occurences which can be associated with domain generation algorithm or Fast Flux sub-techniques.  Partial for coverage and accuracy (potential for false positive/benign).<br/>|
|[T1572 - Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)|Detect|Minimal|Can identify protocol misuse/anomalies in DNS.  Because this detection is specific to DNS, its coverage score is Minimal resulting in an overall Minimal score.|
  


### Tag(s)
- [DNS](#11-dns)
- [Network](#17-network)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/defender-for-dns-introduction>
- <https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-dns>
  

  [Back to Table Of Contents](#contents)
## 5. Alerts for Windows Machines


For Windows, Azure Defender integrates with Azure services to monitor and protect your Windows-based machines. Security Center presents the alerts and remediation suggestions from all of these services in an easy-to-use format.

- [Mapping File](AlertsForWindowsMachines.yaml) ([YAML](AlertsForWindowsMachines.yaml))
- [Navigator Layer](layers/AlertsForWindowsMachines.json) ([JSON](layers/AlertsForWindowsMachines.json))

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)|Detect|Minimal|This control provides detection for a minority of this technique's sub-techniques and procedure examples  resulting in a Minimal Coverage score and consequently an overall score of Minimal.  Furthermore, its detection capability relies on detecting the usage of specific tools (e.g. sqldumper.exe) further adversely impacting  its score.|
|[T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)|Detect|Minimal|This control may detect usage of VBScript.Encode and base-64 encoding to obfuscate malicious commands and scripts. The following alerts may be generated: "Detected suspicious execution of VBScript.Encode command", "Detected encoded executable in command line data".|
|[T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)|Detect|Minimal|This control's detection is specific to a minority of this technique's sub-techniques and procedure examples resulting in a Minimal Coverage score and consequently an overall score of Minimal.|
|[T1055 - Process Injection](https://attack.mitre.org/techniques/T1055/)|Detect|Partial|This control's Fileless Attack Detection covers all relevant sub-techniques. Detection is periodic at an unknown rate.|
|[T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)|Detect|Minimal|This control's detection is specific to a minority of this technique's sub-techniques resulting in a Minimal Coverage score and consequently an overall score of Minimal.|
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode executed as a payload in the exploitation of a software vulnerability. Detection is periodic at an unknown rate. The following alerts may be generated: "Fileless attack technique detected", "Fileless attack behavior detected", "Fileless  attack toolkit detected", "Suspicious SVCHOST process executed".|
|[T1070 - Indicator Removal on Host](https://attack.mitre.org/techniques/T1070/)|Detect|Minimal|This control's detection is specific to a minority of this technique's sub-techniques and procedure examples  resulting in a Minimal Coverage score and consequently an overall score of Minimal.|
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Detect|Partial|This control is able to detect some of this technique's sub-techniques resulting in a Partial Coverage score and consequently an overall score of Partial.|
|[T1082 - System Information Discovery](https://attack.mitre.org/techniques/T1082/)|Detect|Minimal|This control may detect local reconnaissance activity specific to using the systeminfo commands. The following alerts may be generated: "Detected possible local reconnaissance activity".|
|[T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)|Detect|Partial|This control provides partial detection for some of this technique's sub-techniques and procedure examples resulting in a Partial Coverage score and consequently an overall score of Partial.|
|[T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)|Detect|Partial|This control may detect usage of malware droppers and creation of suspicious files on the host machine. The following alerts may be generated: "Detected possible execution of malware dropper", "Detected suspicious file creation".|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Detect|Partial|This control provides detection for some of this technique's sub-techniques and procedure examples resulting  in a Partial Coverage score and consequently an overall score of Partial.|
|[T1112 - Modify Registry](https://attack.mitre.org/techniques/T1112/)|Detect|Partial|This control may detect several methods used to modify the registry for purposes of persistence, privilege elevation, and execution. The following alerts may be generated: "Detected change to a registry key that can be abused to bypass UAC", "Detected enabling of the WDigest UseLogonCredential registry key", "Detected suppression of legal notice displayed to users at logon", "Suspicious WindowPosition registry value detected", "Windows registry persistence method detected".|
|[T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)|Detect|Minimal|This control's detection is specific to a minority of this technique's sub-techniques resulting in a Minimal Coverage score and consequently an overall score of Minimal.|
|[T1140 - Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)|Detect|Partial|This control may detect decoding of suspicious files by certutil.exe and may detect the presence of various encoding schemes to obfuscate malicious scripts and commandline arguments. The following alerts may be generated: "Suspicious download using Certutil detected", "Suspicious download using Certutil detected [seen multiple times]", "Detected decoding of an executable using built-in certutil.exe tool".|
|[T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode executed as a payload in the exploitation of a software vulnerability. Detection is periodic at an unknown rate. The following alerts may be generated: "Fileless attack technique detected", "Fileless attack behavior detected", "Fileless  attack toolkit detected", "Suspicious SVCHOST process executed".|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode executed as a payload in the exploitation of a software vulnerability. Detection is periodic at an unknown rate. The following alerts may be generated: "Fileless attack technique detected", "Fileless attack behavior detected", "Fileless  attack toolkit detected", "Suspicious SVCHOST process executed".|
|[T1202 - Indirect Command Execution](https://attack.mitre.org/techniques/T1202/)|Detect|Minimal|This control may detect suspicious use of Pcalua.exe to launch executable code. There are other methods of indirect command execution that this control may not detect. The following alerts may be generated: "Detected suspicious use of Pcalua.exe to launch executable code".|
|[T1203 - Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode executed as a payload in the exploitation of a software vulnerability. Detection is periodic at an unknown rate. The following alerts may be generated: "Fileless attack technique detected", "Fileless attack behavior detected", "Fileless  attack toolkit detected", "Suspicious SVCHOST process executed".|
|[T1204 - User Execution](https://attack.mitre.org/techniques/T1204/)|Detect|Partial|This control provides detection for one of the two sub-techniques of this technique,  Malicious File, resulting in a Partial Coverage score and consequently an overall score of Partial.|
|[T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode executed as a payload in the exploitation of a software vulnerability. Detection is periodic at an unknown rate. The following alerts may be generated: "Fileless attack technique detected", "Fileless attack behavior detected", "Fileless  attack toolkit detected", "Suspicious SVCHOST process executed".|
|[T1211 - Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode executed as a payload in the exploitation of a software vulnerability. Detection is periodic at an unknown rate. The following alerts may be generated: "Fileless attack technique detected", "Fileless attack behavior detected", "Fileless  attack toolkit detected", "Suspicious SVCHOST process executed".|
|[T1212 - Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode executed as a payload in the exploitation of a software vulnerability. Detection is periodic at an unknown rate. The following alerts may be generated: "Fileless attack technique detected", "Fileless attack behavior detected", "Fileless  attack toolkit detected", "Suspicious SVCHOST process executed".|
|[T1218 - Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)|Detect|Minimal|This control's detection is specific to a minority of this technique's sub-techniques resulting in a Minimal Coverage score and consequently an overall score of Minimal.|
|[T1222 - File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222/)|Detect|Minimal|This control provides minimal detection for some of this technique's sub-techniques resulting in an overall score of Minimal.|
|[T1489 - Service Stop](https://attack.mitre.org/techniques/T1489/)|Detect|Minimal|This control may detect when critical services have been disabled through the usage of specifically net.exe. The following alerts may be generated: "Detected the disabling of critical services".|
|[T1543 - Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)|Detect|Minimal|This control's detection is specific to a minority of this technique's sub-techniques resulting in a Minimal Coverage score and consequently an overall score of Minimal.|
|[T1546 - Event Triggered Execution](https://attack.mitre.org/techniques/T1546/)|Detect|Minimal|This control's detection is specific to a minority of this technique's sub-techniques resulting in a Minimal Coverage score and consequently an overall score of Minimal.|
|[T1547 - Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)|Detect|Minimal|This control's detection is specific to a minority of this technique's sub-techniques resulting in a Minimal Coverage score and consequently an overall score of Minimal.|
|[T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)|Detect|Minimal|The only sub-technique scored (Bypass User Account Control) is the only one relevant to Windows.|
|[T1558 - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/)|Detect|Minimal|This control's detection is specific to a minority of this technique's sub-techniques resulting in a Minimal Coverage score and consequently an overall score of Minimal.|
|[T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/)|Detect|Minimal|This control's detection is specific to a minority of this technique's sub-techniques resulting in a Minimal Coverage score and consequently an overall score of Minimal.|
|[T1563 - Remote Service Session Hijacking](https://attack.mitre.org/techniques/T1563/)|Detect|Partial|This control provides partial detection for some of this technique's sub-techniques  resulting in a Partial Coverage score and consequently an overall score of Partial.|
|[T1564 - Hide Artifacts](https://attack.mitre.org/techniques/T1564/)|Detect|Minimal|This control's detection is specific to a minority of this technique's sub-techniques resulting in a Minimal Coverage score and consequently an overall score of Minimal.|
  


### Tag(s)
- [Azure Defender](#4-azure-defender)
- [Azure Defender for Servers](#6-azure-defender-for-servers)
- [Windows](#20-windows)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/defender-for-servers-introduction>
- <https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-windows>
  

  [Back to Table Of Contents](#contents)
## 6. Azure AD Identity Protection


Identity Protection is a tool that allows organizations to accomplish three key tasks:
Automate the detection and remediation of identity-based risks.
Investigate risks using data in the portal.
Export risk detection data to third-party utilities for further analysis.


- [Mapping File](IdentityProtection.yaml) ([YAML](IdentityProtection.yaml))
- [Navigator Layer](layers/IdentityProtection.json) ([JSON](layers/IdentityProtection.json))

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Detect|Partial|This control provides partial detection for some of this technique's sub-techniques and procedure examples resulting in an overall Partial detection score.|
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Respond|Partial|This control provides a response capability that accompanies its detection capability that can contain and eradicate the impact of this technique.  Because this capability varies between containment (federated accounts) and eradication (cloud accounts) and is only able to respond to some of this technique's sub-techniques, it has been scored as Partial.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Detect|Minimal|This control provides Minimal detection for one of this technique's sub-techniques while not providing any detection for the remaining, resulting in a Minimal score.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Respond|Minimal|Provides significant response capabilities for one of this technique's sub-techniques (Password Spray).  Due to this capability being specific to one of its sub-techniques and not its remaining sub-techniques, the coverage score is Minimal resulting in an overall Minimal score.|
|[T1606 - Forge Web Credentials](https://attack.mitre.org/techniques/T1606/)|Detect|Partial|This control can be effective at detecting forged web credentials because it uses environmental properties (e.g. IP address, device info, etc.) to detect risky users and sign-ins even when valid credentials are utilized.  It provides partial coverage of this technique's sub-techniques and therefore has been assessed a Partial score.|
|[T1606 - Forge Web Credentials](https://attack.mitre.org/techniques/T1606/)|Respond|Partial|Provides Significant response capabilities for one of this technique's sub-techniques (SAML tokens).|
  


### Tag(s)
- [Azure Active Directory](#3-azure-active-directory)
- [Credentials](#10-credentials)
- [Identity](#13-identity)
- [Microsoft 365 Defender](#16-microsoft-365-defender)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-investigate-risk>
- <https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/overview-identity-protection>
- <https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/concept-identity-protection-risks>
- <https://techcommunity.microsoft.com/t5/azure-active-directory-identity/azuread-identity-protection-adds-support-for-federated/ba-p/244328>
  

  [Back to Table Of Contents](#contents)
## 7. Azure AD Identity Secure Score


The identity secure score is a percentage that functions as an indicator for how aligned you are with Microsoft's best practice recommendations for security. Each improvement action in Identity Secure Score is tailored to your specific configuration.  The score helps you to:  Objectively measure your identity security posture, plan identity security improvements, and review the success of your improvements.  
Every 48 hours, Azure looks at your security configuration and compares your settings with the recommended best practices. Based on the outcome of this evaluation, a new score is calculated for your directory.

- [Mapping File](AzureADIdentitySecureScore.yaml) ([YAML](AzureADIdentitySecureScore.yaml))
- [Navigator Layer](layers/AzureADIdentitySecureScore.json) ([JSON](layers/AzureADIdentitySecureScore.json))

### Mapping Comments


This control was mapped to (sub-)techniques based on the Security Score improvement actions listed in a sample Azure AD tenant that we provisioned.  We were unable to find a comprehensive list of the security checks made by the control listed in its documentation.  We did note that there were some improvement actions listed that our tenant received the max score, leading us to believe that the actions listed were the complete list of checks and not just those that were outstanding for our tenant.
The following improvement actions were analyzed:
Require MFA for administrative roles, Designate more than one global admin,  Do not allow users to grant consent to unmanaged applications, Use limited administrative roles, Do not expire passwords, Enable policy to block legacy authentication  Turn on sign-in risk policy, Turn on user risk policy, Ensure all users can complete multi-factor authentication for secure access, Enable self-service password reset, Resolve unsecure account attributes, Reduce lateral movement path risk to sensitive entities,  Set a honeytoken account, Stop clear text credentials exposure, Install Defender for Identity Sensor on all Domain Controllers,  Disable Print spooler service on domain controllers, Configure VPN integration,  Configure Microsoft Defender for Endpoint Integration (*excluded, would increase the scope, see mapping for Microsoft  Defender for Endpoint), Stop legacy protocols communication, Stop weak cipher usage,  Remove dormant accounts from sensitive groups, Protect and manage local admin passwords with Microsoft LAPS,  Remove unsecure SID history attributes from entities, Fix Advanced Audit Policy issues, Modify unsecure Kerberos  delegations to prevent impersonation. 
All scores were capped at Partial since this control provides recommendations rather than applying/enforcing the recommended actions.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)|Protect|Minimal|This control's "Stop clear text credentials exposure" provides a recommendation to run the "Entities exposing credentials in clear text" assessment that monitors your traffic for any entities exposing credentials in clear text (via LDAP simple-bind).  This assessment seems specific to LDAP simple-binds and coupled with the fact that it is a recommendation and is not enforced, results in a Minimal score.<br/>|
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Detect|Minimal|This control provides recommendations that can lead to the detection of the malicious usage of valid cloud accounts but does not provide recommendations for the remaining sub-techniques Additionally, it provides limited detection for this technique's procedure examples. Consequently, its overall detection coverage score is minimal.|
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Protect|Minimal|This control provides recommendations that can lead to protecting against the malicious usage of valid cloud accounts but does not provide recommendations for the remaining sub-techniques Additionally, it provides limited protection for this technique's procedure examples. Consequently, its overall protection coverage score is minimal.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Protect|Partial|The MFA recommendation provides significant protection against password compromises, but because this is a recommendation and doesn't actually enforce MFA, the assessed score is capped at Partial.|
|[T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)|Detect|Partial|This control's "Configure VPN Integration" recommendation can lead to detecting abnormal VPN connections that may be indicative of an attack.  Although this control provides a recommendation that is limited to a specific external remote service type of VPN, most of this technique's procedure examples are VPN related resulting in a Partial overall score.|
|[T1134 - Access Token Manipulation](https://attack.mitre.org/techniques/T1134/)|Detect|Minimal|This control provides a recommendation that can lead to detecting one of this technique's sub-techniques while not providing recommendations relevant to its procedure examples nor its remaining sub-techniques.  It is subsequently scored as Minimal.|
|[T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)|Protect|Partial|This control's "Do not allow users to grant consent to unmanaged applications" recommendation can protect against an adversary constructing a malicious application designed to be granted access to resources with the target user's OAuth token by ensuring users can not be fooled into granting consent to the application. <br/>Due to this being a recommendation, its score is capped at Partial.|
|[T1531 - Account Access Removal](https://attack.mitre.org/techniques/T1531/)|Protect|Partial|This control's "Designate more than one global admin" can enable recovery from an adversary locking a global administrator account (deleted, locked, or manipulated (ex: changed credentials)).  Due to this being a recommendation, its score is capped as Partial.|
|[T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)|Protect|Partial|This control provides recommendations that lead to protections for some of the sub-techniques of this technique.  Due to it only providing a recommendation, its score has been capped at Partial.|
|[T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)|Protect|Minimal|This control's "Resolve unsecure account attributes" provides recommendations that can lead to strengthening how accounts are stored in Active Directory.  This control provides recommendations specific to a few types of unsecured credentials (reversible and weakly encrypted credentials) while not providing recommendations for any other, resulting in a Minimal score.|
|[T1558 - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/)|Protect|Partial|This control provides recommendations that lead to protections for some of the sub-techniques of this technique and therefore its overall protection coverage is Partial.|
|[T1606 - Forge Web Credentials](https://attack.mitre.org/techniques/T1606/)|Detect|Partial|This control's "Turn on sign-in risk policy" and "Turn on user risk policy" recommendations recommend the usage of Azure AD Identity Protection which can detect one of the sub-techniques of this technique.  This is a recommendation and therefore the score is capped at Partial.|
  


### Tag(s)
- [Azure Active Directory](#3-azure-active-directory)
- [Credentials](#10-credentials)
- [Identity](#13-identity)
- [MFA](#15-mfa)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/identity-secure-score>
- <https://techcommunity.microsoft.com/t5/azure-active-directory-identity/new-tools-to-block-legacy-authentication-in-your-organization/ba-p/1225302#>
- <https://docs.microsoft.com/en-us/defender-for-identity/cas-isp-unsecure-account-attributes>
- <https://techcommunity.microsoft.com/t5/microsoft-defender-for-identity/new-identity-security-posture-assessments-riskiest-lmps-and/m-p/1491675>
  

  [Back to Table Of Contents](#contents)
## 8. Azure AD Multi-Factor Authentication


Multi-factor authentication is a process where a user is prompted during the sign-in process for an additional form of identification, such as to enter a code on their cellphone or to provide a fingerprint scan.
If you only use a password to authenticate a user, it leaves an insecure vector for attack. If  the password is weak or has been exposed elsewhere, is it really the user signing in with the  username and password, or is it an attacker? When you require a second form of authentication, security is increased as this additional factor isn't something that's easy for an attacker to  obtain or duplicate.

- [Mapping File](AzureADMultiFactorAuthentication.yaml) ([YAML](AzureADMultiFactorAuthentication.yaml))
- [Navigator Layer](layers/AzureADMultiFactorAuthentication.json) ([JSON](layers/AzureADMultiFactorAuthentication.json))

### Mapping Comments


Note that MFA that is triggered in response to privileged operations (such as assigning a user a privileged role) are considered functionality of the Azure AD Privileged Identity Management control.  Consult the mapping for this control for the ATT&CK (sub-)techniques it maps to.  This mapping specifically deals with MFA when it is enabled as a security default.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Protect|Minimal|This control only protects cloud accounts and therefore its overall protection coverage is Minimal.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Protect|Significant|MFA provides significant protection against password compromises, requiring the adversary to complete an additional authentication method before their access is permitted.|
  


### Tag(s)
- [Azure Active Directory](#3-azure-active-directory)
- [Azure Security Center Recommendation](#8-azure-security-center-recommendation)
- [Credentials](#10-credentials)
- [Identity](#13-identity)
- [MFA](#15-mfa)
- [Passwords](#18-passwords)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks>
  

  [Back to Table Of Contents](#contents)
## 9. Azure AD Password Policy


A password policy is applied to all user accounts that are created and managed directly in Azure Active Directory (AD). Some of these password policy settings can't be modified, though you can configure custom banned passwords for Azure AD password protection or account lockout parameters.

- [Mapping File](AzureADPasswordPolicy.yaml) ([YAML](AzureADPasswordPolicy.yaml))
- [Navigator Layer](layers/AzureADPasswordPolicy.json) ([JSON](layers/AzureADPasswordPolicy.json))

### Mapping Comments


Most scores have been assessed as Partial because this control increases the strength of user passwords thereby reducing the likelihood of a successful brute force attack.  But given sufficient resources, an adversary may still successfully execute the attack vectors included  in this mapping.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Protect|Partial|This control provides partial protection for most of this technique's sub-techniques and therefore has been scored as Partial.|
  


### Tag(s)
- [Azure Active Directory](#3-azure-active-directory)
- [Credentials](#10-credentials)
- [Identity](#13-identity)
- [Passwords](#18-passwords)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-sspr-policy#password-policies-that-only-apply-to-cloud-user-accounts>
  

  [Back to Table Of Contents](#contents)
## 10. Azure AD Privileged Identity Management


Privileged Identity Management (PIM) is a service in Azure Active Directory (Azure AD) that enables you to manage, control, and monitor access to important resources in your organization. These resources include resources in Azure AD, Azure, and other Microsoft Online Services such as Microsoft 365 or Microsoft Intune.

- [Mapping File](PrivilegedIdentityManagement.yaml) ([YAML](PrivilegedIdentityManagement.yaml))
- [Navigator Layer](layers/PrivilegedIdentityManagement.json) ([JSON](layers/PrivilegedIdentityManagement.json))

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Protect|Minimal|This control only provides protection for one of this technique's sub-techniques while not providing any protection for the remaining and therefore its coverage score is Minimal, resulting in a Minimal score.|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Detect|Minimal|This control only provides detection for one of this technique's sub-techniques while not providing any detection for the remaining and therefore its coverage score is Minimal, resulting in a Minimal score.|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Protect|Partial|This control provides significant protection for some of this technique's sub-techniques while not providing any protection for others, resulting in a Partial score.|
|[T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)|Protect|Minimal|This control only provides protection for one of this technique's sub-techniques while not providing any detection for the remaining and therefore its coverage score is Minimal, resulting in a Minimal score.|
  


### Tag(s)
- [Azure Active Directory](#3-azure-active-directory)
- [Identity](#13-identity)
- [MFA](#15-mfa)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure>
  

  [Back to Table Of Contents](#contents)
## 11. Azure Active Directory Password Protection


Azure AD Password Protection detects and blocks known weak passwords and their variants,  and can also block additional weak terms that are specific to your organization. Azure AD Password Protection provides a global banned password list that is automatically applied to all users in an Azure AD tenant.  The Azure AD Identity Protection team constantly analyzes Azure AD security telemetry data looking for commonly used weak or compromised passwords.  When weak terms are found, they're added to the global banned password list. To support your own business and security needs, you can define entries in a custom banned  password list. When users change or reset their passwords, these banned  password lists are checked to enforce the use of strong passwords.


- [Mapping File](AzureADPasswordProtection.yaml) ([YAML](AzureADPasswordProtection.yaml))
- [Navigator Layer](layers/AzureADPasswordProtection.json) ([JSON](layers/AzureADPasswordProtection.json))

### Mapping Comments


All scores have been assessed as Partial because this control increases the strength of user passwords thereby reducing the likelihood of a successful brute force attack.  Due to the fact that a user's password is not checked  against the banned list of passwords unless the user changes or resets their  password (which is an infrequent event), there is still ample opportunity  for attackers to utilize this technique to gain access. This is what prevented the score from being elevated to Significant.
  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Protect|Partial||
  


### Tag(s)
- [Azure Active Directory](#3-azure-active-directory)
- [Credentials](#10-credentials)
- [Identity](#13-identity)
- [Passwords](#18-passwords)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-password-ban-bad>
  

  [Back to Table Of Contents](#contents)
## 12. Azure Alerts for Network Layer


Security Center network-layer analytics are based on sample IPFIX data, which are packet headers collected by Azure core routers. Based on this data feed, Security Center uses machine learning models to identify and flag malicious traffic activities. Security Center also uses the Microsoft Threat Intelligence database to enrich IP addresses.

- [Mapping File](AlertsNetworkLayer.yaml) ([YAML](AlertsNetworkLayer.yaml))
- [Navigator Layer](layers/AlertsNetworkLayer.json) ([JSON](layers/AlertsNetworkLayer.json))

### Mapping Comments


Associated with the Azure Security Center.
The alerts can pick up outbound Denial of Service (DOS) attacks, though that's not an ATT&CK technique  per se (description oriented towards inbound DOS), also is a form of resource hijacking (though not in ATT&CK description, which is oriented towards cryptomining).  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)|Detect|Minimal|This control can identify connections to known malicious sites. Scored minimal since the malicious sites must be on block list.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Detect|Significant|This control can identify multiple connection attempts by external IPs, which may be indicative of Brute Force attempts, though not T1110.002, which is performed offline. It provides significant detection from most of this technique's sub-techniques and  procedure examples resulting in an overall score of Significant.|
|[T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)|Detect|Partial|This control can potentially identify malicious use of remote services via alerts such as "Suspicious incoming RDP network activity" and "Suspicious Incoming SSH network activity".|
  


### Tag(s)
- [Analytics](#2-analytics)
- [Azure Security Center](#7-azure-security-center)
- [Network](#17-network)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-azurenetlayer>
  

  [Back to Table Of Contents](#contents)
## 13. Azure Automation Update Management


"Use Azure Automation Update Management or a third-party solution to ensure that the most recent security updates are installed on your Windows and Linux VMs. "

- [Mapping File](AzureAutomationUpdateMGT.yaml) ([YAML](AzureAutomationUpdateMGT.yaml))
- [Navigator Layer](layers/AzureAutomationUpdateMGT.json) ([JSON](layers/AzureAutomationUpdateMGT.json))

### Mapping Comments


This control generally applies to techniques that leverage vulnerabilities in unpatched software, which can be specific techniques  sub-techniques.   


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Protect|Significant|This control provides significant coverage of methods that leverage vulnerabilities in unpatched software since it enables automated updates of software and rapid configuration change management|
|[T1072 - Software Deployment Tools](https://attack.mitre.org/techniques/T1072/)|Protect|Partial|This control provides partial coverage of attacks that leverage software flaws in unpatched deployment tools since it enables automated updates of software and rapid configuration change management.|
|[T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)|Protect|Partial|This control protects against a subset of drive-by methods that leverage unpatched client software since it enables automated updates of software and rapid configuration change management|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Protect|Partial|This control provides partial coverage for techniques that exploit vulnerabilities in (common) unpatched software since it enables automated updates of software and rapid configuration change management.|
|[T1195 - Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)|Protect|Partial|This control provides coverage of some aspects of software supply chain compromise since it enables automated updates of software and rapid configuration change management.|
|[T1203 - Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)|Protect|Significant|This control provides significant coverage for Exploitation for client execution methods that leverage unpatched vulnerabilities since it enables automated updates of software and rapid configuration change management.|
|[T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)|Protect|Significant|This control provides significant coverage of techniques that leverage vulnerabilities in unpatched remote services since it enables automated updates of software and rapid configuration change management.|
|[T1211 - Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211/)|Protect|Significant|This control provides significant coverage of defensive evasion methods that exploit unpatched vulnerabilities in software/systems since it enables automated updates of software and rapid configuration change management.|
|[T1212 - Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212/)|Protect|Significant|This control provides significant coverage of credential access techniques that leverage unpatched software vulnerabilities since it enables automated updates of software and rapid configuration change management.|
|[T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)|Protect|Partial|This control provides protection against the subset of Denial of Service (DOS) attacks that leverage system/application vulnerabilities as opposed to volumetric attacks since it enables automated updates of software and rapid configuration change management.|
|[T1554 - Compromise Client Software Binary](https://attack.mitre.org/techniques/T1554/)|Protect|Partial|This control provides partial protection against compromised client software binaries since it can provide a baseline to compare with potentially compromised/modified software binaries.|
  


### Tag(s)
- [Linux](#14-linux)
- [Windows](#20-windows)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/automation/update-management/overview>
  

  [Back to Table Of Contents](#contents)
## 14. Azure Backup


"The Azure Backup service provides simple, secure, and cost-effective solutions to back up your data and recover it from the Microsoft Azure cloud."

- [Mapping File](AzureBackup.yaml) ([YAML](AzureBackup.yaml))
- [Navigator Layer](layers/AzureBackup.json) ([JSON](layers/AzureBackup.json))

### Mapping Comments


Azure Backup service provides defense against destruction/manipulation of data at rest. Scoring as "Significant" since it is an essential practice against data destruction et al, and can eradicate the threat event by restoring from backup.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1485 - Data Destruction](https://attack.mitre.org/techniques/T1485/)|Respond|Significant|Data backups provide a significant response to data destruction by enabling the restoration of data from backup.|
|[T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)|Respond|Significant|Data backups provide a significant response to data encryption/ransomware by enabling the restoration of data from backup.|
|[T1491 - Defacement](https://attack.mitre.org/techniques/T1491/)|Respond|Significant|Data backups provide a significant response to data defacement attacks by enabling the restoration of data from backup.|
|[T1561 - Disk Wipe](https://attack.mitre.org/techniques/T1561/)|Respond|Significant|Data backups provide a significant response to disk wipe attacks by enabling the restoration of data from backup.|
  


### Tag(s)
- [Azure Security Center Recommendation](#8-azure-security-center-recommendation)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/backup/backup-overview>
  

  [Back to Table Of Contents](#contents)
## 15. Azure DDOS Protection Standard


Azure DDoS Protection Standard, combined with application design best practices, provides enhanced DDoS mitigation features to defend against DDoS attacks. 
It is automatically tuned to help protect your specific Azure resources in a virtual network.

- [Mapping File](AzureDDOS.yaml) ([YAML](AzureDDOS.yaml))
- [Navigator Layer](layers/AzureDDOS.json) ([JSON](layers/AzureDDOS.json))

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1498 - Network Denial of Service](https://attack.mitre.org/techniques/T1498/)|Protect|Significant|Designed to address multiple DDOS techniques including volumetric attacks.|
|[T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)|Protect|Significant|Protects against volumetric and protocol DOS, though not application.|
  


### Tag(s)
- [Azure Security Center Recommendation](#8-azure-security-center-recommendation)
- [Network](#17-network)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview>
  

  [Back to Table Of Contents](#contents)
## 16. Azure DNS Alias Records


Azure DNS alias records are qualifications on a DNS record set. They can reference other Azure resources from within your DNS zone.   For example, you can create an alias record set that references an Azure public IP address instead of an A record. Your alias record set points to an Azure public IP address service instance dynamically. As a result, the alias record set seamlessly updates itself during DNS resolution.


- [Mapping File](AzureDNSAliasRecords.yaml) ([YAML](AzureDNSAliasRecords.yaml))
- [Navigator Layer](layers/AzureDNSAliasRecords.json) ([JSON](layers/AzureDNSAliasRecords.json))

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1584 - Compromise Infrastructure](https://attack.mitre.org/techniques/T1584/)|Protect|Minimal|This control only provides protection for one of this technique's sub-techniques while not providing any protection for the remaining and therefore its coverage score factor is Minimal, resulting in a Minimal score.|
  


### Tag(s)
- [DNS](#11-dns)
- [Network](#17-network)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/dns/dns-alias#prevent-dangling-dns-records>
  

  [Back to Table Of Contents](#contents)
## 17. Azure DNS Analytics


"DNS Analytics helps you to: identify clients that try to resolve malicious domain names, identify stale resource records, identify frequently queried domain names and talkative DNS clients,  view request load on DNS servers, and view dynamic DNS registration failures.
The solution collects, analyzes, and correlates Windows DNS analytic and audit logs and other related data from your DNS servers."

- [Mapping File](AzureDNSAnalytics.yaml) ([YAML](AzureDNSAnalytics.yaml))
- [Navigator Layer](layers/AzureDNSAnalytics.json) ([JSON](layers/AzureDNSAnalytics.json))

### Mapping Comments


The temporal score for this control on most of the techniques and subtechnique is minimal, since it does not provide specific analytics itself (though can be used to provide data to other analytics after the fact. "The event-related data is collected near real time from the analytic and audit logs provided by enhanced DNS logging and diagnostics in Windows Server 2012 R2.".  Inventory-related data is uploaded every 48 hours.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)|Detect|Minimal|This control can potentially be used to forensically identify exfiltration via a DNS-based C2 channel.|
|[T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)|Detect|Minimal|This control can identify anomalous / high talker DNS clients, possibly related to exfil via DNS|
|[T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)|Detect|Minimal|This control can be used forensically to identify clients that communicated with identified C2 hosts via DNS.|
|[T1566 - Phishing](https://attack.mitre.org/techniques/T1566/)|Detect|Minimal|This control can be used forensically to identify DNS queries to known malicious sites, which may be evidence of phishing.|
|[T1568 - Dynamic Resolution](https://attack.mitre.org/techniques/T1568/)|Detect|Minimal|This control can be used for after-the-fact analysis of potential fast-flux DNS C2|
  


### Tag(s)
- [DNS](#11-dns)
- [Network](#17-network)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/azure-monitor/insights/dns-analytics>
  

  [Back to Table Of Contents](#contents)
## 18. Azure Dedicated HSM


"Azure Dedicated HSM is an Azure service that provides cryptographic key storage in Azure ... for customers who require FIPS 140-2 Level 3-validated devices and complete and exclusive control of the HSM appliance."

- [Mapping File](AzureDedicatedHSM.yaml) ([YAML](AzureDedicatedHSM.yaml))
- [Navigator Layer](layers/AzureDedicatedHSM.json) ([JSON](layers/AzureDedicatedHSM.json))

### Mapping Comments


Note there is also a Managed HSM service.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)|Protect|Minimal|This control's protection is specific to a minority of this technique's sub-techniques and procedure examples resulting in a Minimal Coverage score and consequently an overall score of Minimal.|
|[T1553 - Subvert Trust Controls](https://attack.mitre.org/techniques/T1553/)|Protect|Partial|Provides protection against sub-techniques involved with stealing credentials / certificates / keys from the organization.|
|[T1588 - Obtain Capabilities](https://attack.mitre.org/techniques/T1588/)|Protect|Partial|Provides protection against sub-techniques involved with stealing credentials / certificates / keys from the organization.|
  


### Tag(s)
- [Credentials](#10-credentials)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/dedicated-hsm/overview>
- <https://docs.microsoft.com/en-us/azure/key-vault/managed-hsm/>
  

  [Back to Table Of Contents](#contents)
## 19. Azure Defender for App Service


Azure Defender for App Service monitors VM instances and their management interfaces, App Service apps and their requests/responses, and App Service internal logs to detect threats to App Service resources and provide security recommendations to mitigate them.

- [Mapping File](AzureDefenderForAppService.yaml) ([YAML](AzureDefenderForAppService.yaml))
- [Navigator Layer](layers/AzureDefenderForAppService.json) ([JSON](layers/AzureDefenderForAppService.json))

### Mapping Comments


The AppServices_KnownCredentialAccessTools alert is used to detect suspicious processes associated with credential theft. This is clearly linked to the Credential Access tactic, but does not clearly detect any specific technique or set of techniques, so it has been omitted from this mapping.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)|Detect|Minimal|This control only addresses a minority of this technique's procedure examples and one  of its sub-techniques resulting in an overall Minimal score.|
|[T1005 - Data from Local System](https://attack.mitre.org/techniques/T1005/)|Detect|Minimal|This control analyzes host data to detect execution of known malicious PowerShell PowerSploit cmdlets. This covers execution of this technique via the Exfiltration modules on Windows, but does not address other procedures or platforms, and temporal factor is unknown, resulting in a Minimal score.|
|[T1012 - Query Registry](https://attack.mitre.org/techniques/T1012/)|Detect|Minimal|This control analyzes host data to detect execution of known malicious PowerShell PowerSploit cmdlets. This covers execution of this technique via the Privesc-PowerUp modules, but does not address other procedures, and temporal factor is unknown, resulting in a Minimal score.|
|[T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)|Detect|Minimal|This control only covers one platform and procedure for one of this technique's sub-techniques, resulting in a Minimal score.|
|[T1036 - Masquerading](https://attack.mitre.org/techniques/T1036/)|Detect|Minimal|This control only addresses a minority of this technique's procedure examples and one of its sub-techniques resulting in an overall Minimal score.|
|[T1047 - Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)|Detect|Minimal|This control analyzes host data to detect execution of known malicious PowerShell PowerSploit cmdlets. This covers execution of this technique via the Invoke-WmiCommand module, but does not address other procedures, and temporal factor is unknown, resulting in a Minimal score.|
|[T1053 - Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)|Detect|Minimal|This control does not address this technique's procedure examples and only one of its sub-techniques resulting in an overall Minimal score.|
|[T1055 - Process Injection](https://attack.mitre.org/techniques/T1055/)|Detect|Partial|This control's Fileless Attack Detection covers all relevant sub-techniques. The control also specifically detects process hollowing, executable image injection, and threads started in a dynamically allocated code segment. Detection is periodic at an unknown rate.|
|[T1056 - Input Capture](https://attack.mitre.org/techniques/T1056/)|Detect|Minimal|This control only covers one platform and procedure for one of this technique's sub-techniques, resulting in a Minimal score.|
|[T1057 - Process Discovery](https://attack.mitre.org/techniques/T1057/)|Detect|Minimal|This control analyzes host data to detect execution of known malicious PowerShell PowerSploit cmdlets. This covers execution of this technique via the Get-ProcessTokenPrivilege PowerUp module on Windows, but does not address other procedures or platforms, and temporal factor is unknown, resulting in a Minimal score.|
|[T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)|Detect|Minimal|This control provides minimal detection for this technique's procedure examples and only two of its sub-techniques (only certain specific sub-technique behaviors), resulting in a Minimal score.|
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode executed as a payload in the exploitation of a software vulnerability. Detection is periodic at an unknown rate.|
|[T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)|Detect|Minimal|This control only covers one platform and procedure for one of this technique's sub-techniques, and minimal coverage of its procedure examples resulting in a Minimal overall score.|
|[T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)|Detect|Partial|This control detects binary downloads via certutil, monitors for FTP access from IP addresses found in threat intelligence, monitors for references to suspicious domain names and file downloads from known malware sources, and monitors processes for downloads from raw-data websites like Pastebin. Temporal factor is unknown.|
|[T1113 - Screen Capture](https://attack.mitre.org/techniques/T1113/)|Detect|Minimal|This control analyzes host data to detect execution of known malicious PowerShell PowerSploit cmdlets. This covers execution of this technique via the Get-TimedScreenshot module on Windows, but does not address other procedures or platforms, and temporal factor is unknown, resulting in a Minimal score.|
|[T1123 - Audio Capture](https://attack.mitre.org/techniques/T1123/)|Detect|Minimal|This control analyzes host data to detect execution of known malicious PowerShell PowerSploit cmdlets. This covers execution of this technique via the Get-MicrophoneAudio module on Windows, but does not address other procedures or platforms, and temporal factor is unknown, resulting in a Minimal score.|
|[T1134 - Access Token Manipulation](https://attack.mitre.org/techniques/T1134/)|Detect|Minimal|This control analyzes host data to detect execution of known malicious PowerShell PowerSploit cmdlets. This covers execution of this technique via the Invoke-TokenManipulation module on Windows, but does not address other procedures or platforms, and temporal factor is unknown, resulting in a Minimal score.|
|[T1140 - Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)|Detect|Partial|This control analyzes host data to detect base-64 encoded executables within command sequences. It also monitors for use of certutil to decode executables. Temporal factor is unknown.|
|[T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode injected into browser or other process memory as part of a drive-by attack. Detection is periodic at an unknown rate.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode injected to exploit a vulnerability in a public-facing application. Detection is periodic at an unknown rate.|
|[T1203 - Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode executed as a payload in the exploitation of a software vulnerability. Detection is periodic at an unknown rate.|
|[T1204 - User Execution](https://attack.mitre.org/techniques/T1204/)|Detect|Minimal|This control only provides meaningful detection for one of the technique's two sub-techniques, and the temporal factor is unknown, resulting in a score of Minimal.|
|[T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode injected to exploit a vulnerability in an exposed service. Detection is periodic at an unknown rate.|
|[T1211 - Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode executed as a payload in the exploitation of a software vulnerability. Detection is periodic at an unknown rate.|
|[T1212 - Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode executed as a payload in the exploitation of a software vulnerability. Detection is periodic at an unknown rate.|
|[T1482 - Domain Trust Discovery](https://attack.mitre.org/techniques/T1482/)|Detect|Minimal|This control analyzes host data to detect execution of known malicious PowerShell PowerSploit cmdlets. This covers execution of this technique via the Get-NetDomainTrust and Get-NetForestTrust modules, but does not address other procedures, and temporal factor is unknown, resulting in a Minimal score.|
|[T1496 - Resource Hijacking](https://attack.mitre.org/techniques/T1496/)|Detect|Partial|This control detects file downloads associated with digital currency mining as well as host data related to process and command execution associated with mining. It also includes fileless attack detection, which specifically targets crypto mining activity. Temporal factor is unknown.|
|[T1543 - Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)|Detect|Minimal|This control only addresses a minority of this technique's procedure examples and one of its sub-techniques resulting in an overall Minimal score.|
|[T1547 - Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)|Detect|Minimal|This control only covers one platform and procedure for two of this technique's many sub-techniques, resulting in a Minimal score.|
|[T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)|Detect|Minimal|This control does not address this technique's procedure example and provides minimal detection for some of its sub-techniques resulting in an overall Minimal score.|
|[T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)|Detect|Minimal|This control analyzes host data to detect execution of known malicious PowerShell PowerSploit cmdlets. This covers execution of this technique via the PowerSploit Exfiltration modules on Windows, but does not address other procedures or platforms, and temporal factor is unknown, resulting in a Minimal score.|
|[T1558 - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/)|Detect|Minimal|This control only covers one procedure for one of this technique's sub-techniques, resulting in an  overall Minimal score.|
|[T1559 - Inter-Process Communication](https://attack.mitre.org/techniques/T1559/)|Detect|Partial|This control's Fileless Attack Detection covers the command execution aspects of both of this technique's sub-techniques. Detection is periodic at an unknown rate.|
|[T1566 - Phishing](https://attack.mitre.org/techniques/T1566/)|Protect|Minimal|This control only provides (minimal) protection for one of the technique's sub-techniques, resulting in a Minimal score.|
|[T1574 - Hijack Execution Flow](https://attack.mitre.org/techniques/T1574/)|Detect|Minimal|This control only addresses a minority of this technique's procedure examples and provides  minimal detection of some of its sub-techniques resulting in an overall Minimal score.|
|[T1584 - Compromise Infrastructure](https://attack.mitre.org/techniques/T1584/)|Protect|Minimal|This control only addresses one of the technique's sub-techniques, resulting in a score of Minimal.|
|[T1594 - Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594/)|Detect|Partial|This control monitors for accesses of potentially sensitive web pages from source IP addresses whose access pattern resembles that of a web scanner or have not been logged before. Temporal factor is unknown.|
|[T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)|Detect|Minimal|This control only provides detection for one of its two sub-techniques, resulting in an overall Minimal score.|
  


### Tag(s)
- [Azure Defender](#4-azure-defender)
- [Azure Security Center](#7-azure-security-center)
- [Azure Security Center Recommendation](#8-azure-security-center-recommendation)
- [Linux](#14-linux)
- [Windows](#20-windows)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/alerts-reference>
- <https://docs.microsoft.com/en-us/azure/security-center/defender-for-app-service-introduction>
- <https://azure.microsoft.com/en-us/services/app-service/>
- <https://docs.microsoft.com/en-us/azure/security-center/defender-for-servers-introduction>
  

  [Back to Table Of Contents](#contents)
## 20. Azure Defender for Container Registries


Azure Defender for container registries includes a vulnerability scanner to scan the images in your Azure Resource Manager-based Azure Container Registry registries and provide deeper visibility into your images' vulnerabilities. The integrated scanner is powered by Qualys. Azure Container Registry is a managed, private Docker registry service based on the open-source Docker Registry 2.0.

- [Mapping File](AzureDefenderForContainerRegistries.yaml) ([YAML](AzureDefenderForContainerRegistries.yaml))
- [Navigator Layer](layers/AzureDefenderForContainerRegistries.json) ([JSON](layers/AzureDefenderForContainerRegistries.json))

### Mapping Comments


This mapping file covers Docker container registries security features along with the Azure Defender for Container Registries scanner. The scanning capability of the control is only available for Linux images in registries accessible from the public internet with shell access which limits the general applicability.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Protect|Minimal|This control may provide recommendations to avoid privileged containers and running containers as root.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Protect|Minimal|This control may provide provide information about vulnerabilities within container images. The limited scope of containers and registries that are applicable to this control contribute to the lower score.|
|[T1525 - Implant Container Image](https://attack.mitre.org/techniques/T1525/)|Detect|Partial|This control may scan and alert on import or creation of container images with known vulnerabilities or a possible expanded surface area for exploitation.|
|[T1525 - Implant Container Image](https://attack.mitre.org/techniques/T1525/)|Protect|Partial|This control may prevent adversaries from implanting malicious container images through fine grained permissions and use of container image tag signing. Image tag signing allows for verifiable container images that have been signed with legitimate keys.|
  


### Tag(s)
- [Azure Defender](#4-azure-defender)
- [Azure Security Center Recommendation](#8-azure-security-center-recommendation)
- [Containers](#9-containers)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/defender-for-container-registries-introduction>
- <https://docs.microsoft.com/en-us/azure/container-registry/container-registry-intro>
  

  [Back to Table Of Contents](#contents)
## 21. Azure Defender for Key Vault


Azure Defender detects unusual and potentially harmful attempts to access or exploit Key Vault accounts. When anomalous activities occur, Azure Defender shows alerts and optionally sends them via email to relevant members of your organization. These alerts include the details of the suspicious activity and recommendations on how to investigate and remediate threats.

- [Mapping File](AzureDefenderForKeyVault.yaml) ([YAML](AzureDefenderForKeyVault.yaml))
- [Navigator Layer](layers/AzureDefenderForKeyVault.json) ([JSON](layers/AzureDefenderForKeyVault.json))

### Mapping Comments


This control provides alerts for suspicious activity for Azure Key Vault. Documentation has been offered on how to respond to alerts but no specific tool or feature is offered for response.   


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)|Detect|Partial|This control may detect suspicious secret access from Azure key vaults. This does not apply to any sub-techniques under T1555 - Credentials from Password Stores but Azure Key Vault can be treated as a store for passwords, keys, and certificates. The coverage of this control could be deemed high for cloud credential and secret storage within Key Vault but is not applicable to traditional password stores, such as password managers, keychain, or web browsers.|
|[T1580 - Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/)|Detect|Minimal|This control may alert on suspicious access of key vaults, including suspicious listing of key vault contents. This control does not alert on discovery of other cloud services, such as VMs, snapshots, cloud storage and therefore has minimal coverage. Suspicious activity based on patterns of access from certain users and applications allows for managing false positive rates.|
  


### Tag(s)
- [Azure Defender](#4-azure-defender)
- [Azure Security Center Recommendation](#8-azure-security-center-recommendation)
- [Credentials](#10-credentials)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/defender-for-key-vault-introduction>
- <https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-azurekv>
  

  [Back to Table Of Contents](#contents)
## 22. Azure Defender for Kubernetes


Azure Defender for Kubernetes provides cluster-level threat protection by monitoring your Azure Kubernetes Service (AKS) managed services through the logs retrieved by AKS. Examples of security events that Azure Defender for Kubernetes monitors include exposed Kubernetes dashboards, creation of high privileged roles, and the creation of sensitive mounts.

- [Mapping File](AzureDefenderForKubernetes.yaml) ([YAML](AzureDefenderForKubernetes.yaml))
- [Navigator Layer](layers/AzureDefenderForKubernetes.json) ([JSON](layers/AzureDefenderForKubernetes.json))

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Detect|Partial|This control may alert on detection of new privileged containers and high privilege roles.|
|[T1070 - Indicator Removal on Host](https://attack.mitre.org/techniques/T1070/)|Detect|Partial|This control may alert on deletion of Kubernetes events. Attackers might delete those events for hiding their operations in the cluster. There is no relevant sub-technique for this control but the parent applies.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Protect|Partial|This control may alert on publicly exposed Kubernetes services. This may provide context on services that should be patched or hardened for public access.|
|[T1525 - Implant Container Image](https://attack.mitre.org/techniques/T1525/)|Detect|Partial|This control may alert on containers with sensitive volume mounts, unneeded privileges, or running an image with digital currency mining software.|
  


### Tag(s)
- [Azure Defender](#4-azure-defender)
- [Azure Security Center Recommendation](#8-azure-security-center-recommendation)
- [Containers](#9-containers)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/defender-for-kubernetes-introduction>
- <https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-akscluster>
  

  [Back to Table Of Contents](#contents)
## 23. Azure Defender for Resource Manager


Azure Defender for Resource Manager automatically monitors the  resource management operations in your organization, whether they're  performed through the Azure portal, Azure REST APIs, Azure CLI, or  other Azure programmatic clients. Alerts are generated by threats  detected in Azure Resource Manager logs and Azure Activity logs.  Azure Defender runs advanced security analytics to detect threats  and alert you about suspicious activity.


- [Mapping File](AlertsForResourceManager.yaml) ([YAML](AlertsForResourceManager.yaml))
- [Navigator Layer](layers/AlertsForResourceManager.json) ([JSON](layers/AlertsForResourceManager.json))

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Detect|Minimal|This control may alert on escalation attempts from Azure AD to Azure accounts by  specific exploitation toolkits. Consequently, its Coverage score is Minimal  resulting in an overall Minimal score. The following alerts may be generated: "PowerZure exploitation toolkit used to elevate access from Azure AD to Azure".|
|[T1069 - Permission Groups Discovery](https://attack.mitre.org/techniques/T1069/)|Detect|Minimal|This control may alert on Azure domain cloud groups discovery activity but may not provide alerts for other account types or undocumented exploitation toolkits.  Consequently, its Coverage  score is Minimal resulting in an overall Minimal score.|
|[T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)|Detect|Minimal|This control may alert on Azure cloud account discovery activity but may not provide alerts for other account types or undocumented exploitation toolkits. Consequently, its Coverage  score is Minimal resulting in an overall Minimal score.|
|[T1526 - Cloud Service Discovery](https://attack.mitre.org/techniques/T1526/)|Detect|Partial|This control may alert on Cloud Service Discovery activity generated by specific toolkits, such as MicroBurst, PowerZure, etc. It may not generate alerts on undocumented discovery  techniques or exploitation toolkits. The following alerts may be  generated: "PowerZure exploitation toolkit used to enumerate storage containers, shares, and tables", "PowerZure exploitation toolkit used to enumerate resources", "MicroBurst exploitation toolkit used to enumerate resources in your subscriptions".|
|[T1538 - Cloud Service Dashboard](https://attack.mitre.org/techniques/T1538/)|Detect|Partial|This control may alert on suspicious management activity based on IP, time, anomalous behaviour, or PowerShell usage. Machine learning algorithms are used to reduce false positives. The following alerts may be generated: "Activity from a risky IP address", "Activity from infrequent country", "Impossible travel activity", "Suspicious management session using PowerShell detected", "Suspicious management session using an inactive account detected", "Suspicious management session  using Azure portal detected".|
|[T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)|Detect|Minimal|This control may alert on credential dumping from Azure Key Vaults, App Services Configurations, and Automation accounts by specific exploitation toolkits. Consequently,  its Coverage score is Minimal resulting in an overall Minimal score. The following alerts may be generated: "MicroBurst exploitation toolkit used to extract secrets from your Azure key vaults", "MicroBurst exploitation toolkit used to extract keys to your storage accounts".|
|[T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/)|Detect|Minimal|This control may alert on Windows Defender security  features being disabled but does not alert on other security tools or logging being disabled or tampered with. Consequently, its Coverage score is Minimal  resulting in an overall Minimal score.|
|[T1580 - Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/)|Detect|Partial|This control may alert on Cloud Infrastructure Discovery activity generated by specific toolkits, such as MicroBurst, PowerZure, etc. It may not generate alerts on undocumented discovery  techniques or exploitation toolkits. The following alerts may be  generated: "PowerZure exploitation toolkit used to enumerate storage containers, shares, and tables", "PowerZure exploitation toolkit used to enumerate resources", "MicroBurst exploitation toolkit used to enumerate resources in your subscriptions", "Azurite toolkit run detected".|
  


### Tag(s)
- [Azure Defender](#4-azure-defender)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/defender-for-resource-manager-introduction>
- <https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-resourcemanager>
  

  [Back to Table Of Contents](#contents)
## 24. Azure Defender for Storage


Azure Defender for Storage can detect unusual and potentially harmful attempts to access or exploit storage accounts. Security alerts may trigger due to suspicious access patterns, suspicious activities, and upload of malicious content. Alerts include details of the incident that triggered them, as well as recommendations on how to investigate and remediate threats. Alerts can be exported to Azure Sentinel or any other third-party SIEM or any other external tool.

- [Mapping File](AzureDefenderForStorage.yaml) ([YAML](AzureDefenderForStorage.yaml))
- [Navigator Layer](layers/AzureDefenderForStorage.json) ([JSON](layers/AzureDefenderForStorage.json))

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Detect|Minimal|This control provides minimal detection for its procedure examples.  Additionally, it is able to detect only one of its sub-techniques (Cloud Accounts) resulting in a Minimal Coverage score and consequently an overall score of Minimal.|
|[T1080 - Taint Shared Content](https://attack.mitre.org/techniques/T1080/)|Detect|Partial|This control may alert on upload of possible malware or executable and Azure Cloud Services Package files. These alerts are dependent on Microsoft threat intelligence and may not alert on novel or modified malware.|
|[T1080 - Taint Shared Content](https://attack.mitre.org/techniques/T1080/)|Respond|Partial|"When a file is suspected to contain malware, Security Center displays an alert and can optionally email the storage owner for approval to delete the suspicious file."  This delete response capability leads to a Response type of Eradication although it is specific to Azure Blob, Azure Files and Azure Data Lake Storage storage types resulting in an overall score of Partial.|
|[T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)|Detect|Partial|This control may alert on upload of possible malware or executable and Azure Cloud Services Package files. These alerts are dependent on Microsoft threat intelligence and may not alert on novel or modified malware.|
|[T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)|Respond|Partial|"When a file is suspected to contain malware, Security Center displays an alert and can optionally email the storage owner for approval to delete the suspicious file."  This delete response capability leads to a Response type of Eradication although it is specific to Azure Blob, Azure Files and Azure Data Lake Storage storage types resulting in an overall score of Partial.|
|[T1485 - Data Destruction](https://attack.mitre.org/techniques/T1485/)|Detect|Minimal|This control may generate alerts when there has been an unusual or unexpected delete operation within Azure cloud storage. Alerts may not be generated by disabling of storage backups, versioning, or editing of storage objects.|
|[T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)|Detect|Significant|A variety of alerts may be generated by malicious access and enumeration of Azure Storage.|
|[T1537 - Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)|Detect|Partial|This control may alert on unusually large amounts of data being extracted from Azure storage and suspicious access to storage accounts. There are no alerts specifically tied to data transfer between cloud accounts but there are several alerts for anomalous storage access and transfer.|
  


### Tag(s)
- [Azure Defender](#4-azure-defender)
- [Azure Security Center Recommendation](#8-azure-security-center-recommendation)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/defender-for-storage-introduction>
- <https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-azurestorage>
  

  [Back to Table Of Contents](#contents)
## 25. Azure Firewall


Azure Firewall is a managed, cloud-based network security service that protects your Azure Virtual Network resources.  It's a fully stateful firewall as a service (FWaaS) with built-in high availability and unrestricted cloud scalability.

- [Mapping File](AzureFirewall.yaml) ([YAML](AzureFirewall.yaml))
- [Navigator Layer](layers/AzureFirewall.json) ([JSON](layers/AzureFirewall.json))

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1008 - Fallback Channels](https://attack.mitre.org/techniques/T1008/)|Protect|Partial|This control's threat intelligence-based filtering feature can be enabled to alert and deny traffic from/to known malicious IP addresses and domains. The IP addresses and domains are sourced from the Microsoft Threat Intelligence feed.  Because this protection is limited to known malicious IP addresses and domains and does not provide protection from such attacks from unknown domains and IP addresses, this is scored as partial coverage resulting in an overall Partial score.|
|[T1018 - Remote System Discovery](https://attack.mitre.org/techniques/T1018/)|Protect|Partial|This control typically filters external network traffic and therefore can be effective for preventing external remote system discovery but such activity originating from inside the trusted network is not mitigated.  Due to this partial protection coverage, it has been scored as Partial protection.|
|[T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046/)|Protect|Partial|This control typically filters external network traffic and therefore can be effective for preventing external network service scanning but network service scanning originating from inside the trusted network is not mitigated.  Due to this partial protection coverage, it has been scored as Partial protection.|
|[T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)|Protect|Partial|This control provides partial protection for this technique's sub-techniques and some of its procedure examples resulting in an overall Partial score.|
|[T1095 - Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1095/)|Protect|Partial|This control's threat intelligence-based filtering feature can be enabled to alert and deny traffic from/to known malicious IP addresses and domains. The IP addresses and domains are sourced from the Microsoft Threat Intelligence feed.  Because this protection is limited to known malicious IP addresses and domains and does not provide protection from such attacks from unknown domains and IP addresses, this is scored as partial coverage resulting in an overall Partial score.<br/>Furthermore, it can be used to filter non-application layer protocol traffic such as ICMP.|
|[T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)|Protect|Partial|This control can limit access to external remote services to the minimum necessary.|
|[T1205 - Traffic Signaling](https://attack.mitre.org/techniques/T1205/)|Protect|Partial|This control provides partial protection for this technique's sub-techniques and procedure examples resulting in a Partial score.|
|[T1219 - Remote Access Software](https://attack.mitre.org/techniques/T1219/)|Protect|Partial|This control can be used to limit outgoing traffic to only sites and services used by authorized remote access tools.  This is scored as partial because it doesn't protect against an adversary using an authorized remote access tool for malicious activity.|
|[T1571 - Non-Standard Port](https://attack.mitre.org/techniques/T1571/)|Protect|Significant|This control can limit access to the minimum required ports and therefore protect against adversaries attempting to use non-standard ports for C2 traffic.|
|[T1590 - Gather Victim Network Information](https://attack.mitre.org/techniques/T1590/)|Protect|Partial|This control can prevent the gathering of victim network information via scanning methods but is not effective against methods such as Phishing resulting in a Partial coverage score and an overall Partial score.|
|[T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)|Protect|Partial|This control provides Partial protection for its sub-techniques resulting in an overall Partial score.|
  


### Tag(s)
- [Azure Security Center Recommendation](#8-azure-security-center-recommendation)
- [Network](#17-network)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/firewall/overview>
  

  [Back to Table Of Contents](#contents)
## 26. Azure Key Vault


Azure Key Vault provides a way to store and manage secrets, keys, and certificates used throughout Azure and for internally connected resources. This control allows for fine grained permissions for authentication and authorization for access while providing monitoring for all activity with the key vault.

- [Mapping File](AzureKeyVault.yaml) ([YAML](AzureKeyVault.yaml))
- [Navigator Layer](layers/AzureKeyVault.json) ([JSON](layers/AzureKeyVault.json))

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)|Protect|Minimal|This control provides secure methods for accessing secrets and passwords. This can reduce the incidences of credentials and other authentication material being transmitted in plain text or by insecure encryption methods. Any communication between applications or endpoints after access to Key Vault may not be secure.|
|[T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)|Protect|Partial|This control can provide protection against attackers stealing application access tokens if they are stored within Azure Key Vault. Key vault significantly raises the bar for access for stored tokens by requiring legitimate credentials with proper authorization. Applications may have to be modified to take advantage of Key Vault and may not always be possible to utilize.|
|[T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)|Protect|Partial|This control provides a central, secure location for storage of credentials to reduce the possibility of attackers discovering unsecured credentials.|
|[T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)|Protect|Partial|This control may provide a more secure location for storing passwords. If an Azure user account, endpoint, or application is compromised, they may have limited access to passwords stored in the Key Vault.|
  


### Tag(s)
- [Azure Security Center Recommendation](#8-azure-security-center-recommendation)
- [Credentials](#10-credentials)
- [Passwords](#18-passwords)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/key-vault/general/overview>
  

  [Back to Table Of Contents](#contents)
## 27. Azure Network Traffic Analytics


Traffic Analytics is a cloud-based solution that provides visibility into user and application activity in cloud networks. Traffic analytics analyzes Network Watcher network security group (NSG) flow logs to provide insights into traffic flow in your Azure cloud.  It can identify security threats to, and secure your network, with information such as open-ports, applications attempting internet access, and virtual machines (VM) connecting to rogue networks.

- [Mapping File](AzureTrafficAnalytics.yaml) ([YAML](AzureTrafficAnalytics.yaml))
- [Navigator Layer](layers/AzureTrafficAnalytics.json) ([JSON](layers/AzureTrafficAnalytics.json))

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)|Detect|Partial|This control can detect anomalous traffic or attempts related to network security group (NSG) for remote services.|
|[T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046/)|Detect|Significant|This control can detect network service scanning/discovery activity.|
|[T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)|Detect|Partial|This control can detect anomalous traffic with respect to specific protocols/ports.|
|[T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)|Detect|Partial|This control can identify anomalous traffic with respect to NSG and application layer protocols.|
|[T1072 - Software Deployment Tools](https://attack.mitre.org/techniques/T1072/)|Detect|Partial|This control can detect anomalous traffic with respect to critical systems and software deployment ports.|
|[T1090 - Proxy](https://attack.mitre.org/techniques/T1090/)|Detect|Partial|This control can detect anomalous traffic between systems and external networks.|
|[T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)|Detect|Partial|This control can identify anomalous access to external remote services.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Detect|Partial|This control can detect anomalous traffic to and from externally facing systems with respect to network security group (NSG) policy.|
|[T1199 - Trusted Relationship](https://attack.mitre.org/techniques/T1199/)|Detect|Partial|This control can be used to gain insight into normal traffic from trusted third parties which can then be used to detect anomalous traffic that may be indicative of a threat.|
|[T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)|Detect|Partial|This control can identify volumetric and multi-sourced denial-of-service attacks.|
|[T1542 - Pre-OS Boot](https://attack.mitre.org/techniques/T1542/)|Detect|Minimal|This control can identify anomalous traffic related to one of its sub-techniques (TFTP boot).|
|[T1563 - Remote Service Session Hijacking](https://attack.mitre.org/techniques/T1563/)|Detect|Partial|This control can be used to identify anomalous traffic related to RDP and SSH sessions or blocked attempts to access these management ports.|
|[T1571 - Non-Standard Port](https://attack.mitre.org/techniques/T1571/)|Detect|Significant|This control can identify anomalous traffic that utilizes non-standard application ports.|
|[T1602 - Data from Configuration Repository](https://attack.mitre.org/techniques/T1602/)|Detect|Partial|This control can identify anomalous traffic with respect to configuration repositories or identified configuration management ports.|
  


### Tag(s)
- [Analytics](#2-analytics)
- [Network](#17-network)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/network-watcher/traffic-analytics>
  

  [Back to Table Of Contents](#contents)
## 28. Azure Policy


Azure Policy evaluates resources in Azure by comparing the properties of those resources to business rules. These business rules, described in JSON format, are known as policy definitions. Azure Policy helps to enforce organizational standards and to assess compliance at-scale.

- [Mapping File](AzurePolicy.yaml) ([YAML](AzurePolicy.yaml))
- [Navigator Layer](layers/AzurePolicy.json) ([JSON](layers/AzurePolicy.json))

### Mapping Comments


This mapping is focused on the list of built-in policy definitions provided by Azure Policy. All scores are capped at Partial since this control provides recommendations rather than applying/enforcing the recommended actions.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)|Protect|Minimal||
|[T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)|Protect|Partial|This control may provide recommendations to enable various Azure services that route traffic through secure networks, segment all network traffic, and enable TLS encryption where available.|
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Protect|Minimal|This control may provide recommendations for vulnerability assessment and outdated applications and cloud services. This control covers a wide range of Azure cloud services to help reduce the surface area for exploitation.|
|[T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)|Protect|Minimal||
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Protect|Minimal||
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Protect|Minimal||
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Protect|Partial||
|[T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)|Protect|Partial|This control may provide recommendations to secure external remote services, such as restricting SSH access, enabling multi-factor authentication for VPN access, and auditing external remote services that are not necessary or updated.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Protect|Partial|This control may provide recommendations to restrict access to applications that are public facing and providing information on vulnerable applications.|
|[T1203 - Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)|Protect|Minimal|This control may provide recommendations for vulnerability assessment and outdated applications and cloud services. This control covers a wide range of Azure cloud services to help reduce the surface area for exploitation.|
|[T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)|Protect|Minimal|This control may provide recommendations to enable Azure security controls to harden remote services and reduce surface area for possible exploitation.|
|[T1211 - Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211/)|Protect|Minimal|This control may provide recommendations for vulnerability assessment and outdated applications and cloud services. This control covers a wide range of Azure cloud services to help reduce the surface area for exploitation.|
|[T1212 - Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212/)|Protect|Minimal|This control may provide recommendations for vulnerability assessment and outdated applications and cloud services. This control covers a wide range of Azure cloud services to help reduce the surface area for exploitation.|
|[T1485 - Data Destruction](https://attack.mitre.org/techniques/T1485/)|Protect|Minimal|This control may provide recommendations to enable soft deletion and purge protection in Azure Key Vault. This can help mitigate against malicious deletion of keys and secrets stored within Key Vault.|
|[T1505 - Server Software Component](https://attack.mitre.org/techniques/T1505/)|Protect|Minimal||
|[T1525 - Implant Container Image](https://attack.mitre.org/techniques/T1525/)|Detect|Minimal|This control may provide recommendations to enable scanning and auditing of container images. This can provide information on images that have been added with high privileges or vulnerabilities.|
|[T1526 - Cloud Service Discovery](https://attack.mitre.org/techniques/T1526/)|Protect|Partial|This control may provide recommendations to enable Azure services that limit access to cloud services. Several Azure services and controls provide mitigations against cloud service discovery.|
|[T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)|Protect|Partial|This control may provide recommendations to enable Azure Defender for Storage and other security controls to prevent access to data from cloud storage objects.|
|[T1535 - Unused/Unsupported Cloud Regions](https://attack.mitre.org/techniques/T1535/)|Protect|Partial|This control may provide recommendations to restrict the allowed locations your organization can specify when deploying resources or creating resource groups.|
|[T1537 - Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)|Protect|Minimal|This control may provide recommendations to enable security controls that monitor and prevent malicious transfer of data to cloud accounts.|
|[T1538 - Cloud Service Dashboard](https://attack.mitre.org/techniques/T1538/)|Protect|Partial|This control may provide recommendations to enable Azure services that limit access to Azure Resource Manager and other Azure dashboards. Several Azure services and controls provide mitigations against this technique.|
|[T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)|Protect|Partial|This control may provide recommendations for auditing and hardening Azure Key Vault to prevent malicious access and segment key access.|
|[T1580 - Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/)|Protect|Partial|This control may provide recommendations to enable Azure services that limit access to cloud infrastructure. Several Azure services and controls provide mitigations against cloud infrastructure discovery.|
|[T1590 - Gather Victim Network Information](https://attack.mitre.org/techniques/T1590/)|Protect|Partial|This control may provide recommendations to restrict access to cloud resources from public networks and to route traffic between resources through Azure. Recommendations are also provided to use private DNS zones. If these recommendations are implemented the visible network information should be reduced.|
  


### Tag(s)
- [Azure Security Center Recommendation](#8-azure-security-center-recommendation)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/governance/policy/overview>
- <https://docs.microsoft.com/en-us/azure/governance/policy/samples/built-in-policies#api-for-fhir>
  

  [Back to Table Of Contents](#contents)
## 29. Azure Private Link


Azure Private Link enables you to access Azure PaaS Services (for example, Azure Storage and SQL Database) and Azure hosted customer-owned/partner services over a private endpoint in your virtual network.
Traffic between your virtual network and the service travels the Microsoft backbone network. Exposing your service to the public internet is no longer necessary. You can create your own private link service in your virtual network and deliver it to your customers. Setup and consumption using Azure Private Link is consistent across Azure PaaS, customer-owned, and shared partner services.

- [Mapping File](AzurePrivateLink.yaml) ([YAML](AzurePrivateLink.yaml))
- [Navigator Layer](layers/AzurePrivateLink.json) ([JSON](layers/AzurePrivateLink.json))

### Mapping Comments


This is a private network service, allowing connections between Azure, on-prem, and 3rd party services without traversing the Internet. Generally this reduces risk from MiTM, DOS, network-based data manipulation and network sniffing from untrusted network.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)|Protect|Partial|This control reduces the likelihood of a network sniffing attack for traffic between remote users, cloud, and 3rd parties by routing the traffic via the Microsoft backbone rather than over the Internet.|
|[T1498 - Network Denial of Service](https://attack.mitre.org/techniques/T1498/)|Protect|Partial|Prevents Denial of Service (DOS) against systems that would otherwise need to connect via an internet-traversing path (coverage partial, since doesn't apply to systems that must be directly exposed to the Internet)|
|[T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)|Protect|Partial|Prevents Denial of Service (DOS) against systems that would otherwise need to connect via an internet-traversing path (coverage partial, since doesn't apply to systems that must be directly exposed to the Internet)|
|[T1557 - Man-in-the-Middle](https://attack.mitre.org/techniques/T1557/)|Protect|Partial|This control provides partial protection for this technique's sub-techniques resulting in an overall Partial score.|
|[T1565 - Data Manipulation](https://attack.mitre.org/techniques/T1565/)|Protect|Minimal|This control provides partial protection for one of this technique's sub-techniques resulting in an overall Minimal score.|
  


### Tag(s)
- [Azure Security Center Recommendation](#8-azure-security-center-recommendation)
- [Network](#17-network)
  


### Reference(s)
- <https://docs.microsoft.com/azure/private-link/private-link-overview>
  

  [Back to Table Of Contents](#contents)
## 30. Azure Security Center Recommendations


This feature of Azure Security Center assesses your workloads and raises threat prevention recommendations and security alerts.

- [Mapping File](SecurityCenterRecommendations.yaml) ([YAML](SecurityCenterRecommendations.yaml))
- [Navigator Layer](layers/SecurityCenterRecommendations.json) ([JSON](layers/SecurityCenterRecommendations.json))

### Mapping Comments


Security Center recommendations include recommendations to enable security controls that have already been mapped separately (e.g. "Azure Defender for App Service should be enabled").    Rather than including the (sub-)techniques that these controls map to within this mapping, consult the mapping files for these controls.  To make this latter task easier, we have tagged all such controls with the "Azure Security Center Recommendation" tag.
All scores are capped at Partial since this control provides recommendations rather than applying/enforcing the recommended actions.
IoT related recommendations were not included in this mapping.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)|Protect|Minimal|This control's recommendations related to enforcing the usage of the secure versions of the HTTP and FTP protocols (HTTPS and FTPS) can lead to encrypting traffic which reduces the ability for an adversary to gather sensitive data via network sniffing.  <br/>This also applies to the "Service Fabric clusters should have the ClusterProtectionLevel property set to EncryptAndSign", "Enforce SSL connection should be enabled for MySQL database servers", "Enforce SSL connection should be enabled for PostgreSQL database servers", "Only secure connections to your Redis Cache should be enabled" and "Secure transfer to storage accounts should be enabled" recommendations for their respective protocols.<br/>The "Usage of host networking and ports should be restricted" recommendation for Kubernetes clusters can also lead to mitigating this technique.<br/>These recommendations are limited to specific technologies on the platform and therefore its coverage score is Minimal.|
|[T1053 - Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)|Protect|Minimal|This control's "Immutable (read-only) root filesystem should be enforced for containers" recommendation can mitigate a few of the sub-techniques of this technique.  Due to its Minimal coverage, its score is assessed as Minimal.|
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Protect|Partial|This control's "Container with privilege escalation should be avoided", "Least privileged Linux capabilities should be enforced for containers", "Privileged containers should be avoided", "Running containers as root user should be avoided" and "Containers sharing sensitive host namespaces should be avoided" recommendations can make it difficult for adversaries to advance their operation through exploitation of undiscovered or unpatched vulnerabilities.  Because this is a recommendation, the assessed score has been capped at Partial.|
|[T1074 - Data Staged](https://attack.mitre.org/techniques/T1074/)|Protect|Partial|This control's "Immutable (read-only) root filesystem should be enforced for containers" recommendation can lead to mitigating a sub-technique of this technique by preventing modification of the local filesystem.  Due to it being a recommendation, its score is capped at Partial.|
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Protect|Minimal|This control's recommendations about removing deprecated and external accounts with sensitive permissions from your subscription can lead to mitigating the Cloud Accounts sub-technique of this technique.  Because this is a recommendation and has low coverage, it is assessed as Minimal.|
|[T1080 - Taint Shared Content](https://attack.mitre.org/techniques/T1080/)|Protect|Partial|This control's "Immutable (read-only) root filesystem should be enforced for containers" and "Usage of pod HostPath volume mounts should be restricted to a known list to restrict node access from compromised containers" recommendations can mitigate this technique.  Due to it being a recommendation, its score is capped at Partial.|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Protect|Minimal|This control's "Immutable (read-only) root filesystem should be enforced for containers" recommendation can prevent modifying the ssh_authorized keys file.  Because it is a recommendation and limited to only one sub-technique, its score is Minimal.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Protect|Minimal|This control's "Authentication to Linux machines should require SSH keys" recommendation can  lead to obviating SSH Brute Force password attacks.  Because this is specific to Linux, the coverage score is Minimal leading to an overall Minimal score.|
|[T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)|Protect|Partial|This control's "Management ports should be closed on your virtual machines" recommendation can lead to reducing the attack surface of your Azure VMs by recommending closing management ports.  Because this is a recommendation, its score is limited to Partial.|
|[T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)|Protect|Minimal|This control's "Immutable (read-only) root filesystem should be enforced for containers" recommendation can mitigate a sub-technique of this technique.  Due to its Minimal coverage, its score is assessed as Minimal.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Protect|Minimal|This control's CORS related recommendations can help lead to hardened web applications.  This can reduce  the likelihood of an application being exploited to reveal sensitive data that can lead to the compromise of an environment. <br/>Likewise this control's recommendations related to keeping Java/PHP up to date for API/Function/Web apps can lead to hardening the public facing content that uses these runtimes.<br/>This control's recommendations related to disabling Public network access for Azure databases can lead to reducing the exposure of resources to the public Internet and thereby reduce the attack surface.<br/>These recommendations are limited to specific technologies (Java, PHP and CORS, SQL DBs) and therefore provide Minimal coverage leading to a Minimal score.|
|[T1222 - File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222/)|Protect|Minimal|This control's "Immutable (read-only) root filesystem should be enforced for containers" recommendation can mitigate a sub-technique of this technique.  Due to its Minimal coverage, its score is assessed as Minimal.|
|[T1485 - Data Destruction](https://attack.mitre.org/techniques/T1485/)|Protect|Partial|This control's "Immutable (read-only) root filesystem should be enforced for containers" recommendation can lead to mitigating this technique by preventing modification of the local filesystem.  Due to it being a recommendation, its score is capped at Partial.|
|[T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)|Protect|Partial|This control's "Immutable (read-only) root filesystem should be enforced for containers" recommendation can lead to mitigating this technique by preventing modification of the local filesystem.  Due to it being a recommendation, its score is capped at Partial.|
|[T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)|Protect|Minimal|This control provides recommendations for limiting the CPU and memory resources consumed by a container to minimize resource exhaustion attacks.  Because this control only covers one sub-technique of this technique, its score is assessed as Minimal.|
|[T1505 - Server Software Component](https://attack.mitre.org/techniques/T1505/)|Protect|Minimal|This control's "Immutable (read-only) root filesystem should be enforced for containers" recommendation can mitigate a sub-technique of this technique.  Due to its Minimal coverage, its score is assessed as Minimal.|
|[T1525 - Implant Container Image](https://attack.mitre.org/techniques/T1525/)|Protect|Partial|This control's "Container images should be deployed from trusted registries only", "Container registries should not allow unrestricted network access" and "Container registries should use private link" recommendations can lead to ensuring that container images are only loaded from trusted registries thereby mitigating this technique.|
|[T1542 - Pre-OS Boot](https://attack.mitre.org/techniques/T1542/)|Protect|Partial|This control provides recommendations for enabling Secure Boot of Linux VMs that can mitigate a few of the sub-techniques of this technique.  Because this is a recommendation and only limited to a few sub-techniques of this technique, its assessed score is Partial.|
|[T1543 - Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)|Protect|Minimal|This control's "Immutable (read-only) root filesystem should be enforced for containers" recommendation can mitigate a sub-technique of this technique.  Due to its Minimal coverage, its score is assessed as Minimal.|
|[T1546 - Event Triggered Execution](https://attack.mitre.org/techniques/T1546/)|Protect|Minimal|This control's "Immutable (read-only) root filesystem should be enforced for containers" recommendation can mitigate a sub-technique of this technique.  Due to its Minimal coverage, its score is assessed as Minimal.|
|[T1554 - Compromise Client Software Binary](https://attack.mitre.org/techniques/T1554/)|Protect|Partial|This control's "Immutable (read-only) root filesystem should be enforced for containers" recommendation can lead to preventing modification of binaries in Kubernetes containers thereby mitigating this technique.  Because this is a recommendation, its score is capped at Partial.|
|[T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)|Protect|Minimal|This control's "Immutable (read-only) root filesystem should be enforced for containers" recommendation can mitigate a sub-techniques of this technique.  Due to it being a recommendation and providing minimal coverage, its score is assessed as Minimal.|
|[T1564 - Hide Artifacts](https://attack.mitre.org/techniques/T1564/)|Protect|Minimal|This control's "Immutable (read-only) root filesystem should be enforced for containers" recommendation can mitigate some of the sub-techniques of this technique.  Due to its partial coverage and Minimal score assessed for its sub-techniques, its score is assessed as Minimal.|
|[T1565 - Data Manipulation](https://attack.mitre.org/techniques/T1565/)|Protect|Minimal|This control's "Immutable (read-only) root filesystem should be enforced for containers" recommendation can lead to mitigating a sub-technique of this technique by preventing modification of the local filesystem.  Due to it being a recommendation and mitigating only one sub-technique, its score is assessed as Minimal.|
  


### Tag(s)
- [Azure Security Center](#7-azure-security-center)
- [Azure Security Center Recommendation](#8-azure-security-center-recommendation)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/recommendations-reference>
- <https://docs.microsoft.com/en-us/azure/security-center/security-center-introduction>
  

  [Back to Table Of Contents](#contents)
## 31. Azure Sentinel


Microsoft Azure Sentinel is a scalable, cloud-native, security information event management (SIEM) and security orchestration automated response (SOAR) solution.

- [Mapping File](AzureSentinel.yaml) ([YAML](AzureSentinel.yaml))
- [Navigator Layer](layers/AzureSentinel.json) ([JSON](layers/AzureSentinel.json))

### Mapping Comments


The following capabilities of Azure Sentinel were mapped: Default list of Azure Sentinel Analytics (from the rule template list) Default list of Azure Sentinel Hunting queries
Queries based on 3rd party analytics and/or specific IOC information were omitted from this mapping. Query names are identified in quotes throughout this mapping.
Azure Sentinel Analytics queries are generally periodic, typically on a period of one or more hours.
Azure Sentinel Hunting queries are performed on demand. Note also that a number of the Hunting queries are examples that can be modified for additional use, but scoring was performed on the queries as-written.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)|Detect|Minimal|This control can identify one of this technique's sub-techniques when executed via "Powershell Empire cmdlets seen in command line", but does not address other procedures.|
|[T1016 - System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/)|Detect|Minimal|The Azure Sentinel Analytics "Powershell Empire cmdlets seen in command line" query can detect the use of Empire, which can acquire network configuration information including DNS servers and network proxies used by a host, but does not address other procedures.|
|[T1018 - Remote System Discovery](https://attack.mitre.org/techniques/T1018/)|Detect|Minimal|The Azure Sentinel Hunting "High reverse DNS count by host" and "Squid malformed requests" queries can indicate potentially malicious reconnaissance aimed at detecting network layout and the presence of network security devices.<br/>The Azure Sentinel Analytics "Several deny actions registered" query can identify patterns in Azure Firewall incidents, potentially indicating that an adversary is scanning resources on the network, at a default frequency of once per hour. Note that detection only occurs if the firewall prevents the scanning. The Azure Sentinel Analytics "Rare client observed with high reverse DNS lookup count" query can detect when a particular IP address performs an unusually high number of reverse DNS lookups and has not been observed doing so previously. The coverage for these queries is minimal resulting in an overall Minimal score.|
|[T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)|Detect|Minimal|This control provides minimal to partial coverage for some of this technique's sub-techniques, resulting in an overall score of Minimal.|
|[T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)|Detect|Minimal|The Azure Sentinel Analytics "Powershell Empire cmdlets seen in command line" query can detect the use of Empire, which can obfuscate commands using Invoke-Obfuscation, but does not address other procedures.|
|[T1036 - Masquerading](https://attack.mitre.org/techniques/T1036/)|Detect|Minimal|This control provides minimal to partial coverage of a minority of this technique's sub-techniques and a minority of its procedure examples, resulting in an overall score of Minimal.|
|[T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)|Detect|Minimal|The Azure Sentinel Analytics "Powershell Empire cmdlets seen in command line" query can detect the use of Empire, which can be used to conduct packet capture on target hosts, but does not address other procedures.|
|[T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)|Detect|Minimal|The Azure Sentinel Analytics "Powershell Empire cmdlets seen in command line" query can detect the use of Empire, which can send data gathered from a target through a command and control channel, but does not address other procedures.|
|[T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046/)|Detect|Partial|The Azure Sentinel Analytics "High count of connections by client IP on many ports" query can detect when a given client IP has 30 or more ports used within a 10 minute window, which may indicate malicious scanning. The Azure Sentinel Analytics "Powershell Empire cmdlets seen in command line" query can detect scanning via Empire, but does not address other procedures.|
|[T1047 - Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)|Detect|Minimal|The Azure Sentinel Analytics "Gain Code Execution on ADFS Server via Remote WMI Execution" query can detect use of Windows Managemement Instrumentation on ADFS servers. The Azure Sentinel Analytics "Powershell Empire cmdlets seen in command line" query can detect WMI use via Empire, but does not address other procedures.<br/>The coverage for these queries is minimal (specific to ADFS and Empire) resulting in an overall Minimal score.|
|[T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)|Detect|Minimal|This control provides minimal coverage for a minority of this technique's sub-techniques and does not cover all procedure examples, resulting in an overall score of Minimal.|
|[T1049 - System Network Connections Discovery](https://attack.mitre.org/techniques/T1049/)|Detect|Minimal|The Azure Sentinel Analytics "Powershell Empire cmdlets seen in command line" query can detect the use of Empire, which can enumerate the current network connections of a host, but does not address other procedures.|
|[T1053 - Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)|Detect|Minimal|This control provides minimal to partial coverage of a minority of this technique's sub-techniques, resulting in an overall score of Minimal.|
|[T1055 - Process Injection](https://attack.mitre.org/techniques/T1055/)|Detect|Minimal|The Azure Sentinel Analytics "Powershell Empire cmdlets seen in command line" query can detect the use of Empire, which contains multiple modules for injecting into processes, but does not address other procedures.|
|[T1056 - Input Capture](https://attack.mitre.org/techniques/T1056/)|Detect|Minimal|This control can identify two of this technique's sub-techniques when executed via "Powershell Empire cmdlets seen in command line", but does not address other procedures.|
|[T1057 - Process Discovery](https://attack.mitre.org/techniques/T1057/)|Detect|Minimal|The Azure Sentinel Analytics "Powershell Empire cmdlets seen in command line" query can detect the use of Empire, which can find information about processes running on local and remote systems, but does not address other procedures.|
|[T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)|Detect|Minimal|This control provides minimal coverage for most of this technique's sub-techniques, along with additional mappings for its procedure examples, resulting in an overall score of Minimal.<br/>The following Azure Sentinel Hunting queries can identify potentially malicious use of command and scripting interpreters that does not map directly to one/more sub-techniques: "Anomalous Code Execution" can identifyanomalous runCommand operations on virtual machines, "Azure CloudShell Usage" can identify potentially malicious use of CloudShell, "New processes observed in last 24 hours", "Rare processes run by Service accounts", and "Rare Custom Script Extension" can identify execution outliers that may suggest misuse.<br/>The following Azure Sentinel Analytics queries can identify potentially malicious use of command and scripting interpreters that does not map directly to one/more sub-techniques: "New CloudShell User" can identify potentially malicious use of CloudShell, "Rare and Potentially high-risk Office operations" can identify specific rare mailbox-related  ccount and permission changes via execution.|
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Detect|Minimal|The Azure Sentinel Analytics "Powershell Empire cmdlets seen in command line" query can detect the use of Empire, which can exploit known system vulnerabilities, but does not explicitly address other procedures.|
|[T1069 - Permission Groups Discovery](https://attack.mitre.org/techniques/T1069/)|Detect|Minimal|This control provides minimal coverage for one of this technique's sub-techniques and only minimal coverage for its procedure examples, resulting in an overall score of Minimal.|
|[T1070 - Indicator Removal on Host](https://attack.mitre.org/techniques/T1070/)|Detect|Minimal|This control provides specific minimal coverage for two of this technique's sub-techniques, without additional coverage of its procedure examples, resulting in an overall score of Minimal.<br/>The Azure Sentinel Analytics "Azure DevOps Agent Pool Created Then Deleted" query can detect specific suspicious activity for DevOps Agent Pool. This is close to this technique's File Deletion sub-technique, but not a complete match.|
|[T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)|Detect|Minimal|The Azure Sentinel Analytics "Malformed user agent" query can detect potential C2 or C2 agent activity.<br/>This control provides minimal to partial coverage for a minority of this technique's sub-techniques and only some of its procedure examples, resulting in an overall score of Minimal.|
|[T1074 - Data Staged](https://attack.mitre.org/techniques/T1074/)|Detect|Minimal||
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Detect|Partial|This control provides partial coverage for all of this technique's sub-techniques and a number of its procedures, resulting in an overall score of Partial.|
|[T1080 - Taint Shared Content](https://attack.mitre.org/techniques/T1080/)|Detect|Minimal|The Azure Sentinel Analytics "Potential Build Process Compromise" query can detect when source code files have been modified immediately after the build process has started. The Azure Sentinel Analytics "ADO Build Variable Modified by New User" query may indicate malicious modification to the build process to taint shared content.<br/>The coverage for these queries is minimal (specific to Azure DevOps) resulting in an overall Minimal score.|
|[T1082 - System Information Discovery](https://attack.mitre.org/techniques/T1082/)|Detect|Minimal|The Azure Sentinel Analytics "Powershell Empire cmdlets seen in command line" query can detect the use of Empire, which can enumerate host information like OS, architecture, applied patches, etc., but does not address other procedures.|
|[T1083 - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)|Detect|Minimal|The Azure Sentinel Analytics "Powershell Empire cmdlets seen in command line" query can detect the use of Empire, which includes modules for finding files of interest on hosts and network shares, but does not address other procedures.|
|[T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)|Detect|Minimal|This control provides specific forms of minimal coverage for half of this technique's sub-techniques, but does not address other procedures, resulting in an overall score of Minimal.|
|[T1090 - Proxy](https://attack.mitre.org/techniques/T1090/)|Detect|Minimal|This control provides minimal coverage for one sub-technique of this technique, resulting in an overall coverage score of Minimal.|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Detect|Minimal|The following Azure Sentinel Hunting queries can identify potentially malicious manipulation of accounts to increase or maintain access: "Azure DevOps - Guest users access enabled", "Azure DevOps - Additional Org Admin added", "Anomalous Activity Role Assignment", "Anomalous Role Assignment", and "Anomalous AAD Account Manipulation", which indicate expansion of accounts' access/privileges; "Bots added to multiple teams" which indicates workspace access granted to automated accounts.<br/>The following Azure Sentinel Analytics queries can identify potentially malicious manipulation of accounts to increase or maintain access: "Suspicious granting of permissions to an account" from a previously unobserved IP address, "External user added and removed in short timeframe" for Teams resources, "Account added and removed from privileged group", "User account added to built in domain local or global group", and "New user created and added to the built-in administrator group". "Multiple Password Reset by user" can detect potentially malicious iterative password resets.|
|[T1102 - Web Service](https://attack.mitre.org/techniques/T1102/)|Detect|Minimal|This control can identify one of this technique's sub-techniques when executed via "Powershell Empire cmdlets seen in command line", but does not address other procedures.|
|[T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)|Detect|Partial|The Azure Sentinel Hunting "Crypto currency miners EXECVE" query can detect cryptocurrency mining software downloads through EXECVE.<br/>The following Azure Sentinel Analytics queries can identify potentiall malicious tool transfer: "Linked Malicious Storage Artifacts" may identify potential adversary tool downloads that are missed by anti-malware. "Powershell Empire cmdlets seen in command line" detects downloads via Empire. "New executable via Office FileUploaded Operations" can identify ingress of malicious code and attacker tools to Office services such as SharePoint and OneDrive, but with potential for high false positive rates from normal user upload activity.|
|[T1106 - Native API](https://attack.mitre.org/techniques/T1106/)|Detect|Minimal|The Azure Sentinel Analytics "Powershell Empire cmdlets seen in command line" query can detect the use of Empire, which includes a variety of enumeration modules that have an option to use API calls to carry out tasks, but does not address other procedures.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Detect|Partial|This control includes partial detection coverage for most of this technique's sub-techniques on a periodic basis.|
|[T1113 - Screen Capture](https://attack.mitre.org/techniques/T1113/)|Detect|Minimal|The Azure Sentinel Analytics "Powershell Empire cmdlets seen in command line" query can detect the use of Empire, which can capture screenshots on Windows, but does not address other procedures.|
|[T1114 - Email Collection](https://attack.mitre.org/techniques/T1114/)|Detect|Minimal|This control provides minimal coverage for all of this technique's sub-techniques, resulting in an overall score of Minimal.|
|[T1115 - Clipboard Data](https://attack.mitre.org/techniques/T1115/)|Detect|Minimal|The Azure Sentinel Analytics "Powershell Empire cmdlets seen in command line" query can detect the use of Empire, which can harvest clipboard data on Windows, but does not address other procedures or platforms.|
|[T1119 - Automated Collection](https://attack.mitre.org/techniques/T1119/)|Detect|Minimal|The following Azure Sentinel Hunting queries can identify potentially malicious automated collection: "Multiple large queries made by user" and "Query data volume anomolies" can identify that automated queries are being used to collect data in bulk. "New ServicePrincipal running queries" can indicate that an application is performing automated collection via queries.<br/>The following Azure Sentinel Analytics queries can identify potentially malicious automated collection: "Mass secret retrieval from Azure Key Vault" and "Azure Key Vault access TimeSeries anomaly" can detect a sudden increase in access counts, which may indicate that an adversary is dumping credentials via automated methods. "Users searching for VIP user activity" can identify potentially suspicious Log Analytics queries by users looking for a listing of 'VIP' activity.<br/>The coverage for these queries is minimal (applicable to specific technologies) resulting in an overall Minimal score.|
|[T1125 - Video Capture](https://attack.mitre.org/techniques/T1125/)|Detect|Minimal|The Azure Sentinel Analytics "Powershell Empire cmdlets seen in command line" query can detect the use of Empire, which can capture webcam data on Windows, but does not address other procedures.|
|[T1127 - Trusted Developer Utilities Proxy Execution](https://attack.mitre.org/techniques/T1127/)|Detect|Minimal|This control can identify one of this technique's sub-techniques when executed via "Powershell Empire cmdlets seen in command line", but does not address other procedures.|
|[T1134 - Access Token Manipulation](https://attack.mitre.org/techniques/T1134/)|Detect|Minimal|This control provides minimal coverage of a minority of this technique's sub-techniques, but does not address other procedures, resulting in an overall score of Minimal.<br/>The Azure Sentinel Analytics "Azure DevOps Personal Access Token misuse" query can identify anomalous use of Personal Access Tokens, but does not map directly to any sub-techniques.|
|[T1135 - Network Share Discovery](https://attack.mitre.org/techniques/T1135/)|Detect|Minimal|The Azure Sentinel Analytics "Powershell Empire cmdlets seen in command line" query can detect the use of Empire, which can perform port scans from an infected host, but does not address other procedures.|
|[T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)|Detect|Partial|This control provides partial coverage for all of this technique's sub-techniques, resulting in an overall score of Partial.|
|[T1137 - Office Application Startup](https://attack.mitre.org/techniques/T1137/)|Detect|Minimal|This control only provides minimal to partial coverage for a minority of this technique's<br/>sub-techniques and does not address all of its procedures, resulting in an overall score<br/>of Minimal.|
|[T1140 - Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)|Detect|Minimal|The Azure Sentinel Hunting "New PowerShell Scripts encoded on the commandline" query can detect a specific type of obfuscated file.<br/>The Azure Sentinel Analytics "Process executed from binary hidden in Base64 encoded file" query can use security event searches to detect decoding by Python, bash/sh, and Ruby.<br/>The coverage for these queries is minimal (e.g. base64, PowerShell) resulting in an overall Minimal score.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Detect|Minimal|The Azure Sentinel Hunting "Potential IIS code injection attempt" query can detect some potential injection attacks against public-facing applications.<br/>The Azure Sentinel Analytics "A potentially malicious web request was executed against a web server" query can detect a high ratio of blocked requests and unobstructed requests to a Web Application Firewall (WAF) for a given client IP and hostnam.<br/>The coverage for these queries is minimal (e.g. IIS) resulting in an overall Minimal score.|
|[T1195 - Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)|Detect|Minimal|This control provides partial coverage for one of this technique's sub-techniques, and its coverage is more for supply chain concerns of downstream consumers of software developed within the environemnt than the Azure environment itself, resulting in an overall score of Minimal.|
|[T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)|Detect|Minimal|The Azure Sentinel Analytics "Powershell Empire cmdlets seen in command line" query can detect the use of Empire, which includes built-in modules for exploiting remote SMB, JBoss, and Jenkins servers, but does not address other procedures. The Azure Sentinel Analytics "Gain Code Execution on ADFS Server via SMB + Remote Service or Scheduled Task" query can detect when an adversary gains execution capability on an ADFS server through SMB and Remote Service or Scheduled Task.|
|[T1213 - Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)|Detect|Minimal|This control provides partial detection coverage for only this technique's SharePoint sub-technique.<br/>The Azure Sentinel Hunting "Cross workspace query anomaly" query can identify potential adversary information collection (in this case from Azure ML workspaces), but does not map directly to any sub-techniques.|
|[T1217 - Browser Bookmark Discovery](https://attack.mitre.org/techniques/T1217/)|Detect|Minimal|The Azure Sentinel Analytics "Powershell Empire cmdlets seen in command line" query can detect the use of Empire, which has the ability to gather browser data including bookmarks and history, but does not address other procedures.|
|[T1482 - Domain Trust Discovery](https://attack.mitre.org/techniques/T1482/)|Detect|Minimal|The Azure Sentinel Analytics "Powershell Empire cmdlets seen in command line" query can detect the use of Empire, which can enumerate domain trusts, but does not address other procedures.|
|[T1484 - Domain Policy Modification](https://attack.mitre.org/techniques/T1484/)|Detect|Partial|This control provides minimal to partial coverage of both of this technique's sub-techniques, resulting in an overall score of Partial.|
|[T1485 - Data Destruction](https://attack.mitre.org/techniques/T1485/)|Detect|Minimal|The Azure Sentinel Hunting "Multiple Teams deleted by a single user" query can detect when a threshold is met for number of Teams deleted within an hour. Coverage is minimal because the control is limited to a specific resource (teams) and only works when the threshold is met.<br/>The Azure Sentinel Analytics "Multiple Teams deleted by a single user" query can detect when a threshold is met for number of Teams deleted within an hour. Coverage is minimal because the control is limited to a specific resource (teams) and only works when the threshold is met.|
|[T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)|Detect|Minimal|The Azure Sentinel Analytics "Sensitive Azure Key Vault Operations" query can identify potential attacker activity intended to delete private key(s) required to decrypt content.|
|[T1490 - Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)|Detect|Minimal|The Azure Sentinel Analytics "Sensitive Azure Key Vault Operations" query can identify potential attacker activity intended to interfere with backups.|
|[T1496 - Resource Hijacking](https://attack.mitre.org/techniques/T1496/)|Detect|Partial|The following Azure Sentinel Hunting queries can identify potential resource hijacking based on anomolies in access and usage patterns: "Anomalous Resource Creation and related Network Activity", "Creation of an anomalous number of resources".<br/>The following Azure Sentinel Analytis queries can identify potential resource hijacking: "Creation of Expensive Computes in Azure" and "Suspicious number of resource creation or deployed" [sic] can identify suspicious outliers in resource quantities requested. "Suspicious Resource deployment" can identify deployments from new, potentially malicious, users. "Process execution frequency anomaly" can identify execution that may indicate hijacking. "DNS events related to mining pools", can identify potential cryptocurrency mining activity.|
|[T1505 - Server Software Component](https://attack.mitre.org/techniques/T1505/)|Detect|Minimal|This control provides partial coverage for only one of this technique's sub-techniques, resulting in overall coverage of Minimal.|
|[T1518 - Software Discovery](https://attack.mitre.org/techniques/T1518/)|Detect|Minimal|This control can identify one of this technique's sub-techniques when executed via "Powershell Empire cmdlets seen in command line", but does not address other procedures.|
|[T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)|Detect|Minimal|The Azure Sentinel Hunting "Consent to Application discovery" query can identify recent permissions granted by a user to a particular app.|
|[T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)|Detect|Minimal|The Azure Sentinel Hunting "Anomalous Data Access" query identifies all users performing out-of-profile read operations regarding data or files, which may be indicative of adversarial collection from cloud storage objects.|
|[T1531 - Account Access Removal](https://attack.mitre.org/techniques/T1531/)|Detect|Minimal|The following Azure Sentinel Hunting queries can identify potentially malicious behavior on user accounts: "AD Account Lockout", "Anomalous Password Reset", "SQL User deleted from Database", "User removed from SQL Server Roles", and "User removed from SQL Server SecurityAdmin Group".<br/>The Azure Sentinel Analytics "Sensitive Azure Key Vault operations" query can identify attempts to remove account access by deleting keys or entire key vaults.|
|[T1535 - Unused/Unsupported Cloud Regions](https://attack.mitre.org/techniques/T1535/)|Detect|Minimal|The Azure Sentinel Analytics "Suspicious Resource deployment" query can identify adversary attempts to maintain persistence or evade defenses by leveraging unused and/or unmonitored resources.|
|[T1543 - Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)|Detect|Minimal|This control can identify one of this technique's sub-techniques when executed via "Powershell Empire cmdlets seen in command line", but does not address other procedures.|
|[T1546 - Event Triggered Execution](https://attack.mitre.org/techniques/T1546/)|Detect|Minimal|This control can identify one of this technique's sub-techniques when executed via "Powershell Empire cmdlets seen in command line", but does not address other procedures.|
|[T1547 - Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)|Detect|Minimal|This control can identify three of this technique's sub-techniques when executed via "Powershell Empire cmdlets seen in command line", but does not address other procedures.|
|[T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)|Detect|Minimal|This control can identify one of this technique's sub-techniques when executed via "Powershell Empire cmdlets seen in command line", but does not address other procedures.|
|[T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)|Detect|Minimal|This control provides minimal coverage of half of this technique's sub-techniques, without additional coverage of procedure examples, resulting in an overall score of Minimal.|
|[T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)|Detect|Minimal|This control provides minimal to partial coverage for a minority of this technique's sub-techniques, resulting in an overall detection score of Minimal.|
|[T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)|Protect|Minimal|This control provides a highly specific detection for a misconfiguration that can lead to one of this technique's sub-techniques, ultimately preventing it.|
|[T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)|Detect|Minimal|This control can identify one of this technique's sub-techniques when executed via "Powershell Empire cmdlets seen in command line", but does not address other procedures.|
|[T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)|Detect|Minimal|The Azure Sentinel Hunting "Azure DevOps Conditional Access Disabled" query can identify potentially malicious modifications of the DevOps access policy.<br/>The Azure Sentinel Analytics "MFA disabled for a user" and "GitHub Two Factor Auth Disable" queries can detect potentially malicious changes in multi-factor authentication settings.|
|[T1557 - Man-in-the-Middle](https://attack.mitre.org/techniques/T1557/)|Detect|Minimal|This control can identify one of this technique's sub-techniques when executed via "Powershell Empire cmdlets seen in command line", but does not address other procedures.|
|[T1558 - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/)|Detect|Minimal|This control only provides minimal to partial coverage for some this technique's sub-techniques, resulting in an overall score of Minimal.|
|[T1560 - Archive Collected Data](https://attack.mitre.org/techniques/T1560/)|Detect|Minimal|The Azure Sentinel Analytics "Powershell Empire cmdlets seen in command line" query can detect the use of Empire, which can ZIP directories on target systems, but does not address other procedures.|
|[T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/)|Detect|Minimal|This control provides minimal (mostly) to partial coverage for most of this technique's sub-techniques, resulting in an overall score of Minimal.<br/>The Azure Sentinel Hunting "Anomalous Defensive Mechanism Modification" query detects users performing delete operations on security policies, which may indicate an adversary attempting to impair defenses.|
|[T1567 - Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)|Detect|Minimal|This control provides minimal coverage to both of this technique's sub-techniques as well as some of its procedure examples, resulting in an overall score of Minimal.<br/>The Azure Sentinel Analytics "Malformed user agent" query can detect potential exfiltration over a web service by malicious code with a hard-coded user agent string, or possibly data encoded via the user agent string.|
|[T1568 - Dynamic Resolution](https://attack.mitre.org/techniques/T1568/)|Detect|Minimal|This control only provides partial coverage for one of this technique's sub-techniques, resulting in an overall score of Minimal.|
|[T1569 - System Services](https://attack.mitre.org/techniques/T1569/)|Detect|Minimal|This control can identify one of this technique's sub-techniques when executed via "Powershell Empire cmdlets seen in command line", but does not address other procedures.|
|[T1573 - Encrypted Channel](https://attack.mitre.org/techniques/T1573/)|Detect|Minimal|This control provides minimal coverage for one sub-technique of this technique, resulting in an overall coverage score of Minimal.|
|[T1574 - Hijack Execution Flow](https://attack.mitre.org/techniques/T1574/)|Detect|Minimal|This control can identify several of this technique's sub-techniques when executed via "Powershell Empire cmdlets seen in command line", but does not address other procedures.|
|[T1578 - Modify Cloud Compute Infrastructure](https://attack.mitre.org/techniques/T1578/)|Detect|Minimal|The Azure Sentinel Hunting "Azure Resources assigned Public IP addresses" query detect suspicious IP address changes.|
|[T1580 - Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/)|Detect|Minimal|The Azure Sentinel Hunting "Azure storage key enumeration" query can identify potential attempts by an attacker to discover cloud infrastructure resources.|
|[T1590 - Gather Victim Network Information](https://attack.mitre.org/techniques/T1590/)|Detect|Minimal|This control detects a highly specific behavior that applies to one sub-technique of this technique.|
|[T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)|Detect|Minimal|The Azure Sentinel Analytics "Malformed user agent" query can detect hard-coded user-agent strings associated with some vulnerability scanning tools.<br/>This control provides partial coverage for only one of this technique's sub-techniques, resulting in an overall score of Minimal.|
  


### Tag(s)
- [Analytics](#2-analytics)
- [Threat Hunting](#19-threat-hunting)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/sentinel/overview>
- <https://docs.microsoft.com/en-us/azure/sentinel/hunting>
  

  [Back to Table Of Contents](#contents)
## 32. Azure VPN Gateway


A VPN gateway is a specific type of virtual network gateway that is used to send encrypted traffic between an Azure virtual network and an on-premises location over the public Internet. 
You can also use a VPN gateway to send encrypted traffic between Azure virtual networks over the Microsoft network.

- [Mapping File](AzureVPN.yaml) ([YAML](AzureVPN.yaml))
- [Navigator Layer](layers/AzureVPN.json) ([JSON](layers/AzureVPN.json))

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)|Protect|Significant|This control encrypts traffic traversing over untrusted networks which can prevent information from being gathered via network sniffing.|
|[T1557 - Man-in-the-Middle](https://attack.mitre.org/techniques/T1557/)|Protect|Significant|This control can mitigate Man-in-the-Middle attacks that manipulate network protocol data in transit.|
|[T1565 - Data Manipulation](https://attack.mitre.org/techniques/T1565/)|Protect|Partial|This control provides significant protection against one sub-technique (Transmitted Data Manipulation)  of this technique while not providing protection for its remaining sub-techniques resulting in overall score of Partial.|
  


### Tag(s)
- [Network](#17-network)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-about-vpngateways>
  

  [Back to Table Of Contents](#contents)
## 33. Azure Web Application Firewall


Azure Web Application Firewall (WAF) provides centralized protection of your web applications  from common exploits and vulnerabilities.


- [Mapping File](AzureWebApplicationFirewall.yaml) ([YAML](AzureWebApplicationFirewall.yaml))
- [Navigator Layer](layers/AzureWebApplicationFirewall.json) ([JSON](layers/AzureWebApplicationFirewall.json))

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046/)|Detect|Partial|This control can detect network service scanning of web applications by an adversary. Because this detection is specific to web applications (although frequent targets) and not other application types enumerated in the procedure examples of this technique (e.g. Active Directory), it has been scored as Partial.|
|[T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046/)|Protect|Partial|This control can protect web applications from network service scanning by an adversary. Because this protection is specific to web applications (although frequent targets) and not other application types enumerated in the procedure examples of this technique (e.g. Active Directory), it has been scored as Partial.|
|[T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)|Detect|Minimal|This control can detect one of the sub-techniques of this technique while not providing detection for the remaining, resulting in a Minimal overall score.|
|[T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)|Protect|Minimal|This control can protect against one of the sub-techniques of this technique while not providing protection for the remaining, resulting in a Minimal overall score.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Detect|Significant|This control can detect common web application attack vectors.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Protect|Significant|This control can protect web applications from common attacks (e.g. SQL injection, XSS).|
|[T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)|Protect|Partial|This control can protect web applications from active scanning by an adversary. Because this protection is specific to web applications (although frequent targets) and not other application types, it has been scored as Partial.|
  


### Tag(s)
- [Azure Security Center Recommendation](#8-azure-security-center-recommendation)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/web-application-firewall/overview>
  

  [Back to Table Of Contents](#contents)
## 34. Cloud App Security Policies


Microsoft Cloud App Security is a Cloud Access Security Broker (CASB) that supports various deployment modes including log collection, API connectors, and reverse proxy. It provides rich visibility, control over data travel, and sophisticated analytics to identify and combat cyberthreats across all your Microsoft and third-party cloud services.

- [Mapping File](CloudAppSecurity.yaml) ([YAML](CloudAppSecurity.yaml))
- [Navigator Layer](layers/CloudAppSecurity.json) ([JSON](layers/CloudAppSecurity.json))

### Mapping Comments


This control is basically a CASB, and various features can generate logs and alerts that can be incorporated into a SIEM such as Sentinel for moderate to high temporal score.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)|Detect|Minimal|This control can identify some evidence of potential C2 via a specific application layer protocol (mail). Relevant alerts include  "Suspicious inbox forwarding" and "Suspicious inbox manipulation rule".|
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Detect|Partial|This control can identify anomalous behavior such as geographically impossible logins and out-of-character activity. <br/>Relevant alerts include "Activity from anonymous IP address" , "Activity from infrequent country", "Activity from suspicious IP address", "Impossible Travel", and "Activity performed by terminated user".|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Detect|Minimal|This control can detect anomalous admin activity that may be indicative of account manipulation. Relevant alerts include "Unusual administrative activity (by user)" and "Unusual addition of credentials to an OAuth app".|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Detect|Partial|This control can detect some activity indicative of brute force attempts to login. Relevant alert is "Multiple failed login attempts".|
|[T1119 - Automated Collection](https://attack.mitre.org/techniques/T1119/)|Detect|Partial|This control can detect sensitive information at rest, which may be indicative of data collection activities.|
|[T1119 - Automated Collection](https://attack.mitre.org/techniques/T1119/)|Protect|Partial|This control's Information protection policies can detect and encrypt sensitive information at rest on supported platforms, which can inhibit automated data collection activities.|
|[T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)|Detect|Partial|This control can provide logging of activity associated with potential exploitation of remote services such as anomalous geographic access.|
|[T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)|Protect|Partial|This control's polices for access control can limit abuse of external facing remote services.|
|[T1187 - Forced Authentication](https://attack.mitre.org/techniques/T1187/)|Detect|Significant|This control can alert on anomalous sharing attempts of confidential data.|
|[T1187 - Forced Authentication](https://attack.mitre.org/techniques/T1187/)|Protect|Significant|This control can provide significant protection against forced authentication methods by restricting actions associated with multiple file access methods such as SMB.|
|[T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)|Detect|Partial|This control can detect outdated client browser software, which is a common target of exploitation in drive-by compromises.|
|[T1213 - Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)|Detect|Minimal|This control may detect anomalous user behavior wrt information repositories such as Sharepoint or Confluence.  Due to this capability being limited to these services, it has been scored as Partial coverage resulting in a Partial score.|
|[T1213 - Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)|Protect|Minimal|This control can provide fine-grained access control to information sharing repositories such as Sharepoint or Confluence. Due to this capability being limited to these services, it has been scored as Partial coverage resulting in a Partial score.|
|[T1219 - Remote Access Software](https://attack.mitre.org/techniques/T1219/)|Detect|Partial|This control can identify potential malicious activity associated with the use or attempted use of unapproved remote access software.|
|[T1219 - Remote Access Software](https://attack.mitre.org/techniques/T1219/)|Protect|Significant|This control can limit potential C2 via unapproved remote access software.|
|[T1484 - Domain Policy Modification](https://attack.mitre.org/techniques/T1484/)|Detect|Minimal|This control can detect admin activity from risky IP addresses.|
|[T1485 - Data Destruction](https://attack.mitre.org/techniques/T1485/)|Detect|Partial|This control can identify deletion activity which could be potential malicious data destruction. Relevant Alerts include "Multiple storage deletion activities", "Multiple VM deletion activity", "Unusual file deletion activity (by user), "Suspicous email deletion activiy", and "Ransomware activity".<br/>|
|[T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)|Detect|Partial|This control can detect a range of ransomware-related activities including encryption. Relevant alert include "Ransomware activities" and "Unusual file deletion activity (by user)".|
|[T1496 - Resource Hijacking](https://attack.mitre.org/techniques/T1496/)|Detect|Partial|This control can identify some behaviors that are potential instances of resource hijacking. Relevant alerts include "Multiple VM Creation activities" and "Suspicious creation activity for cloud region".|
|[T1526 - Cloud Service Discovery](https://attack.mitre.org/techniques/T1526/)|Detect|Partial|This control can detect anomalous user activity that may be associated with cloud service discovery. Relevant alert is "Unusual file share activty (by user)".|
|[T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)|Detect|Partial|This control can detect potentially risky apps. Relevant alerts include "Misleading publisher name for an Oauth app" and "Misleading OAuth app name".|
|[T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)|Protect|Partial|This control can restrict user app permissions which can limit the potential for theft of application access tokens.|
|[T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)|Detect|Partial|This control can detect use of unsanctioned business apps and data exfil to unsanctioned storage apps.|
|[T1531 - Account Access Removal](https://attack.mitre.org/techniques/T1531/)|Detect|Minimal|This control can identify anomalous admin activity.|
|[T1534 - Internal Spearphishing](https://attack.mitre.org/techniques/T1534/)|Detect|Minimal|This control can identify anomalous user impersonation activity, which can be an element of internal spearphishing. Relevant alert is "Unusual impersonated activity (by user)".|
|[T1535 - Unused/Unsupported Cloud Regions](https://attack.mitre.org/techniques/T1535/)|Detect|Partial|This control can detect unusual region and activity for cloud resources (preview feature as of this writing).  Relevant alert is "Suspicious creation activity for cloud region".|
|[T1565 - Data Manipulation](https://attack.mitre.org/techniques/T1565/)|Protect|Partial|This control can detect and encrypt sensitive information at rest on supported platforms and restrict access.|
|[T1567 - Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)|Detect|Partial|This control can identify large volume potential exfiltration activity, and log user activity potentially related to exfiltration via web services. A relevant alert is "Unusual file download (by user)".|
|[T1567 - Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)|Protect|Partial|This control can limit user methods to send data over web services.|
|[T1578 - Modify Cloud Compute Infrastructure](https://attack.mitre.org/techniques/T1578/)|Detect|Minimal|This control can identify anomalous admin activity.<br/>Relevant alerts include "Multiple storage deletion activities", "Multiple VM creation activities", and "Suspicious creation activity for cloud region".|
  


### Reference(s)
- <https://docs.microsoft.com/en-us/cloud-app-security/policies-cloud-discovery>
- <https://docs.microsoft.com/en-us/cloud-app-security/policies-information-protection>
- <https://docs.microsoft.com/en-us/cloud-app-security/investigate-anomaly-alerts>
  

  [Back to Table Of Contents](#contents)
## 35. Conditional Access


"Conditional access enables organizations to configure and fine-tune access policies with contextual factors such as user, device, location, and real-time risk information to control what a specific user can access, and how and when they have access."

- [Mapping File](ConditionalAccess.yaml) ([YAML](ConditionalAccess.yaml))
- [Navigator Layer](layers/ConditionalAccess.json) ([JSON](layers/ConditionalAccess.json))

### Mapping Comments


At first glance, this control seems mappable to Exfiltration (sub-)techniques but upon further analysis, it doesn't really mitigate exfiltration but rather its prerequisite Collection (sub-)techniques.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1074 - Data Staged](https://attack.mitre.org/techniques/T1074/)|Protect|Minimal|This control only provides the ability to restrict file downloads for a limited set of applications and therefore its overall Coverage score is minimal.|
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Protect|Minimal|This control only provides minimal protection for this technique's procedure examples along and also only protects one of its sub-techniques resulting in an overall Minimal score.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Protect|Significant|Conditional Access can be used to enforce MFA for users which provides significant protection against  password compromises, requiring an adversary to complete an additional authentication method before their access is permitted.|
|[T1213 - Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)|Protect|Minimal|This control only provides the ability to restrict an adversary from collecting valuable information for a limited set of applications (SharePoint, Exchange, OneDrive) and therefore its overall Coverage score is minimal.|
|[T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)|Protect|Minimal|Conditional Access, when granting (risky) users access to cloud storage, specifically OneDrive, can restrict what they can do in these applications using its app-enforced restrictions.   For example, it can enforce that users on unmanaged devices will have browser-only access to OneDrive with no ability to download, print, or sync files.  This can impede an adversary's ability to exfiltrate data from OneDrive.  The protection coverage provided by this control is Minimal as it doesn't provide protection for other storage services available on Azure such as the Azure Storage service.|
  


### Tag(s)
- [Azure Active Directory](#3-azure-active-directory)
- [Identity](#13-identity)
- [MFA](#15-mfa)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/overview>
  

  [Back to Table Of Contents](#contents)
## 36. Continuous Access Evaluation


Continuous Access Evaluation (CAE) provides the next level of identity security by terminating active user sessions to a subset of Microsoft services (Exchange and Teams) in real-time on changes such as account disable, password reset, and admin initiated user revocation.  CAE aims to improve the response time in situations where a policy setting that applies to a user changes but the user is able to circumvent the new policy setting because their OAuth access token was issued before the policy change.  It's typical that security access tokens issued by Azure AD, like OAuth 2.0 access tokens, are valid for an hour.
CAE enables the scenario where users lose access to organizational SharePoint Online files, email, calendar, or tasks, and Teams from Microsoft 365 client apps within minutes after critical security events (such as user account is deleted, MFA is enabled for a user, High user risk detected by Azure AD Identity Protection, etc.).

- [Mapping File](ContinuousAccessEvaluation.yaml) ([YAML](ContinuousAccessEvaluation.yaml))
- [Navigator Layer](layers/ContinuousAccessEvaluation.json) ([JSON](layers/ContinuousAccessEvaluation.json))

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Respond|Minimal|This control only protects cloud accounts and therefore its overall coverage is minimal resulting in a Minimal respond score for this technique.|
  


### Tag(s)
- [Azure Active Directory](#3-azure-active-directory)
- [Identity](#13-identity)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/concept-continuous-access-evaluation>
  

  [Back to Table Of Contents](#contents)
## 37. Docker Host Hardening


Azure Security Center identifies unmanaged containers hosted on IaaS Linux VMs, or other Linux machines running Docker containers. Security Center continuously assesses the configurations of these containers. It then compares them with the Center for Internet Security (CIS) Docker Benchmark. Security Center includes the entire ruleset of the CIS Docker Benchmark and alerts you if your containers don't satisfy any of the controls. When it finds misconfigurations, Security Center generates security recommendations.

- [Mapping File](DockerHostHardening.yaml) ([YAML](DockerHostHardening.yaml))
- [Navigator Layer](layers/DockerHostHardening.json) ([JSON](layers/DockerHostHardening.json))

### Mapping Comments


All scores are capped at Partial since this control provides recommendations rather than applying/enforcing the recommended actions.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1005 - Data from Local System](https://attack.mitre.org/techniques/T1005/)|Protect|Minimal|This control may provide recommendations that limit the ability of an attacker to gain access to a host from a container, preventing the attacker from discovering and compromising local system data.|
|[T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)|Protect|Minimal||
|[T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)|Protect|Minimal|This control may recommend usage of TLS to encrypt communication between the Docker daemon and clients. This can prevent possible leakage of sensitive information through network sniffing.|
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Protect|Minimal|This control may provide recommendations on how to reduce the surface area and mechanisms by which an attacker could escalate privileges.|
|[T1083 - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)|Protect|Minimal|This control may provide recommendations to ensure sensitive host system directories are not mounted in the container.|
|[T1525 - Implant Container Image](https://attack.mitre.org/techniques/T1525/)|Detect|Minimal|This control may alert on Docker containers that are misconfigured or do not conform to CIS Docker Benchmarks. This may result in detection of container images implanted within Linux VMs with specific vulnerabilities or misconfigurations for malicious purposes.|
|[T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)|Protect|Minimal|This control is only relevant for Linux endpoints containing Docker containers.|
  


### Tag(s)
- [Azure Security Center](#7-azure-security-center)
- [Containers](#9-containers)
- [Linux](#14-linux)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/harden-docker-hosts>
  

  [Back to Table Of Contents](#contents)
## 38. File Integrity Monitoring


File integrity monitoring (FIM), also known as change monitoring, examines operating system files, Windows registries, application software, Linux system files, and more, for changes that might indicate an attack. File Integrity Monitoring (FIM) informs you when changes occur to sensitive areas in your resources, so you can investigate and address unauthorized activity. 


- [Mapping File](FileIntegrityMonitoring.yaml) ([YAML](FileIntegrityMonitoring.yaml))
- [Navigator Layer](layers/FileIntegrityMonitoring.json) ([JSON](layers/FileIntegrityMonitoring.json))

### Mapping Comments


The techniques included in this mapping result in Windows Registry or file system artifacts being created or modified which can be detected by this control.  
The detection score for most techniques included in this mapping was scored as Significant and where there are exceptions, comments have been provided. This Significant score assessment  was due to the following factors: Coverage - (High) The control was able to detect most of the sub-techniques, references and procedure examples of the mapped techniques. Accuracy - (High) Although this control does not include built-in intelligence to minimize  the false positive rate, the specific artifacts generated by the techniques in this mapping do not change frequently and therefore the potential for a high false-positive is reduced.  Temporal - (Medium) This control at worst scans for changes on an hourly basis.
  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)|Detect|Minimal|Most credential dumping operations do not require modifying resources that can be detected by this control (i.e. Registry and File system) and therefore its coverage is minimal.|
|[T1037 - Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1037/)|Detect|Partial||
|[T1053 - Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)|Detect|Significant||
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Detect|Minimal||
|[T1137 - Office Application Startup](https://attack.mitre.org/techniques/T1137/)|Detect|Minimal||
|[T1222 - File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222/)|Detect|Partial||
|[T1543 - Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)|Detect|Partial||
|[T1546 - Event Triggered Execution](https://attack.mitre.org/techniques/T1546/)|Detect|Partial|The detection score for this technique was assessed as Partial because it doesn't detect some of the sub-techniques of this technique such as Windows Management Instrumentation (WMI) Event Subscription and Trap sub-techniques. Additionally for some sub-techniques, this control can be noisy.<br/>|
|[T1547 - Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)|Detect|Partial||
|[T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)|Detect|Minimal||
|[T1553 - Subvert Trust Controls](https://attack.mitre.org/techniques/T1553/)|Detect|Partial|This control can be used to detect a subset of this technique's sub-techniques while minimizing the false positive rate.|
|[T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)|Detect|Partial|This control is effective for detecting the Registry and file system artifacts that are generated during the execution of some variations of this technique while minimizing false positives due to the locations being monitored changing infrequently (e.g. /etc/pam.d/).|
|[T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/)|Detect|Minimal|Due to low detection coverage, this technique is scored as minimal.|
|[T1574 - Hijack Execution Flow](https://attack.mitre.org/techniques/T1574/)|Detect|Minimal||
  


### Tag(s)
- [Azure Defender](#4-azure-defender)
- [Azure Defender for Servers](#6-azure-defender-for-servers)
- [Azure Security Center](#7-azure-security-center)
- [Azure Security Center Recommendation](#8-azure-security-center-recommendation)
- [Linux](#14-linux)
- [Windows](#20-windows)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/security-center-file-integrity-monitoring>
  

  [Back to Table Of Contents](#contents)
## 39. Integrated Vulnerability Scanner Powered by Qualys


This control provides a on-demand and scheduled vulnerability scan for Windows and Linux endpoints that are being protected by Azure Defender. The scanner generates a list of possible vulnerabilities in Azure Security Center for possible remediation. 

- [Mapping File](VulnerabilityAssessmentQualys.yaml) ([YAML](VulnerabilityAssessmentQualys.yaml))
- [Navigator Layer](layers/VulnerabilityAssessmentQualys.json) ([JSON](layers/VulnerabilityAssessmentQualys.json))

### Mapping Comments


Once this control is deployed, it will run a scan every four hours and scans can be run on demand. Documentation notes that within 48 hours of the disclosure of a critical vulnerability, Qualys incorporates the information into their processing and can identify affected machines.
All scores are capped at Partial since this control identifies vulnerabilities and does not address the detected vulnerabilities.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Protect|Partial|Once this control is deployed, it can detect known vulnerabilities in Windows and various Linux endpoints. This information can be used to patch, isolate, or remove vulnerable software and machines. This control does not directly protect against exploitation and it is not effective against zero day attacks, vulnerabilities with no available patch, and software that may not be analyzed by the scanner. As a result, the score is capped at Partial.|
|[T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)|Protect|Partial|Once this control is deployed, it can detect known vulnerabilities in Windows and various Linux endpoints. This information can be used to patch, isolate, or remove vulnerable software and machines. This control does not directly protect against exploitation and it is not effective against zero day attacks, vulnerabilities with no available patch, and software that may not be analyzed by the scanner. As a result, the score is capped at Partial.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Protect|Partial|Once this control is deployed, it can detect known vulnerabilities in Windows and various Linux endpoints. This information can be used to patch, isolate, or remove vulnerable software and machines. This control does not directly protect against exploitation and it is not effective against zero day attacks, vulnerabilities with no available patch, and software that may not be analyzed by the scanner. As a result, the score is capped at Partial.|
|[T1203 - Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)|Protect|Partial|Once this control is deployed, it can detect known vulnerabilities in Windows and various Linux endpoints. This information can be used to patch, isolate, or remove vulnerable software and machines. This control does not directly protect against exploitation and it is not effective against zero day attacks, vulnerabilities with no available patch, and software that may not be analyzed by the scanner. As a result, the score is capped at Partial.|
|[T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)|Protect|Partial|Once this control is deployed, it can detect known vulnerabilities in Windows and various Linux endpoints. This information can be used to patch, isolate, or remove vulnerable software and machines. This control does not directly protect against exploitation and it is not effective against zero day attacks, vulnerabilities with no available patch, and software that may not be analyzed by the scanner. As a result, the score is capped at Partial.|
|[T1211 - Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211/)|Protect|Partial|Once this control is deployed, it can detect known vulnerabilities in Windows and various Linux endpoints. This information can be used to patch, isolate, or remove vulnerable software and machines. This control does not directly protect against exploitation and it is not effective against zero day attacks, vulnerabilities with no available patch, and software that may not be analyzed by the scanner. As a result, the score is capped at Partial.|
|[T1212 - Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212/)|Protect|Partial|Once this control is deployed, it can detect known vulnerabilities in Windows and various Linux endpoints. This information can be used to patch, isolate, or remove vulnerable software and machines. This control does not directly protect against exploitation and it is not effective against zero day attacks, vulnerabilities with no available patch, and software that may not be analyzed by the scanner. As a result, the score is capped at Partial.|
  


### Tag(s)
- [Azure Defender](#4-azure-defender)
- [Azure Security Center](#7-azure-security-center)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/deploy-vulnerability-assessment-vm>
- <https://docs.microsoft.com/en-us/azure/security-center/remediate-vulnerability-findings-vm>
  

  [Back to Table Of Contents](#contents)
## 40. Just-in-Time VM Access


This control locks down inbound traffic to management ports for protocols such as RDP and SSH and only provides access upon request for a specified period of time. This reduces exposure to attacks while providing easy access when you need to connect to a virtual machine. Specific permissions are required to request access to virtual machines that have this control enabled and access can be requested through the Azure web UI, PowerShell, and a REST API.

- [Mapping File](JustInTimeVMAccess.yaml) ([YAML](JustInTimeVMAccess.yaml))
- [Navigator Layer](layers/JustInTimeVMAccess.json) ([JSON](layers/JustInTimeVMAccess.json))

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Protect|Significant|This control can be configured to completely block inbound access to selected ports until access is requested. This prevents any attempt at brute forcing a protocol, such as RDP or SSH, unless the attacker has the credentials and permissions to request such access. Even if permission has been granted to an authorized user to access the virtual machine, a list of authorized IP addresses for that access can be configured.|
|[T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)|Protect|Significant|This control can be configured to completely block inbound access to selected ports until access is requested. This prevents any attempt at utilizing external remote services, such as RDP or a VPN, unless the attacker has the credentials and permissions to request such access. Even if permission has been granted to an authorized user to access the virtual machine, a list of authorized IP addresses for that access can be configured.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Protect|Minimal|This control can be configured to completely block inbound access to selected ports until access is requested. This prevents any attempt at exploitation of a public-facing application unless the attacker has the credentials and permissions to request such access. Even if permission has been granted to an authorized user to access the virtual machine, a list of authorized IP addresses for that access can be configured. The score is minimal, since this control only applies to specific applications requiring credentialed access, as opposed to a public webserver|
  


### Tag(s)
- [Azure Defender for Servers](#6-azure-defender-for-servers)
- [Azure Security Center](#7-azure-security-center)
- [Azure Security Center Recommendation](#8-azure-security-center-recommendation)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/security-center-just-in-time?tabs=jit-config-asc%2Cjit-request-api>
- <https://docs.microsoft.com/en-us/azure/security-center/just-in-time-explained>
  

  [Back to Table Of Contents](#contents)
## 41. Linux auditd alerts and Log Analytics agent integration


This integration enables collection of auditd events in all supported Linux distributions, without any prerequisites. Auditd records are collected, enriched, and aggregated into events by using the Log Analytics agent for Linux agent.

- [Mapping File](LinuxAuditdAndLogAnalytics.yaml) ([YAML](LinuxAuditdAndLogAnalytics.yaml))
- [Navigator Layer](layers/LinuxAuditdAndLogAnalytics.json) ([JSON](layers/LinuxAuditdAndLogAnalytics.json))

### Mapping Comments


Detections are periodic at an unknown rate.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)|Detect|Partial|This control is only relevant for Linux environments, and provides partial coverage for one of the technique's two Linux-relevant sub-techniques.|
|[T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)|Detect|Minimal|This control is only relevant for Linux environments. Among the sub-techinques that are relevant for Linux, this control may only alert on SSH.|
|[T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)|Detect|Minimal|This control only provides detection coverage for the Compile After Delivery sub-technique while not providing detection for all other sub-techniques relevant to the Linux platform or most of its procedure examples. As a result of this minimal coverage, the overall score is assessed as Minimal.|
|[T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)|Detect|Minimal|This control may alert on suspicious Unix shell and PHP execution. Mismatched script extensions may also generate alerts of suspicious activity. Only one of the technique's sub-techniques is covered, resulting in a score of Minimal.|
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Detect|Minimal|This control may alert on suspicious arguments used to exploit Xorg vulnerabilities for privilege escalation.|
|[T1070 - Indicator Removal on Host](https://attack.mitre.org/techniques/T1070/)|Detect|Partial|This control is only relevant for Linux environments and provides partial coverage for multiple Linux-relevant sub-techniques.|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Detect|Minimal|This control provides partial detection for only one of this technique's sub-techniques and does not cover most of its procedure examples, resulting in a score of Minimal.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Detect|Partial|This control provides partial coverage for most of this technique's sub-techniques and procedures.|
|[T1113 - Screen Capture](https://attack.mitre.org/techniques/T1113/)|Detect|Partial|This control may alert on usage of a screenshot tool. Documentation is not provided on the logic for determining a screenshot tool.|
|[T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)|Detect|Minimal|This control is only relevant for Linux endpoints, and it provides partial coverage for the only sub-technique relevant on Linux endpoints, Local Account.|
|[T1505 - Server Software Component](https://attack.mitre.org/techniques/T1505/)|Detect|Minimal|This control provides coverage for the only sub-technique this control is relevant for, Web Shell, but that coverage is Minimal.|
|[T1525 - Implant Container Image](https://attack.mitre.org/techniques/T1525/)|Detect|Partial|This control may alert on suspicious container images running mining software or SSH servers. Privileged Docker containers and privileged commands running within containers may also be detected. These alerts are only generated on containers in Linux endpoint machines and not for containers running from Azure Docker deployment.|
|[T1547 - Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)|Detect|Minimal|This control is only relevant for Linux endpoint machines and the only sub-technique relevant for Linux is Kernel Modules and Extensions.|
|[T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/)|Detect|Minimal|This control only provides coverage for a miniority of the sub-techniques under this technique and provides no coverage for other relevant sub-techniques, such as Impair Command History Logging or Disable or Modify Tools, resulting in a score of Minimal.|
|[T1564 - Hide Artifacts](https://attack.mitre.org/techniques/T1564/)|Detect|Minimal|This control only provides coverage for a minority of this technique's relevant sub-techniques, resulting in a score of Minimal.|
  


### Tag(s)
- [Azure Defender](#4-azure-defender)
- [Linux](#14-linux)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/defender-for-servers-introduction>
- <https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-linux>
  

  [Back to Table Of Contents](#contents)
## 42. Managed identities for Azure resources


Managed identities for Azure resources provide Azure services with an automatically managed identity in Azure Active Directory. You can use this identity to authenticate to any service that supports Azure AD authentication, without having to hard-code credentials in your code.

- [Mapping File](AzureADManagedIdentities.yaml) ([YAML](AzureADManagedIdentities.yaml))
- [Navigator Layer](layers/AzureADManagedIdentities.json) ([JSON](layers/AzureADManagedIdentities.json))

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)|Protect|Minimal|This control provides protection for one of this technique's sub-techniques, while not providing any protection for its procedure examples nor its remaining sub-techniques, resulting in an overall Minimal score.|
  


### Tag(s)
- [Azure Active Directory](#3-azure-active-directory)
- [Azure Security Center Recommendation](#8-azure-security-center-recommendation)
- [Identity](#13-identity)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview>
  

  [Back to Table Of Contents](#contents)
## 43. Microsoft Antimalware for Azure


Microsoft Antimalware for Azure is a free real-time protection that helps identify and remove viruses, spyware, and other malicious software. It generates alerts when known malicious or unwanted software tries to install itself or run on your Azure systems. 

- [Mapping File](MicrosoftAntimalwareForAzure.yaml) ([YAML](MicrosoftAntimalwareForAzure.yaml))
- [Navigator Layer](layers/MicrosoftAntimalwareForAzure.json) ([JSON](layers/MicrosoftAntimalwareForAzure.json))

### Mapping Comments


Signature based antimalware solutions are generally dependent on Indicators of Compromise(IOCs) such as file hashes and malware signatures. ATT&CK is primarily centered on behaviors and Tactics, Techniques, and Procedures(TTPs), hence the minimal amount of techinques and scoring.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)|Detect|Minimal||
|[T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)|Protect|Minimal||
|[T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)|Detect|Minimal|This control may scan created files for malware. This control is dependent on a signature being available.|
|[T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)|Protect|Minimal|This control may scan created files for malware and proceed to quarantine and/or delete the file. This control is dependent on a signature being available.|
|[T1204 - User Execution](https://attack.mitre.org/techniques/T1204/)|Protect|Minimal||
|[T1566 - Phishing](https://attack.mitre.org/techniques/T1566/)|Detect|Minimal||
|[T1566 - Phishing](https://attack.mitre.org/techniques/T1566/)|Protect|Minimal||
  


### Tag(s)
- [Azure Security Center](#7-azure-security-center)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security/fundamentals/antimalware>
- <https://docs.microsoft.com/en-us/azure/security/fundamentals/antimalware-code-samples>
  

  [Back to Table Of Contents](#contents)
## 44. Microsoft Defender for Identity


Microsoft Defender for Identity (formerly Azure Advanced Threat Protection, also known as Azure ATP) is a cloud-based security solution that leverages your on-premises Active Directory signals to identify, detect, and investigate advanced threats, compromised identities, and malicious insider actions directed at your organization.

- [Mapping File](MicrosoftDefenderForIdentity.yaml) ([YAML](MicrosoftDefenderForIdentity.yaml))
- [Navigator Layer](layers/MicrosoftDefenderForIdentity.json) ([JSON](layers/MicrosoftDefenderForIdentity.json))

### Mapping Comments


Understandably (to avoid enabling adversaries to circumvent the detection), many of the detections provided by this control do not provide a detailed description of the detection logic making it often times difficult to map to ATT&CK Techniques.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)|Detect|Minimal|This control provides significant and partial detection for a few of this technique's sub-techniques, while not providing any detection for the remaining, resulting in a Minimal coverage score.|
|[T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)|Detect|Minimal|This control provides Minimal detection for one of this technique's sub-techniques, while not providing any detection for the remaining, resulting in a Minimal score.|
|[T1047 - Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)|Detect|Minimal|This control's "Remote code execution attempt (external ID 2019)" alert can detect Remote code execution via WMI.  This may lead to false positives as administrative workstations, IT team members, and service accounts can all perform legitimate administrative tasks against domain controllers.  Additionally, this alert seems to be specific to detecting execution on domain controllers and AD FS servers, limiting its coverage.<br/>|
|[T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)|Detect|Minimal|This control provides Partial detection for one of this technique's sub-techniques, while not providing any detection for the remaining, resulting in a Minimal score.|
|[T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)|Detect|Minimal|This control provides Minimal detection for one of this technique's sub-techniques, while not providing any detection for the remaining, resulting in a Minimal score.|
|[T1069 - Permission Groups Discovery](https://attack.mitre.org/techniques/T1069/)|Detect|Minimal|This control provides significant detection for one of this technique's sub-techniques, while not providing any detection for the remaining, resulting in a Minimal score.|
|[T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)|Detect|Minimal|This control provides Partial detection for one of this technique's sub-techniques, while not providing any detection for the remaining, resulting in a Minimal score.|
|[T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)|Detect|Minimal|This control provides significant detection for one of this technique's sub-techniques, while not providing any detection for the remaining, resulting in a Minimal score.|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Detect|Partial|This controls's "Suspicious additions to sensitive groups (external ID 2024)" alert can utilize machine learning to detect when an attacker adds users to highly privileged groups. Adding users is done to gain access to more resources, and gain persistency.  This detection relies on profiling the group modification activities of users, and alerting when an abnormal addition to a sensitive group is observed. Defender for Identity profiles continuously. <br/>This alert provides Partial coverage of this technique with a reduced false-positive rate by utilizing machine learning models.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Detect|Partial|This control provides significant detection of some of the sub-techniques of this technique and has therefore been assessed an overall score of Partial.|
|[T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)|Detect|Minimal|This control's "Suspicious VPN connection (external ID 2025)" alert utilizes machine learning models to learn  normal VPN connections for a user and detect deviations from the norm.  This detection is specific to VPN traffic and therefore its overall coverage is Minimal.|
|[T1201 - Password Policy Discovery](https://attack.mitre.org/techniques/T1201/)|Detect|Minimal|This control's "Active Directory attributes reconnaissance (LDAP) (external ID 2210)" alert may be able to detect this operation.  There are statements in the documentation for the alert, such as: "Active Directory LDAP reconnaissance is used by attackers to gain critical information about the domain environment. This information can help attackers map the domain structure ...", that  may indicate support for detecting this technique.  The level of detection though is unknown and therefore a conservative assessment of a Minimal score is assigned.|
|[T1207 - Rogue Domain Controller](https://attack.mitre.org/techniques/T1207/)|Detect|Significant|This control's "Suspected DCShadow attack (domain controller promotion) (external ID 2028)" and "Suspected DCShadow attack (domain controller replication request) (external ID 2029)" alerts can detect this technique.  Also should be a low false positive rate as the quantity and identity of domain controllers on the network should change very infrequently.|
|[T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)|Detect|Minimal|This control's "Remote code execution over DNS (external ID 2036)" alert can look for an attacker attempting to exploit CVE-2018-8626, a remote code execution vulnerability exists in Windows Domain Name System (DNS) servers.  In this detection, a Defender for Identity security alert is triggered when DNS queries suspected of exploiting the CVE-2018-8626 security vulnerability are made against a domain controller in the network.  <br/>Likewise this controls "Suspected SMB packet manipulation (CVE-2020-0796 exploitation)" alert can detect a remote code execution vulnerability with SMBv3.<br/>Because these detections are specific to a few CVEs, its coverage is Minimal resulting in a Minimal score.|
|[T1482 - Domain Trust Discovery](https://attack.mitre.org/techniques/T1482/)|Detect|Minimal|This control's "Active Directory attributes reconnaissance (LDAP) (external ID 2210)" alert may be able to detect this operation.  There are statements in the documentation for the alert, such as: "Active Directory LDAP reconnaissance is used by attackers to gain critical information about the domain environment. This information can help attackers map the domain structure ...", that  may indicate support for detecting this technique.  The level of detection though is unknown and therefore a conservative assessment of a Minimal score is assigned.|
|[T1543 - Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)|Detect|Minimal|This control provides minimal detection for one of this technique's sub-techniques, while not providing any detection for the remaining, resulting in a Minimal score.|
|[T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)|Detect|Partial|This control provides partial detection for some of this technique's sub-techniques  (due to unknown false-positive/true-positive rate), resulting in a Partial score.|
|[T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)|Detect|Minimal|This control provides minimal detection for one of this technique's sub-techniques, while not providing any detection for the remaining, resulting in a Minimal score.|
|[T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)|Detect|Minimal|This control provides minimal detection for one of this technique's sub-techniques, while not providing any detection for the remaining, resulting in a Minimal score.|
|[T1557 - Man-in-the-Middle](https://attack.mitre.org/techniques/T1557/)|Detect|Minimal|This control provides minimal detection for one of this technique's sub-techniques, while not providing any detection for the other, resulting in an overall Minimal score.|
|[T1558 - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/)|Detect|Partial|This control provides partial detection for most of this technique's sub-techniques, resulting in an overall Partial score.|
|[T1569 - System Services](https://attack.mitre.org/techniques/T1569/)|Detect|Minimal|This control provides Minimal detection for one of this technique's sub-techniques, while not providing any detection for the remaining, resulting in a Minimal score.|
  


### Tag(s)
- [Credentials](#10-credentials)
- [DNS](#11-dns)
- [Identity](#13-identity)
- [Microsoft 365 Defender](#16-microsoft-365-defender)
- [Windows](#20-windows)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/defender-for-identity/what-is>
  

  [Back to Table Of Contents](#contents)
## 45. Network Security Groups


You can use an Azure network security group to filter network traffic to and from Azure resources in an Azure virtual network. A network security group contains security rules that allow or deny inbound network traffic to, or outbound network traffic from, several types of Azure resources. For each rule, you can specify source and destination, port, and protocol.

- [Mapping File](NetworkSecurityGroups.yaml) ([YAML](NetworkSecurityGroups.yaml))
- [Navigator Layer](layers/NetworkSecurityGroups.json) ([JSON](layers/NetworkSecurityGroups.json))

### Mapping Comments


Note: one can employ Application Security Groups (ASG) in Network Security Group (NSG) rules to map  rules to workloads etc. Not scoring ASG as a separate control. One can employ Adaptive Network Hardening (ANH)  to generate recommended NSG rules based on traffic, known trusted configuration, threat intelligence, and other inidcators of compromise. Not scoring ANH as a separate control.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)|Protect|Partial|This control provides partial protection for all of its sub-techniques and procedure examples resulting in an overall score of Partial.|
|[T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046/)|Protect|Partial|This control can be used to restrict access to trusted networks.|
|[T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)|Protect|Significant|NSG can minimize alternative protocols allowed to communicate externally.|
|[T1072 - Software Deployment Tools](https://attack.mitre.org/techniques/T1072/)|Protect|Partial|This control can be used to limit access to critical network systems such as software deployment tools.|
|[T1090 - Proxy](https://attack.mitre.org/techniques/T1090/)|Protect|Partial|This control can restrict ports and inter-system / inter-enclave connections as described by the Proxy related sub-techniques although it doesn't provide protection for domain-fronting.  It furthermore provides partial protection of this technique's procedure examples resulting in an overall Partial score.|
|[T1095 - Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1095/)|Protect|Partial|This control can be used to restrict access to trusted networks and protocols.|
|[T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)|Protect|Partial|This control can be used to restrict direct access to remote service gateways and concentrators that typically accompany external remote services.  This can be circumvented though if an adversary is able to compromise a trusted host and use it to access the external remote service. This results in an overall partial (coverage) score.|
|[T1199 - Trusted Relationship](https://attack.mitre.org/techniques/T1199/)|Protect|Partial|This control can isolate portions of network that do not require network-wide access, limiting some attackers that leverage trusted relationships such as remote access for vendor maintenance. Coverage partial, Temporal Immediate.|
|[T1205 - Traffic Signaling](https://attack.mitre.org/techniques/T1205/)|Protect|Partial|This control provides partial protection for this technique's sub-techniques and procedure examples resulting in an overall Partial score.  Other variations that trigger a special response, such as executing a malicous task are not mitigated by this control.|
|[T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)|Protect|Partial|This control can be used to restrict access to remote services to minimum necessary.|
|[T1219 - Remote Access Software](https://attack.mitre.org/techniques/T1219/)|Protect|Partial|This control can be used to restrict network communications to protect sensitive enclaves that may mitigate some of the procedure examples of this technique.|
|[T1482 - Domain Trust Discovery](https://attack.mitre.org/techniques/T1482/)|Protect|Partial|This control can be used to isolate sensitive domains to limit discovery.|
|[T1498 - Network Denial of Service](https://attack.mitre.org/techniques/T1498/)|Protect|Partial|This control can be used to restrict access to endpoints and thereby mitigate low-end network DOS attacks.|
|[T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)|Protect|Partial|This control provides partial protection for a majority of this control's sub-techinques and procedure examples resulting in overall score of Partial.|
|[T1542 - Pre-OS Boot](https://attack.mitre.org/techniques/T1542/)|Protect|Minimal|Provides protection coverage for only one sub-technique partially (booting from remote devies ala TFTP boot) resulting in an overall score of Minimal.|
|[T1557 - Man-in-the-Middle](https://attack.mitre.org/techniques/T1557/)|Protect|Partial|This control can be used to limit access to network infrastructure and resources that can be used to reshape traffic or otherwise produce MiTM conditions.|
|[T1570 - Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/)|Protect|Partial|This control can be used to limit traffic between systems and enclaves to minimum necessary for example via a zero-trust strategy.|
|[T1571 - Non-Standard Port](https://attack.mitre.org/techniques/T1571/)|Protect|Significant|This control can restrict traffic to standard ports and protocols.|
|[T1602 - Data from Configuration Repository](https://attack.mitre.org/techniques/T1602/)|Protect|Partial|This control can limit attackers access to configuration repositories such as SNMP management stations, or to dumps of client configurations from common management ports.|
  


### Tag(s)
- [Adaptive Network Hardening](#1-adaptive-network-hardening)
- [Azure Security Center Recommendation](#8-azure-security-center-recommendation)
- [Network](#17-network)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview>
- <https://docs.microsoft.com/en-us/azure/virtual-network/network-security-group-how-it-works>
- <https://docs.microsoft.com/en-us/azure/security-center/security-center-adaptive-network-hardening>
  

  [Back to Table Of Contents](#contents)
## 46. Passwordless Authentication


Features like multi-factor authentication (MFA) are a great way to secure your organization, but users often get frustrated with the additional security layer on top of having to remember their passwords. Passwordless authentication methods are more convenient because the password is removed and replaced with something you have, plus something you are or something you know.

- [Mapping File](PasswordlessAuthentication.yaml) ([YAML](PasswordlessAuthentication.yaml))
- [Navigator Layer](layers/PasswordlessAuthentication.json) ([JSON](layers/PasswordlessAuthentication.json))

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Protect|Significant|This control provides significant protection against this brute force technique by completing obviating the need for passwords by replacing it with passwordless credentials.|
  


### Tag(s)
- [Azure Active Directory](#3-azure-active-directory)
- [Credentials](#10-credentials)
- [Identity](#13-identity)
- [Passwords](#18-passwords)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-passwordless>
  

  [Back to Table Of Contents](#contents)
## 47. Role Based Access Control


Access management for cloud resources is a critical function for any organization that is using the cloud. Azure role-based access control (Azure RBAC) helps you manage who has access to Azure resources, what they can do with those resources, and what areas they have access to.


- [Mapping File](AzureADRoleBasedAccessControl.yaml) ([YAML](AzureADRoleBasedAccessControl.yaml))
- [Navigator Layer](layers/AzureADRoleBasedAccessControl.json) ([JSON](layers/AzureADRoleBasedAccessControl.json))

### Mapping Comments


RBAC enables organizations to limit the number of users within the organization with an IAM role that has administrative privileges.  This enables limiting the number of users within the tenant that have privileged access thereby resulting in a reduced attack surface and a coverage score factor of Partial.  Most sub-techniques have been scored as Partial for this reason.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Protect|Minimal|This control only provides protection for one of this technique's sub-techniques while not providing any protection for its procedure examples (due to being specific to Azure AD) nor its remaining sub-technqiues.  Consequently its coverage score factor is Minimal, resulting in a Minimal score.|
|[T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)|Protect|Minimal|This control only provides protection for one of this technique's sub-techniques while not providing any protection for its procedure examples nor its remaining sub-technqiues and therefore its coverage score factor is Minimal, resulting in a Minimal score.|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Protect|Partial|This control provides protection for some of this technique's sub-techniques and therefore its coverage score factor is Partial, resulting in a Partial score.|
|[T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)|Protect|Minimal|This control only provides protection for one of this technique's sub-techniques while not providing any protection for the remaining and therefore its coverage score factor is Minimal, resulting in a Minimal score.|
|[T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)|Protect|Partial|This control can be used to limit the number of users that are authorized to grant consent to applications for accessing organizational data.  This can reduce the likelihood that a user is fooled into granting consent to a malicious application that then utilizes the user's OAuth access token to access organizational data.|
|[T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)|Protect|Partial|This control can be used to limit the number of users that have access to storage solutions except for the applications, users, and services that require access, thereby reducing the attack surface.|
|[T1538 - Cloud Service Dashboard](https://attack.mitre.org/techniques/T1538/)|Protect|Partial|This control can be used to limit the number of users that have dashboard visibility thereby reducing the attack surface.|
|[T1578 - Modify Cloud Compute Infrastructure](https://attack.mitre.org/techniques/T1578/)|Protect|Partial|This control provides partial protection for all of its sub-techniques and therefore its coverage score factor is Partial, resulting in a Partial score.|
|[T1580 - Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/)|Protect|Partial|This control can be used to limit the number of users that have privileges to discover cloud infrastructure thereby reducing an organization's cloud infrastructure attack surface.|
  


### Tag(s)
- [Azure Active Directory](#3-azure-active-directory)
- [Azure Security Center Recommendation](#8-azure-security-center-recommendation)
- [Identity](#13-identity)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/role-based-access-control/overview>
  

  [Back to Table Of Contents](#contents)
## 48. SQL Vulnerability Assessment


SQL vulnerability assessment is a service that provides visibility into your security state. The service employs a knowledge base of rules that flag security vulnerabilities. It highlights deviations from best practices, such as misconfigurations, excessive permissions, and unprotected sensitive data.

- [Mapping File](SQLVulnerabilityAssessment.yaml) ([YAML](SQLVulnerabilityAssessment.yaml))
- [Navigator Layer](layers/SQLVulnerabilityAssessment.json) ([JSON](layers/SQLVulnerabilityAssessment.json))

### Mapping Comments


All scores are capped at Partial since this control provides recommendations rather than applying/enforcing the recommended actions.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Protect|Partial|This control may scan for users with unnecessary permissions and if SQL Server is out of date.|
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Protect|Minimal||
|[T1112 - Modify Registry](https://attack.mitre.org/techniques/T1112/)|Protect|Minimal|This control may scan for any stored procedures that can access the Registry and checks that permission to execute those stored procedures have been revoked from all users (other than dbo).|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Protect|Minimal|This control provides recommendations to patch if SQL server is out of date and to disable unneeded features to reduce exploitable surface area.|
|[T1505 - Server Software Component](https://attack.mitre.org/techniques/T1505/)|Protect|Minimal||
  


### Tag(s)
- [Azure Defender for SQL](#5-azure-defender-for-sql)
- [Database](#12-database)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/azure-sql/database/sql-vulnerability-assessment>
- <https://docs.microsoft.com/en-us/azure/azure-sql/database/sql-database-vulnerability-assessment-rules>
  

  [Back to Table Of Contents](#contents)
# Control Tags

## 1. Adaptive Network Hardening

### Controls
- [Network Security Groups](#45-network-security-groups)

### Views
- [Navigator Layer](layers/tags/Adaptive_Network_Hardening.json) ([JSON](layers/tags/Adaptive_Network_Hardening.json))
  

  [Back to Table Of Contents](#contents)
## 2. Analytics

### Controls
- [Azure Alerts for Network Layer](#12-azure-alerts-for-network-layer)
- [Azure Network Traffic Analytics](#27-azure-network-traffic-analytics)
- [Azure Sentinel](#31-azure-sentinel)

### Views
- [Navigator Layer](layers/tags/Analytics.json) ([JSON](layers/tags/Analytics.json))
  

  [Back to Table Of Contents](#contents)
## 3. Azure Active Directory

### Controls
- [Azure AD Identity Protection](#6-azure-ad-identity-protection)
- [Azure AD Identity Secure Score](#7-azure-ad-identity-secure-score)
- [Azure AD Multi-Factor Authentication](#8-azure-ad-multi-factor-authentication)
- [Azure AD Password Policy](#9-azure-ad-password-policy)
- [Azure AD Privileged Identity Management](#10-azure-ad-privileged-identity-management)
- [Azure Active Directory Password Protection](#11-azure-active-directory-password-protection)
- [Conditional Access](#35-conditional-access)
- [Continuous Access Evaluation](#36-continuous-access-evaluation)
- [Managed identities for Azure resources](#42-managed-identities-for-azure-resources)
- [Passwordless Authentication](#46-passwordless-authentication)
- [Role Based Access Control](#47-role-based-access-control)

### Views
- [Navigator Layer](layers/tags/Azure_Active_Directory.json) ([JSON](layers/tags/Azure_Active_Directory.json))
  

  [Back to Table Of Contents](#contents)
## 4. Azure Defender

### Controls
- [Advanced Threat Protection for Azure SQL Database](#2-advanced-threat-protection-for-azure-sql-database)
- [Alerts for Windows Machines](#5-alerts-for-windows-machines)
- [Azure Defender for App Service](#19-azure-defender-for-app-service)
- [Azure Defender for Container Registries](#20-azure-defender-for-container-registries)
- [Azure Defender for Key Vault](#21-azure-defender-for-key-vault)
- [Azure Defender for Kubernetes](#22-azure-defender-for-kubernetes)
- [Azure Defender for Resource Manager](#23-azure-defender-for-resource-manager)
- [Azure Defender for Storage](#24-azure-defender-for-storage)
- [File Integrity Monitoring](#38-file-integrity-monitoring)
- [Integrated Vulnerability Scanner Powered by Qualys](#39-integrated-vulnerability-scanner-powered-by-qualys)
- [Linux auditd alerts and Log Analytics agent integration](#41-linux-auditd-alerts-and-log-analytics-agent-integration)

### Views
- [Navigator Layer](layers/tags/Azure_Defender.json) ([JSON](layers/tags/Azure_Defender.json))
  

  [Back to Table Of Contents](#contents)
## 5. Azure Defender for SQL

### Controls
- [Advanced Threat Protection for Azure SQL Database](#2-advanced-threat-protection-for-azure-sql-database)
- [SQL Vulnerability Assessment](#48-sql-vulnerability-assessment)

### Views
- [Navigator Layer](layers/tags/Azure_Defender_for_SQL.json) ([JSON](layers/tags/Azure_Defender_for_SQL.json))
  

  [Back to Table Of Contents](#contents)
## 6. Azure Defender for Servers

### Controls
- [Adaptive Application Controls](#1-adaptive-application-controls)
- [Alerts for Windows Machines](#5-alerts-for-windows-machines)
- [File Integrity Monitoring](#38-file-integrity-monitoring)
- [Just-in-Time VM Access](#40-just-in-time-vm-access)

### Views
- [Navigator Layer](layers/tags/Azure_Defender_for_Servers.json) ([JSON](layers/tags/Azure_Defender_for_Servers.json))
  

  [Back to Table Of Contents](#contents)
## 7. Azure Security Center

### Controls
- [Adaptive Application Controls](#1-adaptive-application-controls)
- [Advanced Threat Protection for Azure SQL Database](#2-advanced-threat-protection-for-azure-sql-database)
- [Alerts for Azure Cosmos DB](#3-alerts-for-azure-cosmos-db)
- [Azure Alerts for Network Layer](#12-azure-alerts-for-network-layer)
- [Azure Defender for App Service](#19-azure-defender-for-app-service)
- [Azure Security Center Recommendations](#30-azure-security-center-recommendations)
- [Docker Host Hardening](#37-docker-host-hardening)
- [File Integrity Monitoring](#38-file-integrity-monitoring)
- [Integrated Vulnerability Scanner Powered by Qualys](#39-integrated-vulnerability-scanner-powered-by-qualys)
- [Just-in-Time VM Access](#40-just-in-time-vm-access)
- [Microsoft Antimalware for Azure](#43-microsoft-antimalware-for-azure)

### Views
- [Navigator Layer](layers/tags/Azure_Security_Center.json) ([JSON](layers/tags/Azure_Security_Center.json))
  

  [Back to Table Of Contents](#contents)
## 8. Azure Security Center Recommendation

### Controls
- [Adaptive Application Controls](#1-adaptive-application-controls)
- [Advanced Threat Protection for Azure SQL Database](#2-advanced-threat-protection-for-azure-sql-database)
- [Azure AD Multi-Factor Authentication](#8-azure-ad-multi-factor-authentication)
- [Azure Backup](#14-azure-backup)
- [Azure DDOS Protection Standard](#15-azure-ddos-protection-standard)
- [Azure Defender for App Service](#19-azure-defender-for-app-service)
- [Azure Defender for Container Registries](#20-azure-defender-for-container-registries)
- [Azure Defender for Key Vault](#21-azure-defender-for-key-vault)
- [Azure Defender for Kubernetes](#22-azure-defender-for-kubernetes)
- [Azure Defender for Storage](#24-azure-defender-for-storage)
- [Azure Firewall](#25-azure-firewall)
- [Azure Key Vault](#26-azure-key-vault)
- [Azure Policy](#28-azure-policy)
- [Azure Private Link](#29-azure-private-link)
- [Azure Security Center Recommendations](#30-azure-security-center-recommendations)
- [Azure Web Application Firewall](#33-azure-web-application-firewall)
- [File Integrity Monitoring](#38-file-integrity-monitoring)
- [Just-in-Time VM Access](#40-just-in-time-vm-access)
- [Managed identities for Azure resources](#42-managed-identities-for-azure-resources)
- [Network Security Groups](#45-network-security-groups)
- [Role Based Access Control](#47-role-based-access-control)

### Views
- [Navigator Layer](layers/tags/Azure_Security_Center_Recommendation.json) ([JSON](layers/tags/Azure_Security_Center_Recommendation.json))
  

  [Back to Table Of Contents](#contents)
## 9. Containers

### Controls
- [Azure Defender for Container Registries](#20-azure-defender-for-container-registries)
- [Azure Defender for Kubernetes](#22-azure-defender-for-kubernetes)
- [Docker Host Hardening](#37-docker-host-hardening)

### Views
- [Navigator Layer](layers/tags/Containers.json) ([JSON](layers/tags/Containers.json))
  

  [Back to Table Of Contents](#contents)
## 10. Credentials

### Controls
- [Azure AD Identity Protection](#6-azure-ad-identity-protection)
- [Azure AD Identity Secure Score](#7-azure-ad-identity-secure-score)
- [Azure AD Multi-Factor Authentication](#8-azure-ad-multi-factor-authentication)
- [Azure AD Password Policy](#9-azure-ad-password-policy)
- [Azure Active Directory Password Protection](#11-azure-active-directory-password-protection)
- [Azure Dedicated HSM](#18-azure-dedicated-hsm)
- [Azure Defender for Key Vault](#21-azure-defender-for-key-vault)
- [Azure Key Vault](#26-azure-key-vault)
- [Microsoft Defender for Identity](#44-microsoft-defender-for-identity)
- [Passwordless Authentication](#46-passwordless-authentication)

### Views
- [Navigator Layer](layers/tags/Credentials.json) ([JSON](layers/tags/Credentials.json))
  

  [Back to Table Of Contents](#contents)
## 11. DNS

### Controls
- [Alerts for DNS](#4-alerts-for-dns)
- [Azure DNS Alias Records](#16-azure-dns-alias-records)
- [Azure DNS Analytics](#17-azure-dns-analytics)
- [Microsoft Defender for Identity](#44-microsoft-defender-for-identity)

### Views
- [Navigator Layer](layers/tags/DNS.json) ([JSON](layers/tags/DNS.json))
  

  [Back to Table Of Contents](#contents)
## 12. Database

### Controls
- [Advanced Threat Protection for Azure SQL Database](#2-advanced-threat-protection-for-azure-sql-database)
- [Alerts for Azure Cosmos DB](#3-alerts-for-azure-cosmos-db)
- [SQL Vulnerability Assessment](#48-sql-vulnerability-assessment)

### Views
- [Navigator Layer](layers/tags/Database.json) ([JSON](layers/tags/Database.json))
  

  [Back to Table Of Contents](#contents)
## 13. Identity

### Controls
- [Azure AD Identity Protection](#6-azure-ad-identity-protection)
- [Azure AD Identity Secure Score](#7-azure-ad-identity-secure-score)
- [Azure AD Multi-Factor Authentication](#8-azure-ad-multi-factor-authentication)
- [Azure AD Password Policy](#9-azure-ad-password-policy)
- [Azure AD Privileged Identity Management](#10-azure-ad-privileged-identity-management)
- [Azure Active Directory Password Protection](#11-azure-active-directory-password-protection)
- [Conditional Access](#35-conditional-access)
- [Continuous Access Evaluation](#36-continuous-access-evaluation)
- [Managed identities for Azure resources](#42-managed-identities-for-azure-resources)
- [Microsoft Defender for Identity](#44-microsoft-defender-for-identity)
- [Passwordless Authentication](#46-passwordless-authentication)
- [Role Based Access Control](#47-role-based-access-control)

### Views
- [Navigator Layer](layers/tags/Identity.json) ([JSON](layers/tags/Identity.json))
  

  [Back to Table Of Contents](#contents)
## 14. Linux

### Controls
- [Azure Automation Update Management](#13-azure-automation-update-management)
- [Azure Defender for App Service](#19-azure-defender-for-app-service)
- [Docker Host Hardening](#37-docker-host-hardening)
- [File Integrity Monitoring](#38-file-integrity-monitoring)
- [Linux auditd alerts and Log Analytics agent integration](#41-linux-auditd-alerts-and-log-analytics-agent-integration)

### Views
- [Navigator Layer](layers/tags/Linux.json) ([JSON](layers/tags/Linux.json))
  

  [Back to Table Of Contents](#contents)
## 15. MFA

### Controls
- [Azure AD Identity Secure Score](#7-azure-ad-identity-secure-score)
- [Azure AD Multi-Factor Authentication](#8-azure-ad-multi-factor-authentication)
- [Azure AD Privileged Identity Management](#10-azure-ad-privileged-identity-management)
- [Conditional Access](#35-conditional-access)

### Views
- [Navigator Layer](layers/tags/MFA.json) ([JSON](layers/tags/MFA.json))
  

  [Back to Table Of Contents](#contents)
## 16. Microsoft 365 Defender

### Controls
- [Azure AD Identity Protection](#6-azure-ad-identity-protection)
- [Microsoft Defender for Identity](#44-microsoft-defender-for-identity)

### Views
- [Navigator Layer](layers/tags/Microsoft_365_Defender.json) ([JSON](layers/tags/Microsoft_365_Defender.json))
  

  [Back to Table Of Contents](#contents)
## 17. Network

### Controls
- [Alerts for DNS](#4-alerts-for-dns)
- [Azure Alerts for Network Layer](#12-azure-alerts-for-network-layer)
- [Azure DDOS Protection Standard](#15-azure-ddos-protection-standard)
- [Azure DNS Alias Records](#16-azure-dns-alias-records)
- [Azure DNS Analytics](#17-azure-dns-analytics)
- [Azure Firewall](#25-azure-firewall)
- [Azure Network Traffic Analytics](#27-azure-network-traffic-analytics)
- [Azure Private Link](#29-azure-private-link)
- [Azure VPN Gateway](#32-azure-vpn-gateway)
- [Network Security Groups](#45-network-security-groups)

### Views
- [Navigator Layer](layers/tags/Network.json) ([JSON](layers/tags/Network.json))
  

  [Back to Table Of Contents](#contents)
## 18. Passwords

### Controls
- [Azure AD Multi-Factor Authentication](#8-azure-ad-multi-factor-authentication)
- [Azure AD Password Policy](#9-azure-ad-password-policy)
- [Azure Active Directory Password Protection](#11-azure-active-directory-password-protection)
- [Azure Key Vault](#26-azure-key-vault)
- [Passwordless Authentication](#46-passwordless-authentication)

### Views
- [Navigator Layer](layers/tags/Passwords.json) ([JSON](layers/tags/Passwords.json))
  

  [Back to Table Of Contents](#contents)
## 19. Threat Hunting

### Controls
- [Azure Sentinel](#31-azure-sentinel)

### Views
- [Navigator Layer](layers/tags/Threat_Hunting.json) ([JSON](layers/tags/Threat_Hunting.json))
  

  [Back to Table Of Contents](#contents)
## 20. Windows

### Controls
- [Alerts for Windows Machines](#5-alerts-for-windows-machines)
- [Azure Automation Update Management](#13-azure-automation-update-management)
- [Azure Defender for App Service](#19-azure-defender-for-app-service)
- [File Integrity Monitoring](#38-file-integrity-monitoring)
- [Microsoft Defender for Identity](#44-microsoft-defender-for-identity)

### Views
- [Navigator Layer](layers/tags/Windows.json) ([JSON](layers/tags/Windows.json))
  

  [Back to Table Of Contents](#contents)