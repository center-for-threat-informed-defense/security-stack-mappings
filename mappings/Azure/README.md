
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
	* [31. Azure Sentinel Analytics 1-50](#31-azure-sentinel-analytics-1-50)
	* [32. Azure Sentinel Analytics 101-150](#32-azure-sentinel-analytics-101-150)
	* [33. Azure Sentinel Analytics 151-200](#33-azure-sentinel-analytics-151-200)
	* [34. Azure Sentinel Analytics 201-250](#34-azure-sentinel-analytics-201-250)
	* [35. Azure Sentinel Analytics 51-100](#35-azure-sentinel-analytics-51-100)
	* [36. Azure VPN Gateway](#36-azure-vpn-gateway)
	* [37. Azure Web Application Firewall](#37-azure-web-application-firewall)
	* [38. Cloud App Security Policies](#38-cloud-app-security-policies)
	* [39. Conditional Access](#39-conditional-access)
	* [40. Continuous Access Evaluation](#40-continuous-access-evaluation)
	* [41. Docker Host Hardening](#41-docker-host-hardening)
	* [42. File Integrity Monitoring](#42-file-integrity-monitoring)
	* [43. Integrated Vulnerability Scanner Powered by Qualys](#43-integrated-vulnerability-scanner-powered-by-qualys)
	* [44. Just-in-Time VM Access](#44-just-in-time-vm-access)
	* [45. Linux auditd alerts and Log Analytics agent integration](#45-linux-auditd-alerts-and-log-analytics-agent-integration)
	* [46. Managed identities for Azure resources](#46-managed-identities-for-azure-resources)
	* [47. Microsoft Antimalware for Azure](#47-microsoft-antimalware-for-azure)
	* [48. Microsoft Defender for Identity](#48-microsoft-defender-for-identity)
	* [49. Network Security Groups](#49-network-security-groups)
	* [50. Passwordless Authentication](#50-passwordless-authentication)
	* [51. Role Based Access Control](#51-role-based-access-control)
	* [52. SQL Vulnerability Assessment](#52-sql-vulnerability-assessment)
* [Control Tags](#control-tags)
	* [1. Adaptive Network Hardening](#1-adaptive-network-hardening)
	* [2. Analytics](#2-analytics)
	* [3. Azure Active Directory](#3-azure-active-directory)
	* [4. Azure Defender](#4-azure-defender)
	* [5. Azure Defender for App Service](#5-azure-defender-for-app-service)
	* [6. Azure Defender for SQL](#6-azure-defender-for-sql)
	* [7. Azure Defender for Servers](#7-azure-defender-for-servers)
	* [8. Azure Security Center](#8-azure-security-center)
	* [9. Azure Security Center Recommendation](#9-azure-security-center-recommendation)
	* [10. Azure Sentinel](#10-azure-sentinel)
	* [11. Azure VPN Gateway](#11-azure-vpn-gateway)
	* [12. CASB](#12-casb)
	* [13. Containers](#13-containers)
	* [14. Credentials](#14-credentials)
	* [15. DNS](#15-dns)
	* [16. Database](#16-database)
	* [17. Encryption](#17-encryption)
	* [18. File system](#18-file-system)
	* [19. Identity](#19-identity)
	* [20. Linux](#20-linux)
	* [21. MFA](#21-mfa)
	* [22. Microsoft 365 Defender](#22-microsoft-365-defender)
	* [23. Network](#23-network)
	* [24. Passwords](#24-passwords)
	* [25. Registry](#25-registry)
	* [26. VPN](#26-vpn)
	* [27. WAF](#27-waf)
	* [28. Web](#28-web)
	* [29. Web Access Firewall](#29-web-access-firewall)
	* [30. Windows](#30-windows)

# Introduction


This page enumerates the native security controls available on the Azure platform that have been mapped to [MITRE ATT&CK](https://attack.mitre.org/).  <br>Most controls included in scope were derived from the [Azure Security Benchmark (v2)](https://docs.microsoft.com/en-us/azure/security/benchmarks/overview) and our own independent research.

[Aggregate Navigator Layer For All Controls](layers/platform.json)
# Controls

## 1. Adaptive Application Controls


Security Center uses machine learning to analyze the applications running on machines and create a list of known-safe software. Allow lists are based on specific Azure workloads and can be further customized. They are based on trusted paths, publishers, and hashes. When Adaptive Application Controls are enabled, security alerts are generated when applications are run that have not been defined as safe.

- [Mapping File](AdaptiveApplicationControls.yaml)
- [Navigator Layer](layers/AdaptiveApplicationControls.json)

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1036 - Masquerading](https://attack.mitre.org/techniques/T1036/)|Detect|Partial|This control provides detection for some of this technique's sub-techniques while not providing any detection capability for the remaining sub-techniques, and therefore its coverage score is Partial, resulting in a Partial score.|
|[T1204 - User Execution](https://attack.mitre.org/techniques/T1204/)|Detect|Partial|This control only provides detection for one of this technique's sub-techniques while not providing any detection capability for its other sub-technique, and therefore its coverage score is Partial, resulting in a Partial score.|
|[T1553 - Subvert Trust Controls](https://attack.mitre.org/techniques/T1553/)|Detect|Minimal|This control only provides detection for one of this technique's sub-techniques while not providing any detection capability for the remaining sub-techniques, and therefore its coverage score is Minimal, resulting in a Minimal score.|
  


### Tag(s)
- [Azure Defender for Servers](#7-azure-defender-for-servers)
- [Azure Security Center](#8-azure-security-center)
- [Azure Security Center Recommendation](#9-azure-security-center-recommendation)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/security-center-adaptive-application>
  

  [Back to Table Of Contents](#contents)
## 2. Advanced Threat Protection for Azure SQL Database


This control provides alerts for Azure SQL Database, Azure SQL Managed Instance, and Azure Synapse Analytics. An alert may be generated on suspicious database activities, potential vulnerabilities, and SQL injection attacks, as well as anomalous database access and query patterns.

- [Mapping File](ATPForAzureSQLDatabase.yaml)
- [Navigator Layer](layers/ATPForAzureSQLDatabase.json)

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Detect|Minimal|This control only provides alerts for a set of Azure database offerings. Databases that have been deployed to endpoints within Azure or third-party databases deployed to Azure do not generate alerts for this control.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Detect|Partial|This control covers the majority of sub-techniques for this parent technique and may cover both successful and unsuccessful brute force attacks.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Detect|Partial|This control may alert on usage of faulty SQL statements. This generates an alert for a possible SQL injection by an application. Alerts may not be generated on usage of valid SQL statements by attackers for malicious purposes.|
|[T1213 - Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)|Detect|Minimal|This control may alert on extraction of a large amount of data to an unusual location. No documentation is provided on the logic for determining an unusual location.|
  


### Tag(s)
- [Azure Defender](#4-azure-defender)
- [Azure Defender for SQL](#6-azure-defender-for-sql)
- [Azure Security Center](#8-azure-security-center)
- [Azure Security Center Recommendation](#9-azure-security-center-recommendation)
- [Database](#16-database)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/azure-sql/database/threat-detection-overview>
- <https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-sql-db-and-warehouse>
  

  [Back to Table Of Contents](#contents)
## 3. Alerts for Azure Cosmos DB


The Azure Cosmos DB alerts are generated by unusual and potentially harmful attempts to access or exploit Azure Cosmos DB accounts.

- [Mapping File](AlertsForAzureCosmosDB.yaml)
- [Navigator Layer](layers/AlertsForAzureCosmosDB.json)

### Mapping Comments


This control is still in preview, so its coverage will likely expand in the future. This mapping is based on its current (preview) state.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Detect|Minimal|This control provides minimal detection coverage for the only relevant sub-technique so score is Minimal.|
|[T1213 - Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)|Detect|Minimal|This control triggers an alert when an unusually large amount of data is extracted from/by an account compared to recent activity. False positives are fairly likely and extraction in quantities below the control's threshold is not detected, so score is Minimal. Neither of the sub-techniques are relevant in this context, since they are repository-specific.|
  


### Tag(s)
- [Azure Security Center](#8-azure-security-center)
- [Database](#16-database)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/alerts-reference>
- <https://docs.microsoft.com/en-us/azure/security-center/other-threat-protections>
- <https://docs.microsoft.com/en-us/azure/cosmos-db/cosmos-db-advanced-threat-protection>
  

  [Back to Table Of Contents](#contents)
## 4. Alerts for DNS


Azure Defender for DNS provides an additional layer of protection for your cloud resources by continuously monitoring all DNS queries from your Azure resources and running advanced security analytics to alert you about suspicious activity


- [Mapping File](AlertsForDNS.yaml)
- [Navigator Layer](layers/AlertsForDNS.json)

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)|Detect|Minimal|Can detect anomalous use of DNS.  Because this detection is specific to DNS, its coverage score is Minimal resulting in an overall Minimal score.|
|[T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)|Detect|Minimal|Can detect potential DNS protocol misuse/anomalies. Technique coverage is restricted to DNS and therefore results in a Minimal score.|
|[T1090 - Proxy](https://attack.mitre.org/techniques/T1090/)|Detect|Minimal|Can detect DNS activity to anonymity networks e.g. TOR.  Because this detection is specific to DNS, its coverage score is Minimal resulting in an overall Minimal score.|
|[T1568 - Dynamic Resolution](https://attack.mitre.org/techniques/T1568/)|Detect|Partial|Can identify "random" DNS occurences which can be associated with domain generation algorithm or Fast Flux sub-techniques.  Partial for coverage and accuracy (potential for false positive/benign).<br/>|
|[T1572 - Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)|Detect|Minimal|Can identify protocol misuse/anomalies in DNS.  Because this detection is specific to DNS, its coverage score is Minimal resulting in an overall Minimal score.|
  


### Tag(s)
- [DNS](#15-dns)
- [Network](#23-network)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/defender-for-dns-introduction>
- <https://docs.microsoft.com/en-us/azure/security-center/defender-for-dns-introduction>
- <https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-resourcemanager>
  

  [Back to Table Of Contents](#contents)
## 5. Alerts for Windows Machines


For Windows, Azure Defender integrates with Azure services to monitor and protect your Windows-based machines. Security Center presents the alerts and remediation suggestions from all of these services in an easy-to-use format.

- [Mapping File](AlertsForWindowsMachines.yaml)
- [Navigator Layer](layers/AlertsForWindowsMachines.json)

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)|Detect|Partial|This control may detect usage of native Windows tool (e.g. sqldumper.exe) being used in a way that allows to extract credentials from memory.|
|[T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)|Detect|Minimal|This control may detect usage of VBScript.Encode and base-64 encoding to obfuscate malicious commands and scripts.|
|[T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)|Detect|Minimal|This control's detection is specific to a minority of this technique's sub-techniques resulting in a Minimal Coverage score and consequently an overall score of Minimal.|
|[T1055 - Process Injection](https://attack.mitre.org/techniques/T1055/)|Detect|Partial|This control's Fileless Attack Detection covers all relevant sub-techniques. Detection is periodic at an unknown rate.|
|[T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)|Detect|Minimal|This control's detection is specific to a minority of this technique's sub-techniques resulting in a Minimal Coverage score and consequently an overall score of Minimal.|
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode executed as a payload in the exploitation of a software vulnerability. Detection is periodic at an unknown rate.|
|[T1070 - Indicator Removal on Host](https://attack.mitre.org/techniques/T1070/)|Detect|Partial||
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Detect|Partial|This control is able to detect some of this technique's sub-techniques resulting in a Partial Coverage score and consequently an overall score of Partial.|
|[T1082 - System Information Discovery](https://attack.mitre.org/techniques/T1082/)|Detect|Partial|This control may detect local reconnaissance activity using the systeminfo commands.|
|[T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)|Detect|Partial||
|[T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)|Detect|Partial|This control may detect usage of malware droppers and creation of suspicious files on the host machine.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Detect|Partial||
|[T1112 - Modify Registry](https://attack.mitre.org/techniques/T1112/)|Detect|Partial|This control may detect several methods used to modify the registry for purposes of persistence, privilege elevation, and execution.|
|[T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)|Detect|Minimal|This control's detection is specific to a minority of this technique's sub-techniques resulting in a Minimal Coverage score and consequently an overall score of Minimal.|
|[T1140 - Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)|Detect|Partial|This control may detect decoding of suspicious files by certutil.exe and may detect the presence of various encoding schemes to obfuscate malicious scripts and commandline arguments.|
|[T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode executed as a payload in the exploitation of a software vulnerability. Detection is periodic at an unknown rate.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode executed as a payload in the exploitation of a software vulnerability. Detection is periodic at an unknown rate.|
|[T1202 - Indirect Command Execution](https://attack.mitre.org/techniques/T1202/)|Detect|Partial|This control may detect suspicious use of Pcalua.exe to launch executable code. There are other methods of indirect command execution that this control may not detect.|
|[T1203 - Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode executed as a payload in the exploitation of a software vulnerability. Detection is periodic at an unknown rate.|
|[T1204 - User Execution](https://attack.mitre.org/techniques/T1204/)|Detect|Partial|This control provides detection for one of the two sub-techniques of this technique,  Malicious File, resulting in a Partial Coverage score and consequently an overall score of Partial.|
|[T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode executed as a payload in the exploitation of a software vulnerability. Detection is periodic at an unknown rate.|
|[T1211 - Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode executed as a payload in the exploitation of a software vulnerability. Detection is periodic at an unknown rate.|
|[T1212 - Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode executed as a payload in the exploitation of a software vulnerability. Detection is periodic at an unknown rate.|
|[T1218 - Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)|Detect|Minimal|This control's detection is specific to a minority of this technique's sub-techniques resulting in a Minimal Coverage score and consequently an overall score of Minimal.|
|[T1222 - File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222/)|Detect|Partial|This control provides detection for some of this technique's sub-techniques resulting in a Partial Coverage score and consequently an overall score of Partial.|
|[T1489 - Service Stop](https://attack.mitre.org/techniques/T1489/)|Detect|Partial|This control may detect when critical services have been disabled through use of net.exe.|
|[T1543 - Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)|Detect|Minimal|This control's detection is specific to a minority of this technique's sub-techniques resulting in a Minimal Coverage score and consequently an overall score of Minimal.|
|[T1546 - Event Triggered Execution](https://attack.mitre.org/techniques/T1546/)|Detect|Minimal|This control's detection is specific to a minority of this technique's sub-techniques resulting in a Minimal Coverage score and consequently an overall score of Minimal.|
|[T1547 - Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)|Detect|Minimal|This control's detection is specific to a minority of this technique's sub-techniques resulting in a Minimal Coverage score and consequently an overall score of Minimal.|
|[T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)|Detect|Partial|The only sub-technique scored (Bypass User Account Control) is the only one relevant to Windows.|
|[T1558 - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/)|Detect|Minimal|This control's detection is specific to a minority of this technique's sub-techniques resulting in a Minimal Coverage score and consequently an overall score of Minimal.|
|[T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/)|Detect|Partial||
|[T1563 - Remote Service Session Hijacking](https://attack.mitre.org/techniques/T1563/)|Detect|Partial||
|[T1564 - Hide Artifacts](https://attack.mitre.org/techniques/T1564/)|Detect|Minimal|This control's detection is specific to a minority of this technique's sub-techniques resulting in a Minimal Coverage score and consequently an overall score of Minimal.|
  


### Tag(s)
- [Azure Defender](#4-azure-defender)
- [Azure Defender for Servers](#7-azure-defender-for-servers)
- [Windows](#30-windows)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/defender-for-servers-introduction>
- <https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-windows>
  

  [Back to Table Of Contents](#contents)
## 6. Azure AD Identity Protection


Identity Protection is a tool that allows organizations to accomplish three key tasks:
Automate the detection and remediation of identity-based risks.
Investigate risks using data in the portal.
Export risk detection data to third-party utilities for further analysis.


- [Mapping File](IdentityProtection.yaml)
- [Navigator Layer](layers/IdentityProtection.json)

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Detect|Minimal|This control only protects cloud accounts and therefore its overall detection coverage is minimal.|
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Respond|Minimal|Provides significant response capabilities for one of this technique's sub-techniques (cloud accounts).  Due to this capability being specific to cloud accounts and not the remaining sub-techniques of this technique, the coverage score is Minimal resulting in an overall Minimal score.|
|[T1606 - Forge Web Credentials](https://attack.mitre.org/techniques/T1606/)|Detect|Partial|This control can be effective at detecting forged web credentials because it uses environment properties (e.g. IP address, device info, etc.) to detect risky users and sign-ins even when valid credentials are utilized.  It provides partial coverage of this technique's sub-techniques and therefore has been assessed a Partial score.|
|[T1606 - Forge Web Credentials](https://attack.mitre.org/techniques/T1606/)|Respond|Partial|Provides Significant response capabilities for one of this technique's sub-techniques (SAML tokens).|
  


### Tag(s)
- [Azure Active Directory](#3-azure-active-directory)
- [Credentials](#14-credentials)
- [Identity](#19-identity)
- [Microsoft 365 Defender](#22-microsoft-365-defender)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-investigate-risk>
- <https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/overview-identity-protection>
- <https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/concept-identity-protection-risks>
- <https://techcommunity.microsoft.com/t5/azure-active-directory-identity/azuread-identity-protection-adds-support-for-federated/ba-p/244328>
  

  [Back to Table Of Contents](#contents)
## 7. Azure AD Identity Secure Score


The identity secure score is a percentage that functions as an indicator for how aligned you are with Microsoft's best practice recommendations for security. Each improvement action in Identity Secure Score is tailored to your specific configuration.  The score helps you to:  Objectively measure your identity security posture, plan identity security improvements, and review the success of your improvements.  
Every 48 hours, Azure looks at your security configuration and compares your settings with the recommended best practices. Based on the outcome of this evaluation, a new score is calculated for your directory.

- [Mapping File](AzureADIdentitySecureScore.yaml)
- [Navigator Layer](layers/AzureADIdentitySecureScore.json)

### Mapping Comments


This control was mapped to (sub-)techniques based on the Security Score improvement actions listed in a sample Azure AD tenant that we provisioned.  We were unable to find a comprehensive list of the security checks made by the control listed in its documentation.  We did note that there were some improvement actions listed that our tenant received the max score, leading us to believe that the actions listed were the complete list of checks and not just those that were outstanding for our tenant.
The following improvement actions were analyzed:
Require MFA for administrative roles, Designate more than one global admin,  Do not allow users to grant consent to unmanaged applications, Use limited administrative roles, Do not expire passwords, Enable policy to block legacy authentication  Turn on sign-in risk policy, Turn on user risk policy, Ensure all users can complete multi-factor authentication for secure access, Enable self-service password reset, Resolve unsecure account attributes, Reduce lateral movement path risk to sensitive entities,  Set a honeytoken account, Stop clear text credentials exposure, Install Defender for Identity Sensor on all Domain Controllers,  Disable Print spooler service on domain controllers, Configure VPN integration,  Configure Microsoft Defender for Endpoint Integration (*excluded, would increase the scope, see mapping for Microsoft  Defender for Endpoint), Stop legacy protocols communication, Stop weak cipher usage,  Remove dormant accounts from sensitive groups, Protect and manage local admin passwords with Microsoft LAPS,  Remove unsecure SID history attributes from entities, Fix Advanced Audit Policy issues, Modify unsecure Kerberos  delegations to prevent impersonation. 
All scores were capped at Partial since this control provides recommendations rather than applying/enforcing the recommended actions.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)|Protect|Minimal|This control's "Stop clear text credentials exposure" provides a recommendation to run the "Entities exposing credentials in clear text" assessment that monitors your traffic for any entities exposing credentials in clear text (via LDAP simple-bind).  This assessment seems specific to LDAP simple-binds and coupled with the fact that it is a recommendation and is not enforced, results in a Minimal score.<br/>|
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Detect|Minimal|This control provides recommendations that lead to detections for malicious usage of valid cloud accounts but does not provide recommendations for the remaining sub-techniques and therefore its overall detection coverage score is minimal.|
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Protect|Partial|This control provides recommendations that lead to protections for sensitive valid accounts.  Because these are recommendations and do not actually enforce the protections, the assessed score is Partial.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Protect|Partial|The MFA recommendation provides significant protection against password compromises, but because this is a recommendation and doesn't actually enforce MFA, the assessed score is capped at Partial.|
|[T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)|Detect|Minimal|This control's "Configure VPN Integration" recommendation can lead to detecting abnormal VPN connections that may be indicative of an attack.  Because this control provides a recommendation and is limited to a specific external remote service type of VPN, it has been assessed as Minimal.|
|[T1134 - Access Token Manipulation](https://attack.mitre.org/techniques/T1134/)|Detect|Minimal|This control provides a recommendation that can lead to detecting one of this technique's sub-techniques while not providing recommendations for the remaining.  It is subsequently scored as Minimal.|
|[T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)|Protect|Partial|This control's "Do not allow users to grant consent to unmanaged applications" recommendation can protect against an adversary constructing a malicious application designed to be granted access to resources with the target user's OAuth token by ensuring users can not be fooled into granting consent to the application. <br/>Due to this being a recommendation, its score is capped at Partial.|
|[T1531 - Account Access Removal](https://attack.mitre.org/techniques/T1531/)|Protect|Partial|This control's "Designate more than one global admin" can enable recovery from an adversary locking a global administrator account (deleted, locked, or manipulated (ex: changed credentials)).  Due to this being a recommendation, its score is capped as Partial.|
|[T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)|Protect|Partial|This control provides recommendations that lead to protections for some of the sub-techniques of this technique.  Due to it only providing a recommendation, its score has been capped at Partial.|
|[T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)|Protect|Minimal|This control's "Resolve unsecure account attributes" provides recommendations that can lead to strengthening how accounts are stored in Active Directory.  This control provides recommendations specific to a few types of unsecured credentials (reversible and weakly encrypted credentials) while not providing recommendations for any other, resulting in a Minimal score.|
|[T1558 - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/)|Protect|Partial|This control provides recommendations that lead to protections for some of the sub-techniques of this technique and therefore its overall protection coverage is Partial.|
|[T1606 - Forge Web Credentials](https://attack.mitre.org/techniques/T1606/)|Detect|Partial|This control's "Turn on sign-in risk policy" and "Turn on user risk policy" recommendations recommend the usage of Azure AD Identity Protection which can detect one of the sub-techniques of this technique.  This is a recommendation and therefore the score is capped at Partial.|
  


### Tag(s)
- [Azure Active Directory](#3-azure-active-directory)
- [Credentials](#14-credentials)
- [Identity](#19-identity)
- [MFA](#21-mfa)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/identity-secure-score>
- <https://techcommunity.microsoft.com/t5/azure-active-directory-identity/new-tools-to-block-legacy-authentication-in-your-organization/ba-p/1225302#>
- <https://docs.microsoft.com/en-us/defender-for-identity/cas-isp-unsecure-account-attributes>
- <https://techcommunity.microsoft.com/t5/microsoft-defender-for-identity/new-identity-security-posture-assessments-riskiest-lmps-and/m-p/1491675>
  

  [Back to Table Of Contents](#contents)
## 8. Azure AD Multi-Factor Authentication


Multi-factor authentication is a process where a user is prompted during the sign-in process for an additional form of identification, such as to enter a code on their cellphone or to provide a fingerprint scan.
If you only use a password to authenticate a user, it leaves an insecure vector for attack. If  the password is weak or has been exposed elsewhere, is it really the user signing in with the  username and password, or is it an attacker? When you require a second form of authentication, security is increased as this additional factor isn't something that's easy for an attacker to  obtain or duplicate.

- [Mapping File](AzureADMultiFactorAuthentication.yaml)
- [Navigator Layer](layers/AzureADMultiFactorAuthentication.json)

### Mapping Comments


Note that MFA that is triggered in response to privileged operations (such as assigning a user a privileged role) are considered functionality of the Azure AD Privileged Identity Management control.  Consult the mapping for this control for the ATT&CK (sub-)techniques it maps to.  This mapping specifically deals with MFA when it is enabled as a security default.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Protect|Minimal|This control only protects cloud accounts and therefore its overall detection coverage is minimal.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Protect|Significant|MFA provides significant protection against password compromises, requiring the adversary to complete an additional authentication method before their access is permitted.|
  


### Tag(s)
- [Azure Active Directory](#3-azure-active-directory)
- [Azure Security Center Recommendation](#9-azure-security-center-recommendation)
- [Credentials](#14-credentials)
- [Identity](#19-identity)
- [MFA](#21-mfa)
- [Passwords](#24-passwords)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks>
  

  [Back to Table Of Contents](#contents)
## 9. Azure AD Password Policy


A password policy is applied to all user accounts that are created and managed directly in Azure Active Directory (AD). Some of these password policy settings can't be modified, though you can configure custom banned passwords for Azure AD password protection or account lockout parameters.

- [Mapping File](AzureADPasswordPolicy.yaml)
- [Navigator Layer](layers/AzureADPasswordPolicy.json)

### Mapping Comments


Most scores have been assessed as Partial because this control increases the strength of user passwords thereby reducing the likelihood of a successful brute force attack.  But given sufficient resources, an adversary may still successfully execute the attack vectors included  in this mapping.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Protect|Partial|This control provides partial protection for most of this technique's sub-techniques and therefore has been scored as Partial.|
  


### Tag(s)
- [Azure Active Directory](#3-azure-active-directory)
- [Credentials](#14-credentials)
- [Identity](#19-identity)
- [Passwords](#24-passwords)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-sspr-policy#password-policies-that-only-apply-to-cloud-user-accounts>
  

  [Back to Table Of Contents](#contents)
## 10. Azure AD Privileged Identity Management


Privileged Identity Management (PIM) is a service in Azure Active Directory (Azure AD) that enables you to manage, control, and monitor access to important resources in your organization. These resources include resources in Azure AD, Azure, and other Microsoft Online Services such as Microsoft 365 or Microsoft Intune.

- [Mapping File](PrivilegedIdentityManagement.yaml)
- [Navigator Layer](layers/PrivilegedIdentityManagement.json)

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Protect|Minimal|This control only provides protection for one of this technique's sub-techniques while not providing any protection for the remaining and therefore its coverage score is Minimal, resulting in a Minimal score.|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Detect|Minimal|This control only provides detection for one of this technique's sub-techniques while not providing any detection for the remaining and therefore its coverage score is Minimal, resulting in a Minimal score.|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Protect|Partial|This control provides significant protection for some of this technique's sub-techniques while not providing any protection for others, resulting in a Partial score.|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Respond|Minimal|This control only provides response functionality for one of this technique's sub-techniques while not providing it for the remaining and therefore its coverage score is Minimal, resulting in a Minimal score.|
|[T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)|Protect|Minimal|This control only provides protection for one of this technique's sub-techniques while not providing any detection for the remaining and therefore its coverage score is Minimal, resulting in a Minimal score.|
  


### Tag(s)
- [Azure Active Directory](#3-azure-active-directory)
- [Identity](#19-identity)
- [MFA](#21-mfa)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure>
  

  [Back to Table Of Contents](#contents)
## 11. Azure Active Directory Password Protection


Azure AD Password Protection detects and blocks known weak passwords and their variants,  and can also block additional weak terms that are specific to your organization. Azure AD Password Protection provides a global banned password list that is automatically applied to all users in an Azure AD tenant.  The Azure AD Identity Protection team constantly analyzes Azure AD security telemetry data looking for commonly used weak or compromised passwords.  When weak terms are found, they're added to the global banned password list. To support your own business and security needs, you can define entries in a custom banned  password list. When users change or reset their passwords, these banned  password lists are checked to enforce the use of strong passwords.


- [Mapping File](AzureADPasswordProtection.yaml)
- [Navigator Layer](layers/AzureADPasswordProtection.json)

### Mapping Comments


All scores have been assessed as Partial because this control increases the strength of user passwords thereby reducing the likelihood of a successful brute force attack.  Due to the fact that a user's password is not checked  against the banned list of passwords unless the user changes or resets their  password (which is an infrequent event), there is still ample opportunity  for attackers to utilize this technique to gain access. This is what prevented the score from being elevated to Significant.
  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Protect|Partial||
  


### Tag(s)
- [Azure Active Directory](#3-azure-active-directory)
- [Credentials](#14-credentials)
- [Identity](#19-identity)
- [Passwords](#24-passwords)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-password-ban-bad>
  

  [Back to Table Of Contents](#contents)
## 12. Azure Alerts for Network Layer


Security Center network-layer analytics are based on sample IPFIX data, which are packet headers collected by Azure core routers. Based on this data feed, Security Center uses machine learning models to identify and flag malicious traffic activities. Security Center also uses the Microsoft Threat Intelligence database to enrich IP addresses.

- [Mapping File](AlertsNetworkLayer.yaml)
- [Navigator Layer](layers/AlertsNetworkLayer.json)

### Mapping Comments


Associated with the Azure Security Center.
The alerts can pick up outbound Denial of Service (DOS) attacks, though that's not an ATT&CK technique  per se (description oriented towards inbound DOS), also is a form of resource hijacking (though not in ATT&CK description, which is oriented towards cryptomining).  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)|Detect|Partial|This control can identify connections to known malicious sites. Partial (arguably minimal) since the malicious sites must be on block list. No sub-techniques scored since not enough fidelity in the alert.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Detect|Partial|Partial, doesn't cover Password Cracking (done offline typically)|
  


### Tag(s)
- [Analytics](#2-analytics)
- [Azure Security Center](#8-azure-security-center)
- [Network](#23-network)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-azurenetlayer>
  

  [Back to Table Of Contents](#contents)
## 13. Azure Automation Update Management


"Use Azure Automation Update Management or a third-party solution to ensure that the most recent security updates are installed on your Windows and Linux VMs. "

- [Mapping File](AzureAutomationUpdateMGT.yaml)
- [Navigator Layer](layers/AzureAutomationUpdateMGT.json)

### Mapping Comments


Generally applies to techniques that leverage vulnerabilities in unpatched software, which tend to be a subset of possible methods for a given TTP.   


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Protect|Significant|Coverage of methods that leverage vulnerabilities in unpatched software.|
|[T1072 - Software Deployment Tools](https://attack.mitre.org/techniques/T1072/)|Protect|Partial|Coverage of attacks that leverage software flaws in unpatched deployment tools|
|[T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)|Protect|Partial|Protects against a subset of methods that leverage unpatched client software|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Protect|Partial|Partial coverage for techniques that exploit vulnerabilities in (common) unpatched software.|
|[T1195 - Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)|Protect|Partial|Coverage of some aspects of software supply chain compromise|
|[T1203 - Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)|Protect|Significant|Covers methods that leverage unpatched vulnerabilities.|
|[T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)|Protect|Partial|Coverage of techniques that leverage vulnerabilities in unpatched remote services.|
|[T1211 - Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211/)|Protect|Significant|Coverage of methods that exploit unpatched vulnerabilities in software/systems.|
|[T1212 - Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212/)|Protect|Significant|Coverage of techniques that leverage unpatched software vulnerabilities|
|[T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)|Protect|Partial|Protection against Denial of Service (DOS) attacks that leverage system/application vulnerabilities as opposed to volumetric attacks|
|[T1554 - Compromise Client Software Binary](https://attack.mitre.org/techniques/T1554/)|Protect|Partial|Managed software updates can provide a baseline to compare with potentially compromised/modified software binaries.|
  


### Tag(s)
- [Linux](#20-linux)
- [Windows](#30-windows)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/automation/update-management/overview>
  

  [Back to Table Of Contents](#contents)
## 14. Azure Backup


"The Azure Backup service provides simple, secure, and cost-effective solutions to back up your data and recover it from the Microsoft Azure cloud."

- [Mapping File](AzureBackup.yaml)
- [Navigator Layer](layers/AzureBackup.json)

### Mapping Comments


Azure Backup service provides defense against destruction/manipulation of data at rest. Scoring as "Significant" since it is an essential practice against data destruction et al, though there is an argument for a Partial score since it does not prevent so much as enable recovery.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1485 - Data Destruction](https://attack.mitre.org/techniques/T1485/)|Protect|Significant|Data backups provide significant mitigation against data destruction.|
|[T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)|Protect|Significant|Provides significant mitigation against data encryption/ransomware attacks.|
|[T1491 - Defacement](https://attack.mitre.org/techniques/T1491/)|Protect|Significant|Provides significant mitigation against defacement|
|[T1561 - Disk Wipe](https://attack.mitre.org/techniques/T1561/)|Protect|Significant||
  


### Tag(s)
- [Azure Security Center Recommendation](#9-azure-security-center-recommendation)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/backup/backup-overview>
  

  [Back to Table Of Contents](#contents)
## 15. Azure DDOS Protection Standard


Azure DDoS Protection Standard, combined with application design best practices, provides enhanced DDoS mitigation features to defend against DDoS attacks. 
It is automatically tuned to help protect your specific Azure resources in a virtual network.

- [Mapping File](AzureDDOS.yaml)
- [Navigator Layer](layers/AzureDDOS.json)

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1498 - Network Denial of Service](https://attack.mitre.org/techniques/T1498/)|Protect|Significant|Designed to address multiple DDOS techniques including volumetric attacks.|
|[T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)|Protect|Significant|Protects against volumetric and protocol DOS, though not application. (could score Partial here)|
  


### Tag(s)
- [Azure Security Center Recommendation](#9-azure-security-center-recommendation)
- [Network](#23-network)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview>
  

  [Back to Table Of Contents](#contents)
## 16. Azure DNS Alias Records


Azure DNS alias records are qualifications on a DNS record set. They can reference other Azure resources from within your DNS zone.   For example, you can create an alias record set that references an Azure public IP address instead of an A record. Your alias record set points to an Azure public IP address service instance dynamically. As a result, the alias record set seamlessly updates itself during DNS resolution.


- [Mapping File](AzureDNSAliasRecords.yaml)
- [Navigator Layer](layers/AzureDNSAliasRecords.json)

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1584 - Compromise Infrastructure](https://attack.mitre.org/techniques/T1584/)|Protect|Minimal|This control only provides protection for one of this technique's sub-techniques while not providing any protection for the remaining and therefore its coverage score factor is Minimal, resulting in a Minimal score.|
  


### Tag(s)
- [DNS](#15-dns)
- [Network](#23-network)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/dns/dns-alias#prevent-dangling-dns-records>
  

  [Back to Table Of Contents](#contents)
## 17. Azure DNS Analytics


"DNS Analytics helps you to: identify clients that try to resolve malicious domain names, identify stale resource records, identify frequently queried domain names and talkative DNS clients,  view request load on DNS servers, and view dynamic DNS registration failures.
The solution collects, analyzes, and correlates Windows DNS analytic and audit logs and other related data from your DNS servers."

- [Mapping File](AzureDNSAnalytics.yaml)
- [Navigator Layer](layers/AzureDNSAnalytics.json)

### Mapping Comments


For temporal score, generally high with respect to access to known bad domains: "The event-related data is collected near real time from the analytic and audit logs provided by enhanced DNS logging and diagnostics in Windows Server 2012 R2.". DNS logs and analytics can be used in a response context, for example to identify client access to previously unknown malicious domains.  "Noisy" client alerts may be useful for identifying some C2 over DNS.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)|Detect|Minimal|Detection restricted to DNS protocol|
|[T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)|Detect|Partial|Can identify anomalous / high talker DNS clients, possibly related to exfil via DNS|
|[T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)|Detect|Partial|May detect C2 wrt DNS via frequent talkers.|
|[T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)|Respond|Partial|Can be used forensically to identify clients communicated with identified C2 hosts.|
|[T1566 - Phishing](https://attack.mitre.org/techniques/T1566/)|Detect|Partial|Can detect DNS queries to known malicious sites|
|[T1566 - Phishing](https://attack.mitre.org/techniques/T1566/)|Respond|Partial|Can identify clients that attempted to resolve previously unknown malicious sites|
|[T1568 - Dynamic Resolution](https://attack.mitre.org/techniques/T1568/)|Respond|Partial|Can be used for after-the-fact analysis of potential fast-flux DNS C2|
  


### Tag(s)
- [DNS](#15-dns)
- [Network](#23-network)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/azure-monitor/insights/dns-analytics>
  

  [Back to Table Of Contents](#contents)
## 18. Azure Dedicated HSM


"Azure Dedicated HSM is an Azure service that provides cryptographic key storage in Azure ... for customers who require FIPS 140-2 Level 3-validated devices and complete and exclusive control of the HSM appliance."

- [Mapping File](AzureDedicatedHSM.yaml)
- [Navigator Layer](layers/AzureDedicatedHSM.json)

### Mapping Comments


Note there is also a Managed HSM service.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Protect|Partial|Reduces likelihood of obtaining private keys to use or generate new valid accounts|
|[T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)|Protect|Partial|Coverage partial: protects private keys|
|[T1553 - Subvert Trust Controls](https://attack.mitre.org/techniques/T1553/)|Protect|Partial|Coverage limited to code signing and install root certificate|
|[T1588 - Obtain Capabilities](https://attack.mitre.org/techniques/T1588/)|Protect|Partial|Coverage limited to sub-techniques involved with stealing credentials / certificates / keys from the organization.|
  


### Tag(s)
- [Credentials](#14-credentials)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/dedicated-hsm/overview>
- <https://docs.microsoft.com/en-us/azure/key-vault/managed-hsm/>
  

  [Back to Table Of Contents](#contents)
## 19. Azure Defender for App Service


Azure Defender for App Service monitors VM instances and their management interfaces, App Service apps and their requests/responses, and App Service internal logs to detect threats to App Service resources and provide security recommendations to mitigate them.

- [Mapping File](AzureDefenderForAppService.yaml)
- [Navigator Layer](layers/AzureDefenderForAppService.json)

### Mapping Comments


The AppServices_KnownCredentialAccessTools alert is used to detect suspicious processes associated with credential theft. This is clearly linked to the Credential Access tactic, but does not clearly detect any specific technique or set of techniques, so it has been omitted from this mapping.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)|Detect|Minimal|This control only covers one procedure for one of this technique's sub-techniques, so score is Minimal.|
|[T1005 - Data from Local System](https://attack.mitre.org/techniques/T1005/)|Detect|Minimal|This control analyzes host data to detect execution of known malicious PowerShell PowerSploit cmdlets. This covers execution of this technique via the Exfiltration modules on Windows, but does not address other procedures or platforms, and temporal factor is unknown, so score is Minimal.|
|[T1012 - Query Registry](https://attack.mitre.org/techniques/T1012/)|Detect|Minimal|This control analyzes host data to detect execution of known malicious PowerShell PowerSploit cmdlets. This covers execution of this technique via the Privesc-PowerUp modules, but does not address other procedures, and temporal factor is unknown, so score is Minimal.|
|[T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)|Detect|Minimal|This control only covers one platform and procedure for one of this technique's sub-techniques, so score is Minimal.|
|[T1036 - Masquerading](https://attack.mitre.org/techniques/T1036/)|Detect|Minimal|This control only addresses one of this technique's sub-techniques, so its score is Minimal.|
|[T1047 - Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)|Detect|Minimal|This control analyzes host data to detect execution of known malicious PowerShell PowerSploit cmdlets. This covers execution of this technique via the Invoke-WmiCommand module, but does not address other procedures, and temporal factor is unknown, so score is Minimal.|
|[T1053 - Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)|Detect|Minimal|This control only covers one platform and procedure for one of this technique's sub-techniques, so score is Minimal.|
|[T1055 - Process Injection](https://attack.mitre.org/techniques/T1055/)|Detect|Partial|This control's Fileless Attack Detection covers all relevant sub-techniques. The control also specifically detects process hollowing, executable image injection, and threads started in a dynamically allocated code segment. Detection is periodic at an unknown rate.|
|[T1056 - Input Capture](https://attack.mitre.org/techniques/T1056/)|Detect|Minimal|This control only covers one platform and procedure for one of this technique's sub-techniques, so score is Minimal.|
|[T1057 - Process Discovery](https://attack.mitre.org/techniques/T1057/)|Detect|Minimal|This control analyzes host data to detect execution of known malicious PowerShell PowerSploit cmdlets. This covers execution of this technique via the Get-ProcessTokenPrivilege PowerUp module on Windows, but does not address other procedures or platforms, and temporal factor is unknown, so score is Minimal.|
|[T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)|Detect|Minimal|This control only provides detection coverage for two sub-techniques, and only detects certain specific sub-technique behaviors, so score is Minimal.|
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode executed as a payload in the exploitation of a software vulnerability. Detection is periodic at an unknown rate.|
|[T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)|Detect|Minimal|This control only covers one platform and procedure for one of this technique's sub-techniques, so score is Minimal.|
|[T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)|Detect|Partial|This control detects binary downloads via certutil, monitors for FTP access from IP addresses found in threat intelligence, monitors for references to suspicious domain names and file downloads from known malware sources, and monitors processes for downloads from raw-data websites like Pastebin. Temporal factor is unknown.|
|[T1113 - Screen Capture](https://attack.mitre.org/techniques/T1113/)|Detect|Minimal|This control analyzes host data to detect execution of known malicious PowerShell PowerSploit cmdlets. This covers execution of this technique via the Get-TimedScreenshot module on Windows, but does not address other procedures or platforms, and temporal factor is unknown, so score is Minimal.|
|[T1123 - Audio Capture](https://attack.mitre.org/techniques/T1123/)|Detect|Minimal|This control analyzes host data to detect execution of known malicious PowerShell PowerSploit cmdlets. This covers execution of this technique via the Get-MicrophoneAudio module on Windows, but does not address other procedures or platforms, and temporal factor is unknown, so score is Minimal.|
|[T1134 - Access Token Manipulation](https://attack.mitre.org/techniques/T1134/)|Detect|Minimal|This control analyzes host data to detect execution of known malicious PowerShell PowerSploit cmdlets. This covers execution of this technique via the Invoke-TokenManipulation module on Windows, but does not address other procedures or platforms, and temporal factor is unknown, so score is Minimal.|
|[T1140 - Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)|Detect|Partial|This control analyzes host data to detect base-64 encoded executables within command sequences. It also monitors for use of certutil to decode executables. Temporal factor is unknown.|
|[T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode injected into browser or other process memory as part of a drive-by attack. Detection is periodic at an unknown rate.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode injected to exploit a vulnerability in a public-facing application. Detection is periodic at an unknown rate.|
|[T1203 - Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode executed as a payload in the exploitation of a software vulnerability. Detection is periodic at an unknown rate.|
|[T1204 - User Execution](https://attack.mitre.org/techniques/T1204/)|Detect|Minimal|This control only provides meaningful detection for one of the technique's two sub-techniques, and temporal factor is unknown, resulting in a score of Minimal.|
|[T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode injected to exploit a vulnerability in an exposed service. Detection is periodic at an unknown rate.|
|[T1211 - Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode executed as a payload in the exploitation of a software vulnerability. Detection is periodic at an unknown rate.|
|[T1212 - Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212/)|Detect|Partial|This control's Fileless Attack Detection identifies shellcode executing within process memory, including shellcode executed as a payload in the exploitation of a software vulnerability. Detection is periodic at an unknown rate.|
|[T1482 - Domain Trust Discovery](https://attack.mitre.org/techniques/T1482/)|Detect|Minimal|This control analyzes host data to detect execution of known malicious PowerShell PowerSploit cmdlets. This covers execution of this technique via the Get-NetDomainTrust and Get-NetForestTrust modules, but does not address other procedures, and temporal factor is unknown, so score is Minimal.|
|[T1496 - Resource Hijacking](https://attack.mitre.org/techniques/T1496/)|Detect|Partial|This control detects file downloads associated with digital currency mining as well as host data related to process and command execution associated with mining. It also includes fileless attack detection, which specifically targets crypto mining activity. Temporal factor is unknown.|
|[T1543 - Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)|Detect|Minimal|This control only covers one platform and procedure for one of this technique's sub-techniques, so score is Minimal.|
|[T1547 - Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)|Detect|Minimal|This control only covers one platform and procedure for two of this technique's sub-techniques, so score is Minimal.|
|[T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)|Detect|Minimal|This control only covers one platform and procedure for two of this technique's sub-techniques, so score is Minimal.|
|[T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)|Detect|Minimal|This control analyzes host data to detect execution of known malicious PowerShell PowerSploit cmdlets. This covers execution of this technique via the PowerSploit Exfiltration modules on Windows, but does not address other procedures or platforms, and temporal factor is unknown, so score is Minimal.|
|[T1558 - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/)|Detect|Minimal|This control only covers one procedure for one of this technique's sub-techniques, so score is Minimal.|
|[T1559 - Inter-Process Communication](https://attack.mitre.org/techniques/T1559/)|Detect|Partial|This control's Fileless Attack Detection covers the command execution aspects of both of this technique's sub-techniques. Detection is periodic at an unknown rate.|
|[T1566 - Phishing](https://attack.mitre.org/techniques/T1566/)|Protect|Minimal|This control only provides (minimal) protection for one of the technique's sub-techniques, resulting in a Minimal score.|
|[T1574 - Hijack Execution Flow](https://attack.mitre.org/techniques/T1574/)|Detect|Minimal|This control only covers one platform and procedure for some of this technique's sub-techniques, so score is Minimal.|
|[T1584 - Compromise Infrastructure](https://attack.mitre.org/techniques/T1584/)|Protect|Minimal|This control only addresses one of the technique's sub-techniques, resulting in a score of Minimal.|
|[T1594 - Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594/)|Detect|Partial|This control monitors for accesses of potentially sensitive web pages from source IP addresses whose access pattern resembles that of a web scanner or have not been logged before. Temporal factor is unknown.|
|[T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)|Detect|Minimal|This control only provides detection for one of the two sub-techniques, so score is Minimal.|
  


### Tag(s)
- [Azure Defender](#4-azure-defender)
- [Azure Defender for App Service](#5-azure-defender-for-app-service)
- [Azure Security Center](#8-azure-security-center)
- [Azure Security Center Recommendation](#9-azure-security-center-recommendation)
- [Linux](#20-linux)
- [Windows](#30-windows)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/alerts-reference>
- <https://docs.microsoft.com/en-us/azure/security-center/defender-for-app-service-introduction>
- <https://azure.microsoft.com/en-us/services/app-service/>
- <https://docs.microsoft.com/en-us/azure/security-center/defender-for-servers-introduction>
  

  [Back to Table Of Contents](#contents)
## 20. Azure Defender for Container Registries


Azure Defender for container registries includes a vulnerability scanner to scan the images in your Azure Resource Manager-based Azure Container Registry registries and provide deeper visibility into your images' vulnerabilities. The integrated scanner is powered by Qualys. Azure Container Registry is a managed, private Docker registry service based on the open-source Docker Registry 2.0.

- [Mapping File](AzureDefenderForContainerRegistries.yaml)
- [Navigator Layer](layers/AzureDefenderForContainerRegistries.json)

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
- [Azure Security Center Recommendation](#9-azure-security-center-recommendation)
- [Containers](#13-containers)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/defender-for-container-registries-introduction>
- <https://docs.microsoft.com/en-us/azure/container-registry/container-registry-intro>
  

  [Back to Table Of Contents](#contents)
## 21. Azure Defender for Key Vault


Azure Defender detects unusual and potentially harmful attempts to access or exploit Key Vault accounts. When anomalous activities occur, Azure Defender shows alerts and optionally sends them via email to relevant members of your organization. These alerts include the details of the suspicious activity and recommendations on how to investigate and remediate threats.

- [Mapping File](AzureDefenderForKeyVault.yaml)
- [Navigator Layer](layers/AzureDefenderForKeyVault.json)

### Mapping Comments


This control provides alerts for suspicious activity for Azure Key Vault. Documentation has been offered on how to respond to alerts but no specific tool or feature is offered for response.   


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)|Detect|Significant|This control may detect suspicious secret access from Azure key vaults. This does not apply to any sub-techniques under T1555 - Credentials from Password Stores but Azure Key Vault can be treated as a store for passwords, keys, and certificates. The coverage of this control could be deemed high for cloud credential and secret storage within Key Vault but is not applicable to traditional password stores, such as password managers, keychain, or web browsers.|
|[T1580 - Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/)|Detect|Partial|This control may alert on suspicious access of key vaults, including suspicious listing of key vault contents. This control does not alert on discovery of other cloud services, such as VMs, snapshots, cloud storage. Suspicious activity based on patterns of access from certain users and applications allows for managing false positive rates.|
  


### Tag(s)
- [Azure Defender](#4-azure-defender)
- [Azure Security Center Recommendation](#9-azure-security-center-recommendation)
- [Credentials](#14-credentials)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/defender-for-key-vault-introduction>
- <https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-azurekv>
  

  [Back to Table Of Contents](#contents)
## 22. Azure Defender for Kubernetes


Azure Defender for Kubernetes provides cluster-level threat protection by monitoring your Azure Kubernetes Service (AKS) managed services through the logs retrieved by AKS. Examples of security events that Azure Defender for Kubernetes monitors include exposed Kubernetes dashboards, creation of high privileged roles, and the creation of sensitive mounts.

- [Mapping File](AzureDefenderForKubernetes.yaml)
- [Navigator Layer](layers/AzureDefenderForKubernetes.json)

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Detect|Partial|This control may alert on detection of new privileged containers and high privilege roles.|
|[T1070 - Indicator Removal on Host](https://attack.mitre.org/techniques/T1070/)|Detect|Partial|This control may alert on deletion of Kubernetes events. Attackers might delete those events for hiding their operations in the cluster. There is no relevant sub-technique for this control but the parent applies.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Protect|Partial|This control may alert on publicly exposed Kubernetes services. This may provide context on services that should be patched or hardened for public access.|
|[T1525 - Implant Container Image](https://attack.mitre.org/techniques/T1525/)|Detect|Partial|This control may alert on containers with sensitive volume mounts, unneeded privileges, or running an image with digital currency mining software.|
  


### Tag(s)
- [Azure Defender](#4-azure-defender)
- [Azure Security Center Recommendation](#9-azure-security-center-recommendation)
- [Containers](#13-containers)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/defender-for-kubernetes-introduction>
- <https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-akscluster>
  

  [Back to Table Of Contents](#contents)
## 23. Azure Defender for Resource Manager


Azure Defender for Resource Manager automatically monitors the  resource management operations in your organization, whether they're  performed through the Azure portal, Azure REST APIs, Azure CLI, or  other Azure programmatic clients. Alerts are generated by threats  detected in Azure Resource Manager logs and Azure Activity logs.  Azure Defender runs advanced security analytics to detect threats  and alert you about suspicious activity.


- [Mapping File](AlertsForResourceManager.yaml)
- [Navigator Layer](layers/AlertsForResourceManager.json)

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Detect|Minimal|This control may alert on escalation attempts from Azure AD to Azure accounts by specific exploitation toolkits. Consequently, its Coverage score is Minimal resulting in an overall Minimal score.|
|[T1069 - Permission Groups Discovery](https://attack.mitre.org/techniques/T1069/)|Detect|Minimal|This control may alert on Azure domain cloud groups discovery activity but may not provide alerts for other account types or undocumented exploitation toolkits.  Consequently, its Coverage score is Minimal resulting in an overall Minimal score.|
|[T1082 - System Information Discovery](https://attack.mitre.org/techniques/T1082/)|Detect|Minimal|This control may alert on Cloud Service Discovery activity generated by specific toolkits, such as MicroBurst, PowerZure, etc. It may not generate alerts on undocumented discovery techniques or toolkits. Consequently, its Coverage score is Minimal resulting in an overall Minimal score.|
|[T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)|Detect|Minimal|This control may alert on Azure cloud account discovery activity but may not provide alerts for other account types or undocumented exploitation toolkits. Consequently, its Coverage score is Minimal resulting in an overall Minimal score.|
|[T1526 - Cloud Service Discovery](https://attack.mitre.org/techniques/T1526/)|Detect|Partial|This control may alert on Cloud Service Discovery activity generated by specific toolkits, such as MicroBurst, PowerZure, etc. It may not generate alerts on undocumented discovery techniques or exploitation toolkits.|
|[T1538 - Cloud Service Dashboard](https://attack.mitre.org/techniques/T1538/)|Detect|Partial|This control may alert on suspicious management activity based on IP, time, anomalous behaviour, or PowerShell usage. Machine learning algorithms are used to reduce false positives.|
|[T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)|Detect|Minimal|This control may alert on credential dumping from Azure Key Vaults, App Services Configurations, and Automation accounts by specific exploitation toolkits. Consequently, its Coverage score is Minimal resulting in an overall Minimal score.|
|[T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/)|Detect|Minimal|This control may alert on Windows Defender security features being disabled but does not alert on other security tools or logging being disabled or tampered with.  Consequently, its Coverage score is Minimal resulting in an overall Minimal score.|
|[T1580 - Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/)|Detect|Partial|This control may alert on Cloud Infrastructure Discovery activity generated by specific toolkits, such as MicroBurst, PowerZure, etc. It may not generate alerts on undocumented discovery techniques or exploitation toolkits.|
  


### Tag(s)
- [Azure Defender](#4-azure-defender)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/defender-for-resource-manager-introduction>
- <https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-resourcemanager>
  

  [Back to Table Of Contents](#contents)
## 24. Azure Defender for Storage


Azure Defender for Storage can detect unusual and potentially harmful attempts to access or exploit storage accounts. Security alerts may trigger due to suspicious access patterns, suspicious activities, and upload of malicious content. Alerts include details of the incident that triggered them, as well as recommendations on how to investigate and remediate threats. Alerts can be exported to Azure Sentinel or any other third-party SIEM or any other external tool.

- [Mapping File](AzureDefenderForStorage.yaml)
- [Navigator Layer](layers/AzureDefenderForStorage.json)

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Detect|Partial|This control may alert on suspicious cloud storage account access based on IP, location, etc.|
|[T1080 - Taint Shared Content](https://attack.mitre.org/techniques/T1080/)|Detect|Partial|This control may alert on upload of possible malware or executable and Azure Cloud Services Package files. These alerts are dependent on Microsoft threat intelligence and may not alert on novel or modified malware.|
|[T1080 - Taint Shared Content](https://attack.mitre.org/techniques/T1080/)|Respond|Minimal|TBD|
|[T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)|Detect|Partial|This control may alert on upload of possible malware or executable and Azure Cloud Services Package files. These alerts are dependent on Microsoft threat intelligence and may not alert on novel or modified malware.|
|[T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)|Respond|Minimal|TBD|
|[T1485 - Data Destruction](https://attack.mitre.org/techniques/T1485/)|Detect|Minimal|This control may generate alerts when there has been an unusual or unexpected delete operation within Azure cloud storage. Alerts may not be generated by disabling of storage backups, versioning, or editing of storage objects.|
|[T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)|Detect|Significant|A variety of alerts may be generated by malicious access and enumeration of Azure Storage.|
|[T1537 - Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)|Detect|Partial|This control may alert on unusually large amounts of data being extracted from Azure storage and suspicious access to storage accounts. There are no alerts specifically tied to data transfer between cloud accounts but there are several alerts for anomalous storage access and transfer.|
  


### Tag(s)
- [Azure Defender](#4-azure-defender)
- [Azure Security Center Recommendation](#9-azure-security-center-recommendation)
- [Azure Sentinel](#10-azure-sentinel)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/defender-for-storage-introduction>
- <https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-azurestorage>
  

  [Back to Table Of Contents](#contents)
## 25. Azure Firewall


Azure Firewall is a managed, cloud-based network security service that protects your Azure Virtual Network resources. 
It's a fully stateful firewall as a service (FWaaS) with built-in high availability and unrestricted cloud scalability.

- [Mapping File](AzureFirewall.yaml)
- [Navigator Layer](layers/AzureFirewall.json)

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1008 - Fallback Channels](https://attack.mitre.org/techniques/T1008/)|Detect|Minimal|Can provide telemetry|
|[T1008 - Fallback Channels](https://attack.mitre.org/techniques/T1008/)|Protect|Minimal|Can prevent access to known malicious destinations|
|[T1008 - Fallback Channels](https://attack.mitre.org/techniques/T1008/)|Respond|Minimal|Can provide telemetry / network forensics|
|[T1018 - Remote System Discovery](https://attack.mitre.org/techniques/T1018/)|Protect|Partial|Can prevent some discovery between enclaves|
|[T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)|Detect|Minimal|Can provide telemetry|
|[T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)|Protect|Partial|Can restrict some protocols / C2 channels|
|[T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)|Respond|Minimal|TBD|
|[T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046/)|Protect|Significant|Can prevent inter-host scanning / enforce network segmentation|
|[T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)|Protect|Partial|Can restrict protocol use across firewall, though allowed protocols still can be used.|
|[T1095 - Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1095/)|Protect|Significant|Can restrict use of non-application layer protocols such as ICMP|
|[T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)|Detect|Partial|Can provide telemetry of systems attempting access to remote services|
|[T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)|Protect|Partial|Can limit access to external remote services to minimum necessary|
|[T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)|Respond|Minimal|TBD|
|[T1205 - Traffic Signaling](https://attack.mitre.org/techniques/T1205/)|Detect|Minimal|Can provide some telemetry on port knocking attempts|
|[T1205 - Traffic Signaling](https://attack.mitre.org/techniques/T1205/)|Protect|Partial|Can block access to ports used in traffic signalling|
|[T1219 - Remote Access Software](https://attack.mitre.org/techniques/T1219/)|Protect|Partial|Can restrict flow of some protocols across firewall boundaries.|
|[T1498 - Network Denial of Service](https://attack.mitre.org/techniques/T1498/)|Protect|Partial|Can reduce network denial of service (DOS) by dropping packets. Need DDOS protection from upstream provider for large scale attacks.|
|[T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)|Protect|Significant||
|[T1563 - Remote Service Session Hijacking](https://attack.mitre.org/techniques/T1563/)|Protect|Partial|Can limit hijacking between enclaves|
|[T1571 - Non-Standard Port](https://attack.mitre.org/techniques/T1571/)|Protect|Significant|Can restrict access to non-standard ports|
|[T1590 - Gather Victim Network Information](https://attack.mitre.org/techniques/T1590/)|Protect|Partial|Can prevent some scans and probes of targeted network|
|[T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)|Detect|Significant|Can provide telemetry on scanners|
|[T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)|Protect|Significant|Can prevent network scanning and vunerability scanning of targeted endpoints.|
|[T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)|Respond|Minimal|TBD|
  


### Tag(s)
- [Azure Security Center Recommendation](#9-azure-security-center-recommendation)
- [Network](#23-network)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/firewall/overview>
  

  [Back to Table Of Contents](#contents)
## 26. Azure Key Vault


Azure Key Vault provides a way to store and manage secrets, keys, and certificates used throughout Azure and for internally connected resources. This control allows for fine grained permissions for authentication and authorization for access while providing monitoring for all activity with the key vault.

- [Mapping File](AzureKeyVault.yaml)
- [Navigator Layer](layers/AzureKeyVault.json)

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)|Protect|Minimal|This control provides secure methods for accessing secrets and passwords. This can reduce the incidences of credentials and other authentication material being transmitted in plain text or by insecure encryption methods. Any communication between applications or endpoints after access to Key Vault may not be secure.|
|[T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)|Protect|Partial|This control can provide protection against attackers stealing application access tokens if they are stored within Azure Key Vault. Key vault significantly raises the bar for access for stored tokens by requiring legitimate credentials with proper authorization. Applications may have to be modified to take advantage of Key Vault and may not always be possible to utilize.|
|[T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)|Protect|Partial|This control provides a central, secure location for storage of credentials to reduce the possibility of attackers discovering unsecured credentials.|
|[T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)|Protect|Partial|This control may provide a more secure location for storing passwords. If an Azure user account, endpoint, or application is compromised, they may have limited access to passwords stored in the Key Vault.|
  


### Tag(s)
- [Azure Security Center Recommendation](#9-azure-security-center-recommendation)
- [Credentials](#14-credentials)
- [Passwords](#24-passwords)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/key-vault/general/overview>
  

  [Back to Table Of Contents](#contents)
## 27. Azure Network Traffic Analytics


"Traffic Analytics is a cloud-based solution that provides visibility into user and application activity in cloud networks. Traffic analytics analyzes Network Watcher network security group (NSG) flow logs to provide insights into traffic flow in your Azure cloud."

- [Mapping File](AzureTrafficAnalytics.yaml)
- [Navigator Layer](layers/AzureTrafficAnalytics.json)

### Mapping Comments


Network Traffic Analytics can make queries with respect to Network Security Groups. Mappings made with some reasonable assumptions on NSGs such as a group for management systems.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)|Detect|Partial|Can detect anomalous traffic or attempts related to network security group (NSG) for remote services.|
|[T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046/)|Detect|Significant|Can detect network service scanning/discovery activity|
|[T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)|Detect|Partial|Can detect anomalous traffic wrt specific protocols/ports|
|[T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)|Detect|Partial|Can identify anomalous traffic wrt NSG and application layer protocols|
|[T1072 - Software Deployment Tools](https://attack.mitre.org/techniques/T1072/)|Detect|Partial|Can detect anomalous traffic wrt critical systems and software deployment ports|
|[T1090 - Proxy](https://attack.mitre.org/techniques/T1090/)|Detect|Partial|Can detect anomalous traffic between systems and to external networks.|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Detect|Partial|Can identify anomalous access to administrative systems or ports, though can't identify specific sub-techniques/activity.|
|[T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)|Detect|Partial|Can identify anomalous access to external remote services|
|[T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)|Detect|Partial|Can detect anomalous connections to administrative systems/ports|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Detect|Partial|Can detect anomalous traffic to and from externally facing systems wrt network security group (NSG) policy|
|[T1199 - Trusted Relationship](https://attack.mitre.org/techniques/T1199/)|Detect|Partial|Can analyze network security group (NSG) traffic related to trusted third parties|
|[T1482 - Domain Trust Discovery](https://attack.mitre.org/techniques/T1482/)|Detect|Partial|Can identify anomalous traffic and discovery attempts to different domains.|
|[T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)|Detect|Partial|Can identify volumetric attacks and multi-sourced attacks|
|[T1542 - Pre-OS Boot](https://attack.mitre.org/techniques/T1542/)|Detect|Partial|Can identify anomalous traffic related to one sub-technique (TFTP boot)|
|[T1563 - Remote Service Session Hijacking](https://attack.mitre.org/techniques/T1563/)|Detect|Partial|Can identify anomalous RDP and SSH sessions or blocked attempts.|
|[T1570 - Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/)|Detect|Partial|Can detect anomalous traffic between systems|
|[T1571 - Non-Standard Port](https://attack.mitre.org/techniques/T1571/)|Detect|Significant|Can identify anomalous traffic wrt non-application protocols|
|[T1602 - Data from Configuration Repository](https://attack.mitre.org/techniques/T1602/)|Detect|Partial|Can identify anomalous traffic wrt configuration repositories or identified configuration management ports.|
  


### Tag(s)
- [Analytics](#2-analytics)
- [Network](#23-network)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/network-watcher/traffic-analytics>
  

  [Back to Table Of Contents](#contents)
## 28. Azure Policy


Azure Policy evaluates resources in Azure by comparing the properties of those resources to business rules. These business rules, described in JSON format, are known as policy definitions. Azure Policy helps to enforce organizational standards and to assess compliance at-scale.

- [Mapping File](AzurePolicy.yaml)
- [Navigator Layer](layers/AzurePolicy.json)

### Mapping Comments


This mapping is focused on the list of built-in policy definitions provided by Azure Policy.  


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
|[T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)|Protect|Partial|This control may provide recommendations to enable Azure security controls to harden remote services and reduce surface area for possible exploitation.|
|[T1485 - Data Destruction](https://attack.mitre.org/techniques/T1485/)|Protect|Minimal|This control may provide recommendations to enable soft deletion and purge protection in Azure Key Vault. This can help mitigate against malicious deletion of keys and secrets stored within Key Vault.|
|[T1505 - Server Software Component](https://attack.mitre.org/techniques/T1505/)|Protect|Minimal||
|[T1525 - Implant Container Image](https://attack.mitre.org/techniques/T1525/)|Protect|Minimal|This control may provide recommendations to enable scanning and auditing of container images. This can provide information on images that have been added with high privileges or vulnerabilities.|
|[T1526 - Cloud Service Discovery](https://attack.mitre.org/techniques/T1526/)|Protect|Partial|This control may provide recommendations to enable Azure services that limit access to cloud services. Several Azure services and controls provide mitigations against cloud service discovery.|
|[T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)|Protect|Partial|This control may provide recommendations to enable Azure Defender for Storage and other security controls to prevent access to data from cloud storage objects.|
|[T1535 - Unused/Unsupported Cloud Regions](https://attack.mitre.org/techniques/T1535/)|Protect|Minimal|This control may provide recommendations to restrict the allowed locations your organization can specify when deploying resources or creating resource groups.|
|[T1537 - Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)|Protect|Minimal|This control may provide recommendations to enable security controls that monitor and prevent malicious transfer of data to cloud accounts.|
|[T1538 - Cloud Service Dashboard](https://attack.mitre.org/techniques/T1538/)|Protect|Partial|This control may provide recommendations to enable Azure services that limit access to Azure Resource Manager and other Azure dashboards. Several Azure services and controls provide mitigations against this technique.|
|[T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)|Protect|Minimal|This control may provide recommendations for auditing and hardening Azure Key Vault to prevent malicious access and segment key access.|
|[T1580 - Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/)|Protect|Partial|This control may provide recommendations to enable Azure services that limit access to cloud infrastructure. Several Azure services and controls provide mitigations against cloud infrastructure discovery.|
|[T1590 - Gather Victim Network Information](https://attack.mitre.org/techniques/T1590/)|Protect|Partial|This control may provide recommendations to restrict access to cloud resources from public networks and to route traffic between resources through Azure. Recommendations are also provided to use private DNS zones. If these recommendations are implemented the visible network information should be reduced.|
  


### Tag(s)
- [Azure Security Center Recommendation](#9-azure-security-center-recommendation)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/governance/policy/overview>
- <https://docs.microsoft.com/en-us/azure/governance/policy/samples/built-in-policies#api-for-fhir>
  

  [Back to Table Of Contents](#contents)
## 29. Azure Private Link


Azure Private Link enables you to access Azure PaaS Services (for example, Azure Storage and SQL Database) and Azure hosted customer-owned/partner services over a private endpoint in your virtual network.
Traffic between your virtual network and the service travels the Microsoft backbone network. Exposing your service to the public internet is no longer necessary. You can create your own private link service in your virtual network and deliver it to your customers. Setup and consumption using Azure Private Link is consistent across Azure PaaS, customer-owned, and shared partner services.

- [Mapping File](AzurePrivateLink.yaml)
- [Navigator Layer](layers/AzurePrivateLink.json)

### Mapping Comments


This is a private network service, allowing connections between Azure, on-prem, and 3rd party services without traversing the Internet. Generally this reduces risk from MiTM, DOS, network-based data manipulation and network sniffing from untrusted network.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)|Protect|Partial|Reduced risk of traffic being captured  over the internet|
|[T1498 - Network Denial of Service](https://attack.mitre.org/techniques/T1498/)|Protect|Partial|Provides private path for traffic, eliminating exposure to internet-generated Denial of Service (DOS) attacks.|
|[T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)|Protect|Partial|Prevents Denial of Service (DOS) against systems that would otherwise need to connect via an internet-traversing path (coverage partial, since doesn't apply to systems that must be directly exposed to internet)|
|[T1557 - Man-in-the-Middle](https://attack.mitre.org/techniques/T1557/)|Protect|Partial|Can prevent MiTM attacks wrt traversing the internet.|
|[T1565 - Data Manipulation](https://attack.mitre.org/techniques/T1565/)|Protect|Partial|Can prevent data manipulation in transit by routing over private network|
  


### Tag(s)
- [Azure Security Center Recommendation](#9-azure-security-center-recommendation)
- [Network](#23-network)
  


### Reference(s)
- <https://docs.microsoft.com/azure/private-link/private-link-overview>
  

  [Back to Table Of Contents](#contents)
## 30. Azure Security Center Recommendations


This feature of Azure Security Center assesses your workloads and raises threat prevention recommendations and security alerts.

- [Mapping File](SecurityCenterRecommendations.yaml)
- [Navigator Layer](layers/SecurityCenterRecommendations.json)

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
|[T1080 - Taint Shared Content](https://attack.mitre.org/techniques/T1080/)|Protect|Partial|This control's "Immutable (read-only) root filesystem should be enforced for containers" and "Usage of pod HostPath volume mounts should be restricted to a known list to restrict node access from compromised containers" recommendations can mitigate this technique.  Due to it being a recommendation, it score is capped at Partial.|
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
- [Azure Security Center](#8-azure-security-center)
- [Azure Security Center Recommendation](#9-azure-security-center-recommendation)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/recommendations-reference>
- <https://docs.microsoft.com/en-us/azure/security-center/security-center-introduction>
  

  [Back to Table Of Contents](#contents)
## 31. Azure Sentinel Analytics 1-50


Out of the box Azure Sentinel Analytics (from the rule template list)

- [Mapping File](AzureSentinelAnalytics-1-50.yaml)
- [Navigator Layer](layers/AzureSentinelAnalytics-1-50.json)

### Mapping Comments


Note: only mapped out of the box analytics. Did not score analytics that were specific ioc-based (e.g.  ip addresses or hashes ).  Did not score analytics that required a 3rd party integration (e.g. Alsid or TrendMicro). Refer to specific analytics by name in quotes.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1070 - Indicator Removal on Host](https://attack.mitre.org/techniques/T1070/)|Detect|Partial|"Azure DevOps Agent Pool Created  Then Deleted" detects specific suspicious activity for DevOps Agent Pool. Close to file deletion sub-technique, though not a match.|
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Detect|Partial|May detect suspicious modification of domain trust settings. Also "Correlate Unfamiliar sign-in properties" can enhance detection of anomalous activity.|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Detect|Partial|Can detect "First Access Credential Applied..." which can be a sign of account manipulation to attain persistance etc.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Detect|Partial|"High count of failed logins by a user" is specific to iis server.|
|[T1134 - Access Token Manipulation](https://attack.mitre.org/techniques/T1134/)|Detect|Partial|the "Azure DevOps Perasonal Access Token misuse" Can be used to identify anomalous use of Personal Access Tokens. won't specifically identify sub techniques.|
|[T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)|Detect|Partial|Can detect suspicious app permission consents that are associated with drive-by compromise tricking users into installing a malicious app.|
|[T1484 - Domain Policy Modification](https://attack.mitre.org/techniques/T1484/)|Detect|Partial|Can identify potentially malicious modifiactions of domain policy "Modified Domain Federation Trust Settings"|
|[T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/)|Detect|Partial|"Security Service Registry ACL Modification" can detect attempts to modify registry ACL to evade security solutions.  "Azure DevOps Audit Stream Disabled" can detect audit stream being turned off.|
|[T1566 - Phishing](https://attack.mitre.org/techniques/T1566/)|Detect|Partial|Can detect suspicious app permissions that can be associated with OAuth phishing.|
  


### Reference(s)
  

  [Back to Table Of Contents](#contents)
## 32. Azure Sentinel Analytics 101-150


Out of the box Azure Sentinel Analytics (from the rule template list)

- [Mapping File](AzureSentinelAnalytics-101-150.yaml)
- [Navigator Layer](layers/AzureSentinelAnalytics-101-150.json)

### Mapping Comments


Note: only mapped out of the box analytics. Did not score analytics that were specific ioc-based (e.g.  ip addresses or hashes ).  Did not score analytics that required a 3rd party integration
  (e.g. Alsid or TrendMicro). Refer to specific analytics by name in quotes.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)|Detect|Minimal|This control can identify one of this technique’s sub-techniques when executed via “Powershell Empire cmdlets seen in command line”, but does not address other procedures.|
|[T1016 - System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/)|Detect|Minimal|This control can identify instances of “Powershell Empire cmdlets seen in command line”, at a default frequency of once per day. This covers execution of this technique via Empire, but does not address other procedures.|
|[T1018 - Remote System Discovery](https://attack.mitre.org/techniques/T1018/)|Detect|Partial|Can detect when "Several deny actions registered" due to Azure Firewall incidents, potentially indicating that an adversary is scanning resources on the network, at a default frequency of once per hour. Note that detection only occurs if the firewall prevents the scanning. Can also detect "Rare client observed with high reverse DNS lookup count" if a particular IP is observed performing an unusually high number of reverse DNS lookups and has not been observed doing so previously.|
|[T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)|Detect|Minimal|This control only provides minimal coverage for some of this technique's sub-techniques.|
|[T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)|Detect|Minimal|This control can identify instances of “Powershell Empire cmdlets seen in command line”, at a default frequency of once per day. This covers execution of this technique via Empire, but does not address other procedures.|
|[T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)|Detect|Minimal|This control can identify instances of “Powershell Empire cmdlets seen in command line”, at a default frequency of once per day. This covers execution of this technique via Empire, but does not address other procedures.|
|[T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)|Detect|Minimal|This control can identify instances of “Powershell Empire cmdlets seen in command line”, at a default frequency of once per day. This covers execution of this technique via Empire, but does not address other procedures.|
|[T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046/)|Detect|Partial|Can detect a "High count of connections by client IP on many ports" if a given client IP has 30 or more ports used within a 10 minute window, checked at a default frequency of once per hour. Note that false positives are probable based on changes in usage patterns and/or misconfiguration, and this detection only works if scanning is not spread out over a longer timespan. Scanning via "Powershell Empire cmdlets seen in command line" can also be detected.|
|[T1047 - Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)|Detect|Partial|Can detect when adversaries "Gain Code Execution on ADFS Server via Remote WMI Execution", at a default frequency of once per day. Note that this only looks for this behavior on ADFS servers. WMI use via "Powershell Empire cmdlets seen in command line" can also be detected.|
|[T1049 - System Network Connections Discovery](https://attack.mitre.org/techniques/T1049/)|Detect|Minimal|This control can identify instances of “Powershell Empire cmdlets seen in command line”, at a default frequency of once per day. This covers execution of this technique via Empire, but does not address other procedures.|
|[T1053 - Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)|Detect|Minimal|This control can identify one of this technique’s sub-techniques when executed via “Powershell Empire cmdlets seen in command line”, but does not address other procedures.|
|[T1055 - Process Injection](https://attack.mitre.org/techniques/T1055/)|Detect|Minimal|This control can identify instances of “Powershell Empire cmdlets seen in command line”, at a default frequency of once per day. This covers execution of this technique via Empire, but does not address other procedures.|
|[T1056 - Input Capture](https://attack.mitre.org/techniques/T1056/)|Detect|Minimal|This control can identify two of this technique’s sub-techniques when executed via “Powershell Empire cmdlets seen in command line”, but does not address other procedures.|
|[T1057 - Process Discovery](https://attack.mitre.org/techniques/T1057/)|Detect|Minimal|This control can identify instances of “Powershell Empire cmdlets seen in command line”, at a default frequency of once per day. This covers execution of this technique via Empire, but does not address other procedures.|
|[T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)|Detect|Minimal|This control can identify two of this technique’s sub-techniques when executed via "Powershell Empire cmdlets seen in command line", but does not address other procedures.|
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Detect|Minimal|This control can identify instances of “Powershell Empire cmdlets seen in command line”, at a default frequency of once per day. This covers execution of this technique via Empire, but does not address other procedures.|
|[T1070 - Indicator Removal on Host](https://attack.mitre.org/techniques/T1070/)|Detect|Minimal|This control can identify one of this technique’s sub-techniques when executed via “Powershell Empire cmdlets seen in command line”, but does not address other procedures.|
|[T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)|Detect|Minimal|This control can identify one of this technique’s sub-techniques when executed via "Powershell Empire cmdlets seen in command line", but does not address other procedures.|
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Detect|Minimal|This control only provides coverage for specific cases of the relevant sub-techniques.|
|[T1082 - System Information Discovery](https://attack.mitre.org/techniques/T1082/)|Detect|Minimal|This control can identify instances of “Powershell Empire cmdlets seen in command line”, at a default frequency of once per day. This covers execution of this technique via Empire, but does not address other procedures.|
|[T1083 - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)|Detect|Minimal|This control can identify instances of “Powershell Empire cmdlets seen in command line”, at a default frequency of once per day. This covers execution of this technique via Empire, but does not address other procedures.|
|[T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)|Detect|Minimal|This control can identify two of this technique’s sub-techniques when executed via "Powershell Empire cmdlets seen in command line", but does not address other procedures.|
|[T1102 - Web Service](https://attack.mitre.org/techniques/T1102/)|Detect|Minimal|This control can identify one of this technique’s sub-techniques when executed via “Powershell Empire cmdlets seen in command line”, but does not address other procedures.|
|[T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)|Detect|Minimal|This control can identify instances of “Powershell Empire cmdlets seen in command line”, at a default frequency of once per day. This covers execution of this technique via Empire, but does not address other procedures.|
|[T1106 - Native API](https://attack.mitre.org/techniques/T1106/)|Detect|Minimal|This control can identify instances of “Powershell Empire cmdlets seen in command line”, at a default frequency of once per day. This covers execution of this technique via Empire, but does not address other procedures.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Detect|Partial|This control includes detection coverage for all sub-techniques on a periodic basis.|
|[T1113 - Screen Capture](https://attack.mitre.org/techniques/T1113/)|Detect|Minimal|This control can identify instances of “Powershell Empire cmdlets seen in command line”, at a default frequency of once per day. This covers execution of this technique via Empire, but does not address other procedures.|
|[T1114 - Email Collection](https://attack.mitre.org/techniques/T1114/)|Detect|Minimal|This control can identify one of this technique’s sub-techniques when executed via “Powershell Empire cmdlets seen in command line”, but does not address other procedures.|
|[T1115 - Clipboard Data](https://attack.mitre.org/techniques/T1115/)|Detect|Minimal|This control can identify instances of "Powershell Empire cmdlets seen in command line", at a default frequency of once per day. This covers execution of this technique via Empire, but does not address other procedures.|
|[T1125 - Video Capture](https://attack.mitre.org/techniques/T1125/)|Detect|Minimal|This control can identify instances of “Powershell Empire cmdlets seen in command line”, at a default frequency of once per day. This covers execution of this technique via Empire, but does not address other procedures.|
|[T1127 - Trusted Developer Utilities Proxy Execution](https://attack.mitre.org/techniques/T1127/)|Detect|Minimal|This control can identify one of this technique’s sub-techniques when executed via “Powershell Empire cmdlets seen in command line”, but does not address other procedures.|
|[T1134 - Access Token Manipulation](https://attack.mitre.org/techniques/T1134/)|Detect|Minimal|This control can identify two of this technique’s sub-techniques when executed via "Powershell Empire cmdlets seen in command line", but does not address other procedures.|
|[T1135 - Network Share Discovery](https://attack.mitre.org/techniques/T1135/)|Detect|Minimal|This control can identify instances of “Powershell Empire cmdlets seen in command line”, at a default frequency of once per day. This covers execution of this technique via Empire, but does not address other procedures.|
|[T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)|Detect|Minimal|This control only provides minimal coverage this technique's sub-techniques.|
|[T1137 - Office Application Startup](https://attack.mitre.org/techniques/T1137/)|Detect|Minimal|This control only provides partial coverage for one of this technique's sub-techniques.|
|[T1140 - Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)|Detect|Partial|Can detect "Process executed from binary hidden in Base64 encoded file" based on security event searches for decoding by Python, bash/sh, and Ruby at a default frequency of once per day.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Detect|Minimal|Can detect when "A potentially malicious web request was executed against a web server" based on a high ratio of blocked requests and unobstructed requests to a Web Application Firewall (WAF) for a given client IP and hostname, with a default frequency of once per day.|
|[T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)|Detect|Minimal|This control can identify instances of “Powershell Empire cmdlets seen in command line”, at a default frequency of once per day. This covers execution of this technique via Empire, but does not address other procedures.|
|[T1217 - Browser Bookmark Discovery](https://attack.mitre.org/techniques/T1217/)|Detect|Minimal|This control can identify instances of "Powershell Empire cmdlets seen in command line", at a default frequency of once per day. This covers execution of this technique via Empire, but does not address other procedures.|
|[T1482 - Domain Trust Discovery](https://attack.mitre.org/techniques/T1482/)|Detect|Minimal|This control can identify instances of “Powershell Empire cmdlets seen in command line”, at a default frequency of once per day. This covers execution of this technique via Empire, but does not address other procedures.|
|[T1484 - Domain Policy Modification](https://attack.mitre.org/techniques/T1484/)|Detect|Minimal|This control can identify one of this technique’s sub-techniques when executed via “Powershell Empire cmdlets seen in command line”, but does not address other procedures.|
|[T1518 - Software Discovery](https://attack.mitre.org/techniques/T1518/)|Detect|Minimal|This control can identify one of this technique’s sub-techniques when executed via “Powershell Empire cmdlets seen in command line”, but does not address other procedures.|
|[T1543 - Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)|Detect|Minimal|This control can identify one of this technique’s sub-techniques when executed via “Powershell Empire cmdlets seen in command line”, but does not address other procedures.|
|[T1546 - Event Triggered Execution](https://attack.mitre.org/techniques/T1546/)|Detect|Minimal|This control can identify one of this technique’s sub-techniques when executed via “Powershell Empire cmdlets seen in command line”, but does not address other procedures.|
|[T1547 - Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)|Detect|Minimal|This control can identify three of this technique’s sub-techniques when executed via "Powershell Empire cmdlets seen in command line", but does not address other procedures.|
|[T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)|Detect|Minimal|This control can identify one of this technique’s sub-techniques when executed via "Powershell Empire cmdlets seen in command line", but does not address other procedures.|
|[T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)|Detect|Minimal|This control can identify one of this technique’s sub-techniques when executed via “Powershell Empire cmdlets seen in command line”, but does not address other procedures.|
|[T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)|Detect|Minimal|This control can identify two of this technique’s sub-techniques when executed via “Powershell Empire cmdlets seen in command line”, but does not address other procedures.|
|[T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)|Protect|Minimal|This control provides a highly specific detection for a misconfiguration that can lead to one of this technique's sub-techniques.|
|[T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)|Detect|Minimal|This control can identify one of this technique’s sub-techniques when executed via “Powershell Empire cmdlets seen in command line”, but does not address other procedures.|
|[T1557 - Man-in-the-Middle](https://attack.mitre.org/techniques/T1557/)|Detect|Minimal|This control can identify one of this technique’s sub-techniques when executed via “Powershell Empire cmdlets seen in command line”, but does not address other procedures.|
|[T1558 - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/)|Detect|Minimal|This control only provides minimal to partial coverage for some this technique's sub-techniques.|
|[T1560 - Archive Collected Data](https://attack.mitre.org/techniques/T1560/)|Detect|Minimal|This control can identify instances of "Powershell Empire cmdlets seen in command line", at a default frequency of once per day. This covers execution of this technique via Empire, but does not address other procedures.|
|[T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/)|Detect|Minimal|This control provides coverage for only two of this technique's sub-techniques.|
|[T1567 - Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)|Detect|Minimal|This control can identify both of this technique’s sub-techniques when executed via “Powershell Empire cmdlets seen in command line”, but does not address other procedures.|
|[T1568 - Dynamic Resolution](https://attack.mitre.org/techniques/T1568/)|Detect|Minimal|This control only provides partial coverage for one of this technique's sub-techniques.|
|[T1569 - System Services](https://attack.mitre.org/techniques/T1569/)|Detect|Minimal|This control can identify one of this technique’s sub-techniques when executed via “Powershell Empire cmdlets seen in command line”, but does not address other procedures.|
|[T1573 - Encrypted Channel](https://attack.mitre.org/techniques/T1573/)|Detect|Minimal|This control can identify one of this technique’s sub-techniques when executed via “Powershell Empire cmdlets seen in command line”, but does not address other procedures.|
|[T1574 - Hijack Execution Flow](https://attack.mitre.org/techniques/T1574/)|Detect|Minimal|This control can identify several of this technique’s sub-techniques when executed via “Powershell Empire cmdlets seen in command line”, but does not address other procedures.|
|[T1590 - Gather Victim Network Information](https://attack.mitre.org/techniques/T1590/)|Detect|Minimal|This control detects a highly specific behavior that applies to one sub-technique of this technique.|
|[T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)|Detect|Partial|This control provides partial coverage for one of this technique's two sub-techniques.|
  


### Reference(s)
  

  [Back to Table Of Contents](#contents)
## 33. Azure Sentinel Analytics 151-200


Out of the box Analytics for Azure Sentinel 

- [Mapping File](AzureSentinelAnalytics-151-200.yaml)
- [Navigator Layer](layers/AzureSentinelAnalytics-151-200.json)

### Mapping Comments


Analytics rule templates. note did not score ioc-based or 3rd-party analytics.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)|Detect|Minimal|"Multiple users email forwarded to same destination" can detect potential exfiltration via email. specific method so a minimal score.|
|[T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)|Detect|Partial|"Base64 encoded Windows process command-lines" can identify Base64 encoded PE files being launched from command line.|
|[T1070 - Indicator Removal on Host](https://attack.mitre.org/techniques/T1070/)|Detect|Partial|"Security Event Log cleared" detects potentially malicious clearing of Windows Security events|
|[T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)|Detect|Minimal|"Malformed user agent" can detect potential C2 or C2 agent activity.|
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Detect|Partial|"Failed Host logons but success logon to AzureAD" can detect some potentially malicious domain logon activity that leverages a valid account.  <br/>"|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Detect|Minimal|"Full Admin policy created and then attached to Role, User, or Group" is an AWS-specific analytic that identifies potential account-manipulation for persistence or priv esc. (score mininimal for spcificity) (scoring this 3rd party since AWS can be very commonnly used).<br/>"New access credential added to Application or Service Principal" can identify potentially malicious  additional credentials for privilege esc, persistence<br/>"Suspicious granting of permissions to an account" can identify some potentially illegitimate permission-granting activity (specifically from a previously unseen IP).|
|[T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)|Detect|Partial|"Linked Malicious Storage Artifacts" may identify potential downloaded adversary tools that are missed by anti-malware.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Detect|Minimal|"Hi count of failed attempts same client IP" detects  brute-force password guessing for specific service (iis).|
|[T1195 - Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)|Detect|Partial|"AzureDevops Service Connection Abuse" Can detect potential malicious behavior associated with use of large number of service connections. <br/>"External Upstream Source added to Azure DevOps" identifies a specific behavior that could compromise the devops build pipeline<br/>"Azure DevOps Pull Request Policy Bypassing - History" can identify specific potentially malicious behavior that compromises the build process.<br/>"Azure DevOps Pipeline modified by a New User" identifies potentially malicious activity that could compromise the devops pipeline.<br/>"Azure DevOps Administrator Group Monitoring" monitors for specific activity which could compromise the build/release process.<br/>"New Agent Added to Pool by New User or a New OS" can detect a suspicious behavior that could potentially compromise devops pipeline|
|[T1496 - Resource Hijacking](https://attack.mitre.org/techniques/T1496/)|Detect|Partial|"Process execution frequency anomaly" may detect potential resource hijacking / use of processor.<br/>"Suspicious number of resource (sic) creation or deployed" can identify potential misuse and hijacking of resources.|
|[T1567 - Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)|Detect|Minimal|"Malformed user agent" may detect potential exfiltration over a web service by malcious code with a hard-coded user agent string, or possibly data encoded via the user agent string. spcific method so scoring minimal.<br/>"SharePointFileOperation via previously unseen IPs" may detect potential exfil activity via sharepoint.|
|[T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)|Detect|Minimal|"Malformed user agent" analytic may detect hard-coded user-agent strings associated with an adversary's vulnerability scanning tool.|
  


### Reference(s)
  

  [Back to Table Of Contents](#contents)
## 34. Azure Sentinel Analytics 201-250


Out of the box analytic rule templates for Azure Sentinel

- [Mapping File](AzureSentinelAnalytics-201-250.yaml)
- [Navigator Layer](layers/AzureSentinelAnalytics-201-250.json)

### Mapping Comments


No scoring of 3rd party-dependent analytics or ioc-based analytics (e.g. IP addresses from Threat Intelligence feed)  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)|Detect|Minimal|"Anomalous RDP Login Detections" can identify some potentially suspicious use of RDP<br/>"Multiple RDP connections from Single Systems" can identify above-threshold activity of RDP potentially indicative of lateral movement.|
|[T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)|Detect|Minimal|"New CloudShell User" can detect potentially suspicious Commandline/shell activity. Candidate for additional sub-technique (Cloud Shell, vs powershell etc)<br/>"Rare and Potentially high-risk Office operations" can identify specific rare mailbox-related account and permission changes.|
|[T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)|Detect|Minimal|"Request for single resource on domain" can detect a specific pattern for potential C2 "Beaconing" via web request.|
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Detect|Minimal|"Anomalous SSH Login Detection" can identify some suspicious ssh logins potentially indicative of Valid Acct technique. (local)<br/>"Anomalous RDP Login Detections" can identify some suspicious  RDP activity indicative of Valid Account technique (domain and local)<br/>"Login to AWS management console without MFA" can identify potential use of Valid Account technique (cloud acct)|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Detect|Minimal|"External User Access Enabled" identifies potentially malicious changes to external domain access specific to Zoom.<br/>"External user added and removed in short timeframe" can detect potential account manipulation technique, specific to Teams.<br/>"New user created and added to the built-in administrator group "  can identify potential attempt to maintain persistence with a new user assigned admin privileges.<br/>"Account added and removed from privileged group" can identify potential attempt to evade defense and escalate privilege.|
|[T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)|Detect|Minimal|"New executable via Office FileUploaded Operations" can help identify potential ingress of malicious code and attacker tools to Office services such as Sharepoint and OneDrive (though may generate false positives from normal user exe upload activity)|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Detect|Minimal|"SSH - Potential Brute Force" can detect potential Brute force password guessing for SSH<br/>"SecurityEvent - Multiple authentication failures followed by success" can identify brute force attempts wrt domain access.|
|[T1119 - Automated Collection](https://attack.mitre.org/techniques/T1119/)|Detect|Minimal|"Users searching for VIP user activity" can identify potentially suspicious Log Analytics queries by users looking for a listing of "VIP" activity.|
|[T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)|Detect|Minimal|"New Cloud Shell User" identifies new Azure cloud Shell  that could be potential attempts to maintain persistence.|
|[T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)|Detect|Minimal|"Sensitive Azure Key Vault operations" may help identify attacker attempting to impact data by deleting private key(s) required to decrypt.|
|[T1490 - Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)|Detect|Minimal|"Sensitive Azure Key Vault Operations" may help identify attacker activity that interfers with backups|
|[T1496 - Resource Hijacking](https://attack.mitre.org/techniques/T1496/)|Detect|Partial|"Creation of Expensive Computes in Azure" identifies potential resource hijacking.<br/>"Suspicious Resource deployment" can identify potential resource hijacking.|
|[T1531 - Account Access Removal](https://attack.mitre.org/techniques/T1531/)|Detect|Minimal|"Sensitive Azure Key Vault operations" may identify attempts to remove account access by deleting keys or deleting entire key vault.|
|[T1534 - Internal Spearphishing](https://attack.mitre.org/techniques/T1534/)|Detect|Minimal|"suspicious link sharing pattern" can identify potential internal lateral movement via spearphishing (albeit leveraging Zoom not email). Simple threshold rule for specific service, so minimal score. perhaps candidate for new sub-technique of internal spearphishing .|
|[T1535 - Unused/Unsupported Cloud Regions](https://attack.mitre.org/techniques/T1535/)|Detect|Minimal|"Suspicious Resource deployment" can identify potential attacker attempt to maintain persistence or evade defense. by leveraging unused/unmonitored resources.|
  


### Tag(s)
- [Analytics](#2-analytics)
  


### Reference(s)
  

  [Back to Table Of Contents](#contents)
## 35. Azure Sentinel Analytics 51-100


Out of the box Azure Sentinel Analytics (from the rule template list)

- [Mapping File](AzureSentinelAnalytics-51-100.yaml)
- [Navigator Layer](layers/AzureSentinelAnalytics-51-100.json)

### Mapping Comments


Only mapped out of the box analytics. Did not score analytics that were specific ioc-based (e.g.  ip addresses or hashes ).  Did not score analytics that required a 3rd party integration (e.g. Alsid or TrendMicro). Refer to specific analytics by name in quotes.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)|Detect|Minimal||
|[T1053 - Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)|Detect|Minimal||
|[T1074 - Data Staged](https://attack.mitre.org/techniques/T1074/)|Detect|Minimal||
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Detect|Minimal||
|[T1080 - Taint Shared Content](https://attack.mitre.org/techniques/T1080/)|Detect|Partial|This control may detect "Potential Build Process Compromise" when source code files have been modified immediately after the build process has started. The analytic "ADO Build Variable Modified by New User" may also indicate malicious modification to the build process to taint shared content.|
|[T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)|Detect|Minimal||
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Detect|Minimal||
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Detect|Partial||
|[T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)|Detect|Minimal|This control may detect "Gain Code Execution on ADFS Server via SMB + Remote Service or Scheduled Task"|
|[T1213 - Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)|Detect|Minimal||
|[T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)|Detect|Minimal||
|[T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)|Detect|Minimal||
|[T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)|Detect|Minimal|This control may detect when "MFA disabled for a user" and "GitHub Two Factor Auth Disable".|
|[T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/)|Detect|Minimal||
|[T1600 - Weaken Encryption](https://attack.mitre.org/techniques/T1600/)|Detect|Minimal|This control may detect when "Zoom E2E Encryption Disabled".|
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/sentinel/overview>
  

  [Back to Table Of Contents](#contents)
## 36. Azure VPN Gateway


A VPN gateway is a specific type of virtual network gateway that is used to send encrypted traffic between an Azure virtual network and an on-premises location over the public Internet. 
You can also use a VPN gateway to send encrypted traffic between Azure virtual networks over the Microsoft network.

- [Mapping File](AzureVPN.yaml)
- [Navigator Layer](layers/AzureVPN.json)

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)|Protect|Significant|Prevents capture of information in transit.|
|[T1557 - Man-in-the-Middle](https://attack.mitre.org/techniques/T1557/)|Protect|Significant|Prevents intercept and manipulation of data in transit.|
|[T1565 - Data Manipulation](https://attack.mitre.org/techniques/T1565/)|Protect|Partial|Covers data in transit.|
  


### Tag(s)
- [Azure VPN Gateway](#11-azure-vpn-gateway)
- [Encryption](#17-encryption)
- [Network](#23-network)
- [VPN](#26-vpn)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-about-vpngateways>
  

  [Back to Table Of Contents](#contents)
## 37. Azure Web Application Firewall


Azure Web Application Firewall (WAF) provides centralized protection of your web applications  from common exploits and vulnerabilities.


- [Mapping File](AzureWebApplicationFirewall.yaml)
- [Navigator Layer](layers/AzureWebApplicationFirewall.json)

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1001 - Data Obfuscation](https://attack.mitre.org/techniques/T1001/)|Detect|Partial||
|[T1001 - Data Obfuscation](https://attack.mitre.org/techniques/T1001/)|Protect|Partial|Some protocol enforcement for T1001.003 Protocol Impersonation|
|[T1008 - Fallback Channels](https://attack.mitre.org/techniques/T1008/)|Detect|Partial||
|[T1008 - Fallback Channels](https://attack.mitre.org/techniques/T1008/)|Protect|Partial||
|[T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)|Detect|Partial||
|[T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)|Protect|Partial||
|[T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046/)|Detect|Partial|May provide telemetry or trigger a scanner signature|
|[T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046/)|Protect|Partial|May block some ports|
|[T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)|Detect|Partial||
|[T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)|Protect|Partial||
|[T1056 - Input Capture](https://attack.mitre.org/techniques/T1056/)|Detect|Partial||
|[T1056 - Input Capture](https://attack.mitre.org/techniques/T1056/)|Protect|Partial|Web portal capture|
|[T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)|Detect|Partial||
|[T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)|Protect|Partial||
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Detect|Partial||
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Protect|Partial|Covers some techniques traversing the perimeter.|
|[T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)|Detect|Partial||
|[T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)|Protect|Partial||
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Detect|Significant||
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Protect|Significant||
|[T1203 - Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)|Detect|Partial||
|[T1203 - Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)|Protect|Partial||
|[T1205 - Traffic Signaling](https://attack.mitre.org/techniques/T1205/)|Detect|Minimal|Provides telemetry but wouldn't identify the activity as bad or block it|
|[T1491 - Defacement](https://attack.mitre.org/techniques/T1491/)|Detect|Partial||
|[T1491 - Defacement](https://attack.mitre.org/techniques/T1491/)|Protect|Partial|Note will identify direct attacks, not defacing due to abuse of a valid account, not internal defacement from compromised internal host|
|[T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)|Detect|Significant||
|[T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)|Protect|Significant||
|[T1526 - Cloud Service Discovery](https://attack.mitre.org/techniques/T1526/)|Detect|Minimal|Minimal: some telemetry for detect|
|[T1567 - Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)|Detect|Partial||
|[T1567 - Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)|Protect|Partial||
|[T1572 - Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)|Detect|Partial||
|[T1572 - Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)|Protect|Partial||
|[T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)|Protect|Partial|Covers web app vulnerabilities, not other services.|
  


### Tag(s)
- [Azure Security Center Recommendation](#9-azure-security-center-recommendation)
- [WAF](#27-waf)
- [Web](#28-web)
- [Web Access Firewall](#29-web-access-firewall)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/web-application-firewall/overview>
  

  [Back to Table Of Contents](#contents)
## 38. Cloud App Security Policies


Microsoft Cloud App Security is a Cloud Access Security Broker (CASB) that supports various deployment modes including log collection, API connectors, and reverse proxy. It provides rich visibility, control over data travel, and sophisticated analytics to identify and combat cyberthreats across all your Microsoft and third-party cloud services.

- [Mapping File](CloudAppSecurity.yaml)
- [Navigator Layer](layers/CloudAppSecurity.json)

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Detect|Partial|Can identify anomalous behavior such as geographically impossible logins and out-of-character activity.|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Detect|Partial|Can detect anomalous admin activity|
|[T1119 - Automated Collection](https://attack.mitre.org/techniques/T1119/)|Detect|Partial|Can detect sensitive information at rest.|
|[T1119 - Automated Collection](https://attack.mitre.org/techniques/T1119/)|Protect|Partial|Information protection policies can detect and encrypt sensitive information at rest on supported platforms.|
|[T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)|Protect|Partial|Polices of reverse proxy can limit abuse of access from remote devices.|
|[T1187 - Forced Authentication](https://attack.mitre.org/techniques/T1187/)|Detect|Partial|Can alert on anomalous file sharing|
|[T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)|Detect|Partial|Can detect outdated client browser|
|[T1213 - Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)|Detect|Partial|May detect anomalous user behavior wrt information repositories such as Sharepoint or Confluence.|
|[T1219 - Remote Access Software](https://attack.mitre.org/techniques/T1219/)|Protect|Significant|Can limit potential C2 via unapproved remote access software|
|[T1484 - Domain Policy Modification](https://attack.mitre.org/techniques/T1484/)|Detect|Partial|Can detect admin activity from risky IP addresses.|
|[T1526 - Cloud Service Discovery](https://attack.mitre.org/techniques/T1526/)|Detect|Partial|Can detect anomalous user activity that may be associated with cloud service discovery.|
|[T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)|Detect|Partial|Can detect potentially risky apps|
|[T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)|Detect|Partial|Can detect use of unsanctioned business apps and data exfil to unsanctioned storage apps.|
|[T1531 - Account Access Removal](https://attack.mitre.org/techniques/T1531/)|Detect|Partial|Can identify anomalous admin activity|
|[T1535 - Unused/Unsupported Cloud Regions](https://attack.mitre.org/techniques/T1535/)|Detect|Partial|Can detect unusual region for cloud resource (preview feature as of this writing)|
|[T1565 - Data Manipulation](https://attack.mitre.org/techniques/T1565/)|Protect|Partial|Can detect and encrypt sensitive information at rest on supported platforms, and restrict access.|
|[T1567 - Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)|Detect|Partial|Can identify large volume exfil|
|[T1578 - Modify Cloud Compute Infrastructure](https://attack.mitre.org/techniques/T1578/)|Detect|Partial|Can identify anomalous admin activity|
  


### Tag(s)
- [CASB](#12-casb)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/cloud-app-security/policies-cloud-discovery>
- <https://docs.microsoft.com/en-us/cloud-app-security/policies-information-protection>
  

  [Back to Table Of Contents](#contents)
## 39. Conditional Access


The modern security perimeter now extends beyond an organization's network to include user and device identity. Organizations can utilize these identity signals as part of their access control decisions.  Conditional Access is the tool used by Azure Active Directory to bring signals together, to make decisions, and enforce organizational policies. Conditional Access is at the heart of the new identity driven control plane.

- [Mapping File](ConditionalAccess.yaml)
- [Navigator Layer](layers/ConditionalAccess.json)

### Mapping Comments


At first glance, this control seems mappable to Exfiltration (sub-)techniques but upon further analysis, it doesn't really mitigate exfiltration but rather its prerequisite Collection (sub-)techniques.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1074 - Data Staged](https://attack.mitre.org/techniques/T1074/)|Protect|Minimal|This control only provides the ability to restrict file downloads for a limited set of applications and therefore its overall Coverage score is minimal.|
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Protect|Minimal|This control only provides protection for one of this technique's sub-techniques while not providing any protection for the remaining and therefore its coverage score is Minimal, resulting in a Minimal score.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Protect|Significant|Conditional Access can be used to enforce MFA for users which provides significant protection against  password compromises, requiring an adversary to complete an additional authentication method before their access is permitted.|
|[T1213 - Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)|Protect|Minimal|This control only provides the ability to restrict an adversary from collecting valuable information for a limited set of applications (SharePoint, Exchange, OneDrive) and therefore its overall Coverage score is minimal.|
|[T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)|Protect|Minimal|Conditional Access, when granting (risky) users access to cloud storage, specifically OneDrive, can restrict what they can do in these applications using its app-enforced restrictions.   For example, it can enforce that users on unmanaged devices will have browser-only access to OneDrive with no ability to download, print, or sync files.  This can impede an adversary's ability to exfiltrate data from OneDrive.  The protection coverage provided by this control is Minimal as it doesn't provide protection for other storage services available on Azure such as the Azure Storage service.|
  


### Tag(s)
- [Azure Active Directory](#3-azure-active-directory)
- [Identity](#19-identity)
- [MFA](#21-mfa)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/overview>
  

  [Back to Table Of Contents](#contents)
## 40. Continuous Access Evaluation


Continuous Access Evaluation (CAE) provides the next level of identity security by terminating active user sessions to a subset of Microsoft services (Exchange and Teams) in real-time on changes such as account disable, password reset, and admin initiated user revocation.  CAE aims to improve the response time in situations where a policy setting that applies to a user changes but the user is able to circumvent the new policy setting because their OAuth access token was issued before the policy change.  It’s typical that security access tokens issued by Azure AD, like OAuth 2.0 access tokens, are valid for an hour.
CAE enables the scenario where users lose access to organizational SharePoint Online files, email, calendar, or tasks, and Teams from Microsoft 365 client apps within mins after critical security events (such as user account is deleted, MFA is enabled for a user, High user risk detected by Azure AD Identity Protection, etc.).

- [Mapping File](ContinuousAccessEvaluation.yaml)
- [Navigator Layer](layers/ContinuousAccessEvaluation.json)

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Respond|Minimal|This control only protects cloud accounts and therefore its overall coverage is minimal resulting in a Minimal respond score for this technique.|
  


### Tag(s)
- [Azure Active Directory](#3-azure-active-directory)
- [Identity](#19-identity)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/concept-continuous-access-evaluation>
  

  [Back to Table Of Contents](#contents)
## 41. Docker Host Hardening


Azure Security Center identifies unmanaged containers hosted on IaaS Linux VMs, or other Linux machines running Docker containers. Security Center continuously assesses the configurations of these containers. It then compares them with the Center for Internet Security (CIS) Docker Benchmark. Security Center includes the entire ruleset of the CIS Docker Benchmark and alerts you if your containers don't satisfy any of the controls. When it finds misconfigurations, Security Center generates security recommendations.

- [Mapping File](DockerHostHardening.yaml)
- [Navigator Layer](layers/DockerHostHardening.json)

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1005 - Data from Local System](https://attack.mitre.org/techniques/T1005/)|Protect|Partial|This control may provide recommendations that limit the ability of an attacker to gain access to a host from a container, preventing the attacker from discovering and compromising local system data.|
|[T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)|Protect|Minimal||
|[T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)|Protect|Minimal|This control may recommend usage of TLS to encrypt communication between the Docker daemon and clients. This can prevent possible leakage of sensitive information through network sniffing.|
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Protect|Partial|This control may provide recommendations on how to reduce the surface area and mechanisms by which an attacker could escalate privileges.|
|[T1083 - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)|Protect|Minimal|This control may provide recommendations to ensure sensitive host system directories are not mounted in the container.|
|[T1525 - Implant Container Image](https://attack.mitre.org/techniques/T1525/)|Detect|Minimal|This control may alert on Docker containers that are misconfigured or do not conform to CIS Docker Benchmarks. This may result in detection of container images implanted within Linux VMs with specific vulnerabilities or misconfigurations for malicious purposes.|
|[T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)|Protect|Minimal|This control is only relevant for Linux endpoints containing Docker containers.|
  


### Tag(s)
- [Azure Security Center](#8-azure-security-center)
- [Containers](#13-containers)
- [Linux](#20-linux)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/harden-docker-hosts>
  

  [Back to Table Of Contents](#contents)
## 42. File Integrity Monitoring


File integrity monitoring (FIM), also known as change monitoring, examines  operating system files, Windows registries, application software, Linux  system files, and more, for changes that might indicate an attack. File Integrity Monitoring (FIM) informs you when changes occur to sensitive  areas in your resources, so you can investigate and address unauthorized  activity. 


- [Mapping File](FileIntegrityMonitoring.yaml)
- [Navigator Layer](layers/FileIntegrityMonitoring.json)

### Mapping Comments


The techniques included in this mapping result in Windows Registry or file system artifacts being created or modified which can be detected by this control.  
The detection score for most techniques included in this mapping was scored as Significant and where there are exceptions, comments have been provided. This Significant score assessment  was due to the following factors: Coverage - (High) The control was able to detect most of the sub-techniques, references and procedure examples of the mapped techniques. Accuracy - (High) Although this control does not include built-in intelligence to minimize  the false positive rate, the specific artifacts generated by the techniques in this mapping do not change frequently and therefore the potential for a high false-positive is reduced.  Temporal - (Medium) This control at worst scans for changes on an hourly basis.
  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)|Detect|Minimal|Most credential dumping operations do not require modifying resources that can be detected by this control (i.e. Registry and File system) and therefore its coverage is minimal.|
|[T1037 - Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1037/)|Detect|Significant||
|[T1053 - Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)|Detect|Significant||
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Detect|Minimal||
|[T1137 - Office Application Startup](https://attack.mitre.org/techniques/T1137/)|Detect|Minimal||
|[T1222 - File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222/)|Detect|Partial|This control can detect file and directory permissions modifications for Windows but there is no indication it can do so for Linux platforms.|
|[T1543 - Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)|Detect|Significant||
|[T1546 - Event Triggered Execution](https://attack.mitre.org/techniques/T1546/)|Detect|Partial|The detection score for this technique was assessed as Partial because it doesn't detect some of the sub-techniques of this technique such as Windows Management Instrumentation (WMI) Event Subscription and Trap sub-techniques.  Additionally for  some sub-techniques, this control can be noisy.<br/>|
|[T1547 - Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)|Detect|Significant||
|[T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)|Detect|Minimal||
|[T1553 - Subvert Trust Controls](https://attack.mitre.org/techniques/T1553/)|Detect|Partial|This control can be used to detect a subset of this technique's sub-techniques while minimizing the false positive rate.|
|[T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)|Detect|Partial|This control is effective for detecting the Registry and file system artifacts that are generated during the execution of some variations of this technique while minimizing false positives due to the locations being monitored changing infrequently (e.g. /etc/pam.d/).|
|[T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/)|Detect|Minimal|Due to low detection coverage, this technique is scored as minimal.|
|[T1574 - Hijack Execution Flow](https://attack.mitre.org/techniques/T1574/)|Detect|Minimal||
  


### Tag(s)
- [Azure Defender](#4-azure-defender)
- [Azure Defender for Servers](#7-azure-defender-for-servers)
- [Azure Security Center](#8-azure-security-center)
- [Azure Security Center Recommendation](#9-azure-security-center-recommendation)
- [File system](#18-file-system)
- [Linux](#20-linux)
- [Registry](#25-registry)
- [Windows](#30-windows)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/security-center-file-integrity-monitoring>
  

  [Back to Table Of Contents](#contents)
## 43. Integrated Vulnerability Scanner Powered by Qualys


This control provides a on-demand and scheduled vulnerability scan for Windows and Linux endpoints that are being protected by Azure Defender. The scanner generates a list of possible vulnerabilities in Azure Security Center for possible remediation. 

- [Mapping File](VulnerabilityAssessmentQualys.yaml)
- [Navigator Layer](layers/VulnerabilityAssessmentQualys.json)

### Mapping Comments


Once this control is deployed, it will run a scan every four hours and scans can be run on demand. Documentation notes that within 48 hours of the disclosure of a critical vulnerability, Qualys incorporates the information into their processing and can identify affected machines.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Protect|Partial|Once this control is deployed, it can detect known vulnerabilities in Windows and various Linux endpoints. This information can be used to patch, isolate, or remove vulnerable software and machines. This control does not directly protect against exploitation and it is not effective against zero day attacks, vulnerabilities with no available patch, and software that may not be analyzed by the scanner.|
|[T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)|Protect|Partial|Once this control is deployed, it can detect known vulnerabilities in Windows and various Linux endpoints. This information can be used to patch, isolate, or remove vulnerable software and machines. This control does not directly protect against exploitation and it is not effective against zero day attacks, vulnerabilities with no available patch, and software that may not be analyzed by the scanner.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Protect|Partial|Once this control is deployed, it can detect known vulnerabilities in Windows and various Linux endpoints. This information can be used to patch, isolate, or remove vulnerable software and machines. This control does not directly protect against exploitation and it is not effective against zero day attacks, vulnerabilities with no available patch, and software that may not be analyzed by the scanner.|
|[T1203 - Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)|Protect|Partial|Once this control is deployed, it can detect known vulnerabilities in Windows and various Linux endpoints. This information can be used to patch, isolate, or remove vulnerable software and machines. This control does not directly protect against exploitation and it is not effective against zero day attacks, vulnerabilities with no available patch, and software that may not be analyzed by the scanner.|
|[T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)|Protect|Partial|Once this control is deployed, it can detect known vulnerabilities in Windows and various Linux endpoints. This information can be used to patch, isolate, or remove vulnerable software and machines. This control does not directly protect against exploitation and it is not effective against zero day attacks, vulnerabilities with no available patch, and software that may not be analyzed by the scanner.|
|[T1211 - Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211/)|Protect|Partial|Once this control is deployed, it can detect known vulnerabilities in Windows and various Linux endpoints. This information can be used to patch, isolate, or remove vulnerable software and machines. This control does not directly protect against exploitation and it is not effective against zero day attacks, vulnerabilities with no available patch, and software that may not be analyzed by the scanner.|
|[T1212 - Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212/)|Protect|Partial|Once this control is deployed, it can detect known vulnerabilities in Windows and various Linux endpoints. This information can be used to patch, isolate, or remove vulnerable software and machines. This control does not directly protect against exploitation and it is not effective against zero day attacks, vulnerabilities with no available patch, and software that may not be analyzed by the scanner.|
  


### Tag(s)
- [Azure Defender](#4-azure-defender)
- [Azure Security Center](#8-azure-security-center)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/deploy-vulnerability-assessment-vm>
- <https://docs.microsoft.com/en-us/azure/security-center/remediate-vulnerability-findings-vm>
  

  [Back to Table Of Contents](#contents)
## 44. Just-in-Time VM Access


This control locks down inbound traffic to management ports for protocols such as RDP and SSH and only provides access upon request for a specified period of time. This reduces exposure to attacks while providing easy access when you need to connect to a virtual machine. Specific permissions are required to request access to virtual machines that have this control enabled and access can be requested through the Azure web UI, PowerShell, and a REST API.

- [Mapping File](JustInTimeVMAccess.yaml)
- [Navigator Layer](layers/JustInTimeVMAccess.json)

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Protect|Significant|This control can be configured to completely block inbound access to selected ports until access is requested. This prevents any attempt at brute forcing a protocol, such as RDP or SSH, unless the attacker has the credentials and permissions to request such access. Even if permission has been granted to an authorized user to access the virtual machine, a list of authorized IP addresses for that access can be configured.|
|[T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)|Protect|Significant|This control can be configured to completely block inbound access to selected ports until access is requested. This prevents any attempt at utilizing external remote services, such as RDP or a VPN, unless the attacker has the credentials and permissions to request such access. Even if permission has been granted to an authorized user to access the virtual machine, a list of authorized IP addresses for that access can be configured.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Protect|Significant|This control can be configured to completely block inbound access to selected ports until access is requested. This prevents any attempt at exploitation of a public-facing application unless the attacker has the credentials and permissions to request such access. Even if permission has been granted to an authorized user to access the virtual machine, a list of authorized IP addresses for that access can be configured.|
  


### Tag(s)
- [Azure Defender for Servers](#7-azure-defender-for-servers)
- [Azure Security Center](#8-azure-security-center)
- [Azure Security Center Recommendation](#9-azure-security-center-recommendation)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/security-center-just-in-time?tabs=jit-config-asc%2Cjit-request-api>
- <https://docs.microsoft.com/en-us/azure/security-center/just-in-time-explained>
  

  [Back to Table Of Contents](#contents)
## 45. Linux auditd alerts and Log Analytics agent integration


This integration enables collection of auditd events in all supported Linux distributions, without any prerequisites. Auditd records are collected, enriched, and aggregated into events by using the Log Analytics agent for Linux agent.

- [Mapping File](LinuxAuditdAndLogAnalytics.yaml)
- [Navigator Layer](layers/LinuxAuditdAndLogAnalytics.json)

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)|Detect|Partial|This control is only relevant for Linux environments.|
|[T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)|Detect|Minimal|This control is only relevant for Linux environments. Among the sub-techinques that are relevant for Linux, this control may only alert on SSH.|
|[T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)|Detect|Minimal|This control only provides detection coverage for the Compile After Delivery sub-technique while not providing detection for all other sub-techniques relevant to the Linux platform.  As a result of this minimal coverage, the overall score is assessed as Minimal.|
|[T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)|Detect|Minimal|This control may alert on suspicious Unix shell and PHP execution. Mismatched script extensions may also generate alerts of suspicious activity.|
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Detect|Minimal|This control may alert on suspicious arguments used to exploit Xorg vulnerabilities for privilege escalation.|
|[T1070 - Indicator Removal on Host](https://attack.mitre.org/techniques/T1070/)|Detect|Partial|This control is only relevant for Linux environments and may alert on multiple sub-techniques.|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Detect|Minimal||
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Detect|Partial||
|[T1113 - Screen Capture](https://attack.mitre.org/techniques/T1113/)|Detect|Partial|This control may alert on usage of a screenshot tool. Documentation is not provided on the logic for determining a screenshot tool.|
|[T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)|Detect|Partial|This control is only relevant for Linux endpoints.|
|[T1505 - Server Software Component](https://attack.mitre.org/techniques/T1505/)|Detect|Minimal|The only sub-technique this control is relevant for is Web Shell.|
|[T1525 - Implant Container Image](https://attack.mitre.org/techniques/T1525/)|Detect|Partial|This control may alert on suspicious container images running mining software or SSH servers. Privileged Docker containers and privileged commands running within containers may also be detected. These alerts are only generated on containers in Linux endpoint machines and not for containers running from Azure Docker deployment.|
|[T1547 - Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)|Detect|Minimal|This control is only relevant for Linux endpoint machines and the only sub-technique relevant for Linux is Kernel Modules and Extensions.|
|[T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/)|Detect|Minimal|This control only provides coverage for two sub-techniques under this technique and provides no coverage for other relevant sub-techniques, such as, Impair Command History Logging or Disable or Modify Tools.|
|[T1564 - Hide Artifacts](https://attack.mitre.org/techniques/T1564/)|Detect|Minimal||
  


### Tag(s)
- [Azure Defender](#4-azure-defender)
- [Linux](#20-linux)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security-center/defender-for-servers-introduction>
- <https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-linux>
  

  [Back to Table Of Contents](#contents)
## 46. Managed identities for Azure resources


Managed identities for Azure resources provide Azure services with an automatically managed identity in Azure Active Directory. You can use this identity to authenticate to any service that supports Azure AD authentication, without having to hard-code credentials in your code.

- [Mapping File](AzureADManagedIdentities.yaml)
- [Navigator Layer](layers/AzureADManagedIdentities.json)

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)|Protect|Minimal|This control provides protection for one of this technique's sub-techniques, while not providing any protection for the remaining, resulting in a Minimal score.|
  


### Tag(s)
- [Azure Active Directory](#3-azure-active-directory)
- [Azure Security Center Recommendation](#9-azure-security-center-recommendation)
- [Identity](#19-identity)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview>
  

  [Back to Table Of Contents](#contents)
## 47. Microsoft Antimalware for Azure


Microsoft Antimalware for Azure is a free real-time protection that helps identify and remove viruses, spyware, and other malicious software. It generates alerts when known malicious or unwanted software tries to install itself or run on your Azure systems. 

- [Mapping File](MicrosoftAntimalwareForAzure.yaml)
- [Navigator Layer](layers/MicrosoftAntimalwareForAzure.json)

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
- [Azure Security Center](#8-azure-security-center)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/security/fundamentals/antimalware>
- <https://docs.microsoft.com/en-us/azure/security/fundamentals/antimalware-code-samples>
  

  [Back to Table Of Contents](#contents)
## 48. Microsoft Defender for Identity


Microsoft Defender for Identity (formerly Azure Advanced Threat Protection, also known as Azure ATP) is a cloud-based security solution that leverages your on-premises Active Directory signals to identify, detect, and investigate advanced threats, compromised identities, and malicious insider actions directed at your organization.

- [Mapping File](MicrosoftDefenderForIdentity.yaml)
- [Navigator Layer](layers/MicrosoftDefenderForIdentity.json)

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
- [Credentials](#14-credentials)
- [DNS](#15-dns)
- [Identity](#19-identity)
- [Microsoft 365 Defender](#22-microsoft-365-defender)
- [Windows](#30-windows)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/defender-for-identity/what-is>
  

  [Back to Table Of Contents](#contents)
## 49. Network Security Groups


You can use an Azure network security group to filter network traffic to and from Azure resources in an Azure virtual network. A network security group contains security rules that allow or deny inbound network traffic to, or outbound network traffic from, several types of Azure resources. For each rule, you can specify source and destination, port, and protocol.

- [Mapping File](NetworkSecurityGroups.yaml)
- [Navigator Layer](layers/NetworkSecurityGroups.json)

### Mapping Comments


Note: one can employ Application Security Groups (ASG) in Network Security Group (NSG) rules to map  rules to workloads etc. Not scoring ASG as a separate control. One can employ Adaptive Network Hardening (ANH)  to generate recommended NSG rules based on traffic, known trusted configuration, threat intelligence, and other inidcators of compromise. Not scoring ANH as a separate control.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)|Protect|Partial|Can deny direct access to remote services with NSG rules to restrict access via proxies etc.|
|[T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046/)|Protect|Significant|Can restrict access on host and port basis|
|[T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)|Protect|Significant|NSG can minimize alternative protocols allowed to communicate externally.|
|[T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)|Protect|Partial|Can restrict some protocols, though not inspect/restrict the application layer|
|[T1072 - Software Deployment Tools](https://attack.mitre.org/techniques/T1072/)|Protect|Partial|Can limit access to critical systems.|
|[T1090 - Proxy](https://attack.mitre.org/techniques/T1090/)|Protect|Partial|Can restrict ports and inter-system / inter-enclave connections. Doesn't cover domain-fronting.|
|[T1095 - Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1095/)|Protect|Significant|Can restrict non-application layer protocols between systems and enclaves.|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Protect|Partial|Can limit access to domain controllers etc.|
|[T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)|Protect|Partial|Can restrict access to remote services to trusted paths and proxies.|
|[T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)|Protect|Partial|Can limit network access to domain controllers. Partial coverage domain and cloud account techniques.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Protect|Partial|Can segment externally facing servers from the rest of the network|
|[T1199 - Trusted Relationship](https://attack.mitre.org/techniques/T1199/)|Protect|Partial|Can isolate portions of network that do not require network-wide access, limiting some attackers that leverage trusted relationships such as remote access for vendor maintenance. Coverage partial, Temporal Immediate|
|[T1205 - Traffic Signaling](https://attack.mitre.org/techniques/T1205/)|Protect|Partial|Can restrict communication by port.|
|[T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)|Protect|Partial|Can restrict access to remote services to minimum necessary.|
|[T1219 - Remote Access Software](https://attack.mitre.org/techniques/T1219/)|Protect|Partial|Can restrict system and enclave communications|
|[T1482 - Domain Trust Discovery](https://attack.mitre.org/techniques/T1482/)|Protect|Partial|Can isolate sensitive domains to limit discovery|
|[T1498 - Network Denial of Service](https://attack.mitre.org/techniques/T1498/)|Protect|Partial|Can restrict direct access to systems. Partial since can't restrict incoming requests (more anti-DDOS and firewall with rate-limiting)|
|[T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)|Protect|Partial|Can restrict direct access to endpoints|
|[T1542 - Pre-OS Boot](https://attack.mitre.org/techniques/T1542/)|Protect|Minimal|Can cover one sub-technique partially (booting from remote devies ala TFTP boot)|
|[T1557 - Man-in-the-Middle](https://attack.mitre.org/techniques/T1557/)|Protect|Partial|Limits the ability of attackers to intercept/redirect traffic to just within the defined enclaves.|
|[T1563 - Remote Service Session Hijacking](https://attack.mitre.org/techniques/T1563/)|Protect|Partial|Can limit/minimize connectivity via RDP and SSH.|
|[T1565 - Data Manipulation](https://attack.mitre.org/techniques/T1565/)|Protect|Minimal|Covers only manipulation in transit.|
|[T1570 - Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/)|Protect|Significant|Can limit traffic between systems and enclaves to minimum necessary.|
|[T1571 - Non-Standard Port](https://attack.mitre.org/techniques/T1571/)|Protect|Significant|Can restrict traffic to standard ports.|
|[T1602 - Data from Configuration Repository](https://attack.mitre.org/techniques/T1602/)|Protect|Partial|Can limit attackers access to configuration repositories such as SNMP management stations, or to dumps of client configurations from common management ports.|
  


### Tag(s)
- [Adaptive Network Hardening](#1-adaptive-network-hardening)
- [Azure Security Center Recommendation](#9-azure-security-center-recommendation)
- [Network](#23-network)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview>
- <https://docs.microsoft.com/en-us/azure/virtual-network/network-security-group-how-it-works>
- <https://docs.microsoft.com/en-us/azure/security-center/security-center-adaptive-network-hardening>
  

  [Back to Table Of Contents](#contents)
## 50. Passwordless Authentication


Features like multi-factor authentication (MFA) are a great way to secure your organization, but users often get frustrated with the additional security layer on top of having to remember their passwords. Passwordless authentication methods are more convenient because the password is removed and replaced with something you have, plus something you are or something you know.

- [Mapping File](PasswordlessAuthentication.yaml)
- [Navigator Layer](layers/PasswordlessAuthentication.json)

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Protect|Significant|This control provides significant protection against this brute force technique by completing obviating the need for passwords by replacing it with passwordless credentials.|
  


### Tag(s)
- [Azure Active Directory](#3-azure-active-directory)
- [Credentials](#14-credentials)
- [Identity](#19-identity)
- [Passwords](#24-passwords)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-passwordless>
  

  [Back to Table Of Contents](#contents)
## 51. Role Based Access Control


Access management for cloud resources is a critical function for any organization that is using the cloud. Azure role-based access control (Azure RBAC) helps you manage who has access to Azure resources, what they can do with those resources, and what areas they have access to.


- [Mapping File](AzureADRoleBasedAccessControl.yaml)
- [Navigator Layer](layers/AzureADRoleBasedAccessControl.json)

### Mapping Comments


RBAC enables organizations to limit the number of users within the organization with an IAM role that has administrative privileges.  This enables limiting the number of users within the tenant that have privileged access thereby resulting in a reduced attack surface and a coverage score factor of Partial.  Most sub-techniques have been scored as Partial for this reason.  


### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Protect|Minimal|This control only provides protection for one of this technique's sub-techniques while not providing any protection for the remaining and therefore its coverage score factor is Minimal, resulting in a Minimal score.|
|[T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)|Protect|Minimal|This control only provides protection for one of this technique's sub-techniques while not providing any protection for the remaining and therefore its coverage score factor is Minimal, resulting in a Minimal score.|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Protect|Partial|This control provides protection for some of this technique's sub-techniques and therefore its coverage score factor is Partial, resulting in a Partial score.|
|[T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)|Protect|Minimal|This control only provides protection for one of this technique's sub-techniques while not providing any protection for the remaining and therefore its coverage score factor is Minimal, resulting in a Minimal score.|
|[T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)|Protect|Partial|This control can be used to limit the number of users that are authorized to grant consent to applications for accessing organizational data.  This can reduce the likelihood that a user is fooled into granting consent to a malicious application that then utilizes the user's OAuth access token to access organizational data.|
|[T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)|Protect|Partial|This control can be used to limit the number of users that have access to storage solutions except for the applications, users, and services that require access, thereby reducing the attack surface.|
|[T1538 - Cloud Service Dashboard](https://attack.mitre.org/techniques/T1538/)|Protect|Partial|This control can be used to limit the number of users that have dashboard visibility thereby reducing the attack surface.|
|[T1578 - Modify Cloud Compute Infrastructure](https://attack.mitre.org/techniques/T1578/)|Protect|Partial|This control provides partial protection for all of its sub-techniques and therefore its coverage score factor is Partial, resulting in a Partial score.|
|[T1580 - Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/)|Protect|Partial|This control can be used to limit the number of users that have privileges to discover cloud infrastructure thereby reducing an organization's cloud infrastructure attack surface.|
  


### Tag(s)
- [Azure Active Directory](#3-azure-active-directory)
- [Azure Security Center Recommendation](#9-azure-security-center-recommendation)
- [Identity](#19-identity)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/role-based-access-control/overview>
  

  [Back to Table Of Contents](#contents)
## 52. SQL Vulnerability Assessment


SQL vulnerability assessment is a service that provides visibility into your security state. The service employs a knowledge base of rules that flag security vulnerabilities. It highlights deviations from best practices, such as misconfigurations, excessive permissions, and unprotected sensitive data.

- [Mapping File](SQLVulnerabilityAssessment.yaml)
- [Navigator Layer](layers/SQLVulnerabilityAssessment.json)

### Technique(s)

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Protect|Partial|This control may scan for users with unnecessary permissions and if SQL Server is out of date.|
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Protect|Minimal||
|[T1112 - Modify Registry](https://attack.mitre.org/techniques/T1112/)|Protect|Minimal|This control may scan for any stored procedures that can access the Registry and checks that permission to execute those stored procedures have been revoked from all users (other than dbo).|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Protect|Partial|This control provides recommendations to patch if SQL server is out of date and to disable unneeded features to reduce exploitable surface area.|
|[T1505 - Server Software Component](https://attack.mitre.org/techniques/T1505/)|Protect|Minimal||
  


### Tag(s)
- [Azure Defender for SQL](#6-azure-defender-for-sql)
- [Database](#16-database)
  


### Reference(s)
- <https://docs.microsoft.com/en-us/azure/azure-sql/database/sql-vulnerability-assessment>
- <https://docs.microsoft.com/en-us/azure/azure-sql/database/sql-database-vulnerability-assessment-rules>
  

  [Back to Table Of Contents](#contents)
# Control Tags

## 1. Adaptive Network Hardening

### Controls
- [Network Security Groups](#49-network-security-groups)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Adaptive_Network_Hardening.json)
  

  [Back to Table Of Contents](#contents)
## 2. Analytics

### Controls
- [Azure Alerts for Network Layer](#12-azure-alerts-for-network-layer)
- [Azure Network Traffic Analytics](#27-azure-network-traffic-analytics)
- [Azure Sentinel Analytics 201-250](#34-azure-sentinel-analytics-201-250)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Analytics.json)
  

  [Back to Table Of Contents](#contents)
## 3. Azure Active Directory

### Controls
- [Azure AD Identity Protection](#6-azure-ad-identity-protection)
- [Azure AD Identity Secure Score](#7-azure-ad-identity-secure-score)
- [Azure AD Multi-Factor Authentication](#8-azure-ad-multi-factor-authentication)
- [Azure AD Password Policy](#9-azure-ad-password-policy)
- [Azure AD Privileged Identity Management](#10-azure-ad-privileged-identity-management)
- [Azure Active Directory Password Protection](#11-azure-active-directory-password-protection)
- [Conditional Access](#39-conditional-access)
- [Continuous Access Evaluation](#40-continuous-access-evaluation)
- [Managed identities for Azure resources](#46-managed-identities-for-azure-resources)
- [Passwordless Authentication](#50-passwordless-authentication)
- [Role Based Access Control](#51-role-based-access-control)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Azure_Active_Directory.json)
  

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
- [File Integrity Monitoring](#42-file-integrity-monitoring)
- [Integrated Vulnerability Scanner Powered by Qualys](#43-integrated-vulnerability-scanner-powered-by-qualys)
- [Linux auditd alerts and Log Analytics agent integration](#45-linux-auditd-alerts-and-log-analytics-agent-integration)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Azure_Defender.json)
  

  [Back to Table Of Contents](#contents)
## 5. Azure Defender for App Service

### Controls
- [Azure Defender for App Service](#19-azure-defender-for-app-service)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Azure_Defender_for_App_Service.json)
  

  [Back to Table Of Contents](#contents)
## 6. Azure Defender for SQL

### Controls
- [Advanced Threat Protection for Azure SQL Database](#2-advanced-threat-protection-for-azure-sql-database)
- [SQL Vulnerability Assessment](#52-sql-vulnerability-assessment)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Azure_Defender_for_SQL.json)
  

  [Back to Table Of Contents](#contents)
## 7. Azure Defender for Servers

### Controls
- [Adaptive Application Controls](#1-adaptive-application-controls)
- [Alerts for Windows Machines](#5-alerts-for-windows-machines)
- [File Integrity Monitoring](#42-file-integrity-monitoring)
- [Just-in-Time VM Access](#44-just-in-time-vm-access)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Azure_Defender_for_Servers.json)
  

  [Back to Table Of Contents](#contents)
## 8. Azure Security Center

### Controls
- [Adaptive Application Controls](#1-adaptive-application-controls)
- [Advanced Threat Protection for Azure SQL Database](#2-advanced-threat-protection-for-azure-sql-database)
- [Alerts for Azure Cosmos DB](#3-alerts-for-azure-cosmos-db)
- [Azure Alerts for Network Layer](#12-azure-alerts-for-network-layer)
- [Azure Defender for App Service](#19-azure-defender-for-app-service)
- [Azure Security Center Recommendations](#30-azure-security-center-recommendations)
- [Docker Host Hardening](#41-docker-host-hardening)
- [File Integrity Monitoring](#42-file-integrity-monitoring)
- [Integrated Vulnerability Scanner Powered by Qualys](#43-integrated-vulnerability-scanner-powered-by-qualys)
- [Just-in-Time VM Access](#44-just-in-time-vm-access)
- [Microsoft Antimalware for Azure](#47-microsoft-antimalware-for-azure)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Azure_Security_Center.json)
  

  [Back to Table Of Contents](#contents)
## 9. Azure Security Center Recommendation

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
- [Azure Web Application Firewall](#37-azure-web-application-firewall)
- [File Integrity Monitoring](#42-file-integrity-monitoring)
- [Just-in-Time VM Access](#44-just-in-time-vm-access)
- [Managed identities for Azure resources](#46-managed-identities-for-azure-resources)
- [Network Security Groups](#49-network-security-groups)
- [Role Based Access Control](#51-role-based-access-control)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Azure_Security_Center_Recommendation.json)
  

  [Back to Table Of Contents](#contents)
## 10. Azure Sentinel

### Controls
- [Azure Defender for Storage](#24-azure-defender-for-storage)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Azure_Sentinel.json)
  

  [Back to Table Of Contents](#contents)
## 11. Azure VPN Gateway

### Controls
- [Azure VPN Gateway](#36-azure-vpn-gateway)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Azure_VPN_Gateway.json)
  

  [Back to Table Of Contents](#contents)
## 12. CASB

### Controls
- [Cloud App Security Policies](#38-cloud-app-security-policies)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/CASB.json)
  

  [Back to Table Of Contents](#contents)
## 13. Containers

### Controls
- [Azure Defender for Container Registries](#20-azure-defender-for-container-registries)
- [Azure Defender for Kubernetes](#22-azure-defender-for-kubernetes)
- [Docker Host Hardening](#41-docker-host-hardening)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Containers.json)
  

  [Back to Table Of Contents](#contents)
## 14. Credentials

### Controls
- [Azure AD Identity Protection](#6-azure-ad-identity-protection)
- [Azure AD Identity Secure Score](#7-azure-ad-identity-secure-score)
- [Azure AD Multi-Factor Authentication](#8-azure-ad-multi-factor-authentication)
- [Azure AD Password Policy](#9-azure-ad-password-policy)
- [Azure Active Directory Password Protection](#11-azure-active-directory-password-protection)
- [Azure Dedicated HSM](#18-azure-dedicated-hsm)
- [Azure Defender for Key Vault](#21-azure-defender-for-key-vault)
- [Azure Key Vault](#26-azure-key-vault)
- [Microsoft Defender for Identity](#48-microsoft-defender-for-identity)
- [Passwordless Authentication](#50-passwordless-authentication)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Credentials.json)
  

  [Back to Table Of Contents](#contents)
## 15. DNS

### Controls
- [Alerts for DNS](#4-alerts-for-dns)
- [Azure DNS Alias Records](#16-azure-dns-alias-records)
- [Azure DNS Analytics](#17-azure-dns-analytics)
- [Microsoft Defender for Identity](#48-microsoft-defender-for-identity)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/DNS.json)
  

  [Back to Table Of Contents](#contents)
## 16. Database

### Controls
- [Advanced Threat Protection for Azure SQL Database](#2-advanced-threat-protection-for-azure-sql-database)
- [Alerts for Azure Cosmos DB](#3-alerts-for-azure-cosmos-db)
- [SQL Vulnerability Assessment](#52-sql-vulnerability-assessment)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Database.json)
  

  [Back to Table Of Contents](#contents)
## 17. Encryption

### Controls
- [Azure VPN Gateway](#36-azure-vpn-gateway)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Encryption.json)
  

  [Back to Table Of Contents](#contents)
## 18. File system

### Controls
- [File Integrity Monitoring](#42-file-integrity-monitoring)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/File_system.json)
  

  [Back to Table Of Contents](#contents)
## 19. Identity

### Controls
- [Azure AD Identity Protection](#6-azure-ad-identity-protection)
- [Azure AD Identity Secure Score](#7-azure-ad-identity-secure-score)
- [Azure AD Multi-Factor Authentication](#8-azure-ad-multi-factor-authentication)
- [Azure AD Password Policy](#9-azure-ad-password-policy)
- [Azure AD Privileged Identity Management](#10-azure-ad-privileged-identity-management)
- [Azure Active Directory Password Protection](#11-azure-active-directory-password-protection)
- [Conditional Access](#39-conditional-access)
- [Continuous Access Evaluation](#40-continuous-access-evaluation)
- [Managed identities for Azure resources](#46-managed-identities-for-azure-resources)
- [Microsoft Defender for Identity](#48-microsoft-defender-for-identity)
- [Passwordless Authentication](#50-passwordless-authentication)
- [Role Based Access Control](#51-role-based-access-control)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Identity.json)
  

  [Back to Table Of Contents](#contents)
## 20. Linux

### Controls
- [Azure Automation Update Management](#13-azure-automation-update-management)
- [Azure Defender for App Service](#19-azure-defender-for-app-service)
- [Docker Host Hardening](#41-docker-host-hardening)
- [File Integrity Monitoring](#42-file-integrity-monitoring)
- [Linux auditd alerts and Log Analytics agent integration](#45-linux-auditd-alerts-and-log-analytics-agent-integration)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Linux.json)
  

  [Back to Table Of Contents](#contents)
## 21. MFA

### Controls
- [Azure AD Identity Secure Score](#7-azure-ad-identity-secure-score)
- [Azure AD Multi-Factor Authentication](#8-azure-ad-multi-factor-authentication)
- [Azure AD Privileged Identity Management](#10-azure-ad-privileged-identity-management)
- [Conditional Access](#39-conditional-access)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/MFA.json)
  

  [Back to Table Of Contents](#contents)
## 22. Microsoft 365 Defender

### Controls
- [Azure AD Identity Protection](#6-azure-ad-identity-protection)
- [Microsoft Defender for Identity](#48-microsoft-defender-for-identity)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Microsoft_365_Defender.json)
  

  [Back to Table Of Contents](#contents)
## 23. Network

### Controls
- [Alerts for DNS](#4-alerts-for-dns)
- [Azure Alerts for Network Layer](#12-azure-alerts-for-network-layer)
- [Azure DDOS Protection Standard](#15-azure-ddos-protection-standard)
- [Azure DNS Alias Records](#16-azure-dns-alias-records)
- [Azure DNS Analytics](#17-azure-dns-analytics)
- [Azure Firewall](#25-azure-firewall)
- [Azure Network Traffic Analytics](#27-azure-network-traffic-analytics)
- [Azure Private Link](#29-azure-private-link)
- [Azure VPN Gateway](#36-azure-vpn-gateway)
- [Network Security Groups](#49-network-security-groups)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Network.json)
  

  [Back to Table Of Contents](#contents)
## 24. Passwords

### Controls
- [Azure AD Multi-Factor Authentication](#8-azure-ad-multi-factor-authentication)
- [Azure AD Password Policy](#9-azure-ad-password-policy)
- [Azure Active Directory Password Protection](#11-azure-active-directory-password-protection)
- [Azure Key Vault](#26-azure-key-vault)
- [Passwordless Authentication](#50-passwordless-authentication)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Passwords.json)
  

  [Back to Table Of Contents](#contents)
## 25. Registry

### Controls
- [File Integrity Monitoring](#42-file-integrity-monitoring)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Registry.json)
  

  [Back to Table Of Contents](#contents)
## 26. VPN

### Controls
- [Azure VPN Gateway](#36-azure-vpn-gateway)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/VPN.json)
  

  [Back to Table Of Contents](#contents)
## 27. WAF

### Controls
- [Azure Web Application Firewall](#37-azure-web-application-firewall)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/WAF.json)
  

  [Back to Table Of Contents](#contents)
## 28. Web

### Controls
- [Azure Web Application Firewall](#37-azure-web-application-firewall)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Web.json)
  

  [Back to Table Of Contents](#contents)
## 29. Web Access Firewall

### Controls
- [Azure Web Application Firewall](#37-azure-web-application-firewall)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Web_Access_Firewall.json)
  

  [Back to Table Of Contents](#contents)
## 30. Windows

### Controls
- [Alerts for Windows Machines](#5-alerts-for-windows-machines)
- [Azure Automation Update Management](#13-azure-automation-update-management)
- [Azure Defender for App Service](#19-azure-defender-for-app-service)
- [File Integrity Monitoring](#42-file-integrity-monitoring)
- [Microsoft Defender for Identity](#48-microsoft-defender-for-identity)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Windows.json)
  

  [Back to Table Of Contents](#contents)