
Azure Controls
==============

Contents
========

* [Introduction](#introduction)
* [Controls](#controls)
	* [Adaptive Application Controls](#adaptive-application-controls)
	* [Advanced Threat Protection for Azure SQL Database](#advanced-threat-protection-for-azure-sql-database)
	* [Alerts for Azure Cosmos DB](#alerts-for-azure-cosmos-db)
	* [Alerts for DNS](#alerts-for-dns)
	* [Alerts for Windows Machines](#alerts-for-windows-machines)
	* [Azure AD Identity Protection](#azure-ad-identity-protection)
	* [Azure AD Identity Secure Score](#azure-ad-identity-secure-score)
	* [Azure AD Multi-Factor Authentication](#azure-ad-multi-factor-authentication)
	* [Azure AD Password Policy](#azure-ad-password-policy)
	* [Azure AD Privileged Identity Management](#azure-ad-privileged-identity-management)
	* [Azure Active Directory Password Protection](#azure-active-directory-password-protection)
	* [Azure Alerts for Network Layer](#azure-alerts-for-network-layer)
	* [Azure Automation Update Management](#azure-automation-update-management)
	* [Azure Backup](#azure-backup)
	* [Azure DDOS Protection Standard](#azure-ddos-protection-standard)
	* [Azure DNS Alias Records](#azure-dns-alias-records)
	* [Azure DNS Analytics](#azure-dns-analytics)
	* [Azure Dedicated HSM](#azure-dedicated-hsm)
	* [Azure Defender for App Service](#azure-defender-for-app-service)
	* [Azure Defender for Container Registries](#azure-defender-for-container-registries)
	* [Azure Defender for Key Vault](#azure-defender-for-key-vault)
	* [Azure Defender for Kubernetes](#azure-defender-for-kubernetes)
	* [Azure Defender for Resource Manager](#azure-defender-for-resource-manager)
	* [Azure Defender for Storage](#azure-defender-for-storage)
	* [Azure Firewall](#azure-firewall)
	* [Azure Key Vault](#azure-key-vault)
	* [Azure Network Traffic Analytics](#azure-network-traffic-analytics)
	* [Azure Policy](#azure-policy)
	* [Azure Private Link](#azure-private-link)
	* [Azure Security Center Recommendations](#azure-security-center-recommendations)
	* [Azure Sentinel Analytics 1-50](#azure-sentinel-analytics-1-50)
	* [Azure Sentinel Analytics 101-150](#azure-sentinel-analytics-101-150)
	* [Azure Sentinel Analytics 151-200](#azure-sentinel-analytics-151-200)
	* [Azure VPN Gateway](#azure-vpn-gateway)
	* [Azure Web Application Firewall](#azure-web-application-firewall)
	* [Cloud App Security Policies](#cloud-app-security-policies)
	* [Conditional Access](#conditional-access)
	* [Continuous Access Evaluation](#continuous-access-evaluation)
	* [Docker Host Hardening](#docker-host-hardening)
	* [File Integrity Monitoring](#file-integrity-monitoring)
	* [Integrated Vulnerability Scanner Powered by Qualys](#integrated-vulnerability-scanner-powered-by-qualys)
	* [Just-in-Time(JIT) VM Access](#just-in-timejit-vm-access)
	* [Linux auditd alerts and Log Analytics agent integration](#linux-auditd-alerts-and-log-analytics-agent-integration)
	* [Managed identities for Azure resources](#managed-identities-for-azure-resources)
	* [Microsoft Antimalware for Azure](#microsoft-antimalware-for-azure)
	* [Microsoft Defender for Identity](#microsoft-defender-for-identity)
	* [Network Security Groups](#network-security-groups)
	* [Passwordless Authentication](#passwordless-authentication)
	* [Role Based Access Control](#role-based-access-control)
	* [SQL Vulnerability Assessment](#sql-vulnerability-assessment)
* [Tags](#tags)
	* [Adaptive Network Hardening](#adaptive-network-hardening)
	* [Analytics](#analytics)
	* [Azure Active Directory](#azure-active-directory)
	* [Azure Defender](#azure-defender)
	* [Azure Defender for App Service](#azure-defender-for-app-service)
	* [Azure Defender for SQL](#azure-defender-for-sql)
	* [Azure Defender for Servers](#azure-defender-for-servers)
	* [Azure Security Center](#azure-security-center)
	* [Azure Security Center Recommendation](#azure-security-center-recommendation)
	* [Azure Sentinel](#azure-sentinel)
	* [Azure VPN Gateway](#azure-vpn-gateway)
	* [CASB](#casb)
	* [Containers](#containers)
	* [Credentials](#credentials)
	* [DNS](#dns)
	* [Database](#database)
	* [Encryption](#encryption)
	* [File system](#file-system)
	* [Identity](#identity)
	* [Linux](#linux)
	* [MFA](#mfa)
	* [Microsoft 365 Defender](#microsoft-365-defender)
	* [Network](#network)
	* [Passwords](#passwords)
	* [Registry](#registry)
	* [VPN](#vpn)
	* [WAF](#waf)
	* [Web](#web)
	* [Web Access Firewall](#web-access-firewall)
	* [Windows](#windows)

# Introduction


This page enumerates the native security controls available on the Azure platform that have been mapped to [MITRE ATT&CK](https://attack.mitre.org/).  <br>Most controls included in scope were derived from the [Azure Security Benchmark (v2)](https://docs.microsoft.com/en-us/azure/security/benchmarks/overview) and our own independent research.
# Controls

## Adaptive Application Controls


Security Center uses machine learning to analyze the applications running on machines and create a list of known-safe software. Allow lists are based on specific Azure workloads and can be further customized. They are based on trusted paths, publishers, and hashes. When Adaptive Application Controls are enabled, security alerts are generated when applications are run that have not been defined as safe.

- [Mapping File](AdaptiveApplicationControls.yaml)
- [Navigator Layer](layers/AdaptiveApplicationControls.json)

### Technique(s)
- [T1036 - Masquerading](https://attack.mitre.org/techniques/T1036/)
- [T1204 - User Execution](https://attack.mitre.org/techniques/T1204/)
- [T1553 - Subvert Trust Controls](https://attack.mitre.org/techniques/T1553/)
  


### Tag(s)
- [Azure Defender for Servers](#azure-defender-for-servers)
- [Azure Security Center](#azure-security-center)
- [Azure Security Center Recommendation](#azure-security-center-recommendation)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/security-center/security-center-adaptive-application
  


## Advanced Threat Protection for Azure SQL Database


This control provides alerts for Azure SQL Database, Azure SQL Managed Instance, and Azure Synapse Analytics. An alert may be generated on suspicious database activities, potential vulnerabilities, and SQL injection attacks, as well as anomalous database access and query patterns.

- [Mapping File](ATPForAzureSQLDatabase.yaml)
- [Navigator Layer](layers/ATPForAzureSQLDatabase.json)

### Technique(s)
- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1213 - Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)
  


### Tag(s)
- [Azure Defender](#azure-defender)
- [Azure Defender for SQL](#azure-defender-for-sql)
- [Azure Security Center](#azure-security-center)
- [Azure Security Center Recommendation](#azure-security-center-recommendation)
- [Database](#database)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/azure-sql/database/threat-detection-overview
- https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-sql-db-and-warehouse
  


## Alerts for Azure Cosmos DB


The Azure Cosmos DB alerts are generated by unusual and potentially harmful attempts to access or exploit Azure Cosmos DB accounts.

- [Mapping File](AlertsForAzureCosmosDB.yaml)
- [Navigator Layer](layers/AlertsForAzureCosmosDB.json)

### Technique(s)
- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1213 - Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)
  


### Mapping Comments


This control is still in preview, so its coverage will likely expand in the future. This mapping is based on its current (preview) state.  


### Tag(s)
- [Azure Security Center](#azure-security-center)
- [Database](#database)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/security-center/alerts-reference
- https://docs.microsoft.com/en-us/azure/security-center/other-threat-protections
- https://docs.microsoft.com/en-us/azure/cosmos-db/cosmos-db-advanced-threat-protection
  


## Alerts for DNS


Azure Defender for DNS provides an additional layer of protection for your cloud resources by continuously monitoring all DNS queries from your Azure resources and running advanced security analytics to alert you about suspicious activity


- [Mapping File](AlertsForDNS.yaml)
- [Navigator Layer](layers/AlertsForDNS.json)

### Technique(s)
- [T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [T1090 - Proxy](https://attack.mitre.org/techniques/T1090/)
- [T1568 - Dynamic Resolution](https://attack.mitre.org/techniques/T1568/)
- [T1572 - Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
  


### Tag(s)
- [DNS](#dns)
- [Network](#network)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/security-center/defender-for-dns-introduction 
- "https://docs.microsoft.com/en-us/azure/security-center/defender-for-dns-introduction https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-resourcemanager"
  


## Alerts for Windows Machines


For Windows, Azure Defender integrates with Azure services to monitor and protect your Windows-based machines. Security Center presents the alerts and remediation suggestions from all of these services in an easy-to-use format.

- [Mapping File](AlertsForWindowsMachines.yaml)
- [Navigator Layer](layers/AlertsForWindowsMachines.json)

### Technique(s)
- [T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [T1055 - Process Injection](https://attack.mitre.org/techniques/T1055/)
- [T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [T1070 - Indicator Removal on Host](https://attack.mitre.org/techniques/T1070/)
- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1082 - System Information Discovery](https://attack.mitre.org/techniques/T1082/)
- [T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)
- [T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
- [T1112 - Modify Registry](https://attack.mitre.org/techniques/T1112/)
- [T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)
- [T1140 - Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)
- [T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1202 - Indirect Command Execution](https://attack.mitre.org/techniques/T1202/)
- [T1203 - Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)
- [T1204 - User Execution](https://attack.mitre.org/techniques/T1204/)
- [T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)
- [T1211 - Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211/)
- [T1212 - Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212/)
- [T1218 - Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)
- [T1222 - File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222/)
- [T1489 - Service Stop](https://attack.mitre.org/techniques/T1489/)
- [T1543 - Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)
- [T1546 - Event Triggered Execution](https://attack.mitre.org/techniques/T1546/)
- [T1547 - Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)
- [T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)
- [T1558 - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/)
- [T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/)
- [T1563 - Remote Service Session Hijacking](https://attack.mitre.org/techniques/T1563/)
- [T1564 - Hide Artifacts](https://attack.mitre.org/techniques/T1564/)
  


### Tag(s)
- [Azure Defender](#azure-defender)
- [Azure Defender for Servers](#azure-defender-for-servers)
- [Windows](#windows)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/security-center/defender-for-servers-introduction
- https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-windows
  


## Azure AD Identity Protection


Identity Protection is a tool that allows organizations to accomplish three key tasks:
Automate the detection and remediation of identity-based risks.
Investigate risks using data in the portal.
Export risk detection data to third-party utilities for further analysis.


- [Mapping File](IdentityProtection.yaml)
- [Navigator Layer](layers/IdentityProtection.json)

### Technique(s)
- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1606 - Forge Web Credentials](https://attack.mitre.org/techniques/T1606/)
  


### Tag(s)
- [Azure Active Directory](#azure-active-directory)
- [Credentials](#credentials)
- [Identity](#identity)
- [Microsoft 365 Defender](#microsoft-365-defender)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-investigate-risk
- https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/overview-identity-protection
- https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/concept-identity-protection-risks
- https://techcommunity.microsoft.com/t5/azure-active-directory-identity/azuread-identity-protection-adds-support-for-federated/ba-p/244328
  


## Azure AD Identity Secure Score


The identity secure score is a percentage that functions as an indicator for how aligned you are with Microsoft's best practice recommendations for security. Each improvement action in Identity Secure Score is tailored to your specific configuration.  The score helps you to:  Objectively measure your identity security posture, plan identity security improvements, and review the success of your improvements.  
Every 48 hours, Azure looks at your security configuration and compares your settings with the recommended best practices. Based on the outcome of this evaluation, a new score is calculated for your directory.

- [Mapping File](AzureADIdentitySecureScore.yaml)
- [Navigator Layer](layers/AzureADIdentitySecureScore.json)

### Technique(s)
- [T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)
- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
- [T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)
- [T1134 - Access Token Manipulation](https://attack.mitre.org/techniques/T1134/)
- [T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [T1531 - Account Access Removal](https://attack.mitre.org/techniques/T1531/)
- [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)
- [T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
- [T1558 - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/)
- [T1606 - Forge Web Credentials](https://attack.mitre.org/techniques/T1606/)
  


### Mapping Comments


This control was mapped to (sub-)techniques based on the Security Score improvement actions listed in a sample Azure AD tenant that we provisioned.  We were unable to find a comprehensive list of the security checks made by the control listed in its documentation.  We did note that there were some improvement actions listed that our tenant received the max score, leading us to believe that the actions listed were the complete list of checks and not just those that were outstanding for our tenant.
The following improvement actions were analyzed:
Require MFA for administrative roles, Designate more than one global admin,  Do not allow users to grant consent to unmanaged applications, Use limited administrative roles, Do not expire passwords, Enable policy to block legacy authentication  Turn on sign-in risk policy, Turn on user risk policy, Ensure all users can complete multi-factor authentication for secure access, Enable self-service password reset, Resolve unsecure account attributes, Reduce lateral movement path risk to sensitive entities,  Set a honeytoken account, Stop clear text credentials exposure, Install Defender for Identity Sensor on all Domain Controllers,  Disable Print spooler service on domain controllers, Configure VPN integration,  Configure Microsoft Defender for Endpoint Integration (*excluded, would increase the scope, see mapping for Microsoft  Defender for Endpoint), Stop legacy protocols communication, Stop weak cipher usage,  Remove dormant accounts from sensitive groups, Protect and manage local admin passwords with Microsoft LAPS,  Remove unsecure SID history attributes from entities, Fix Advanced Audit Policy issues, Modify unsecure Kerberos  delegations to prevent impersonation. 
All scores were capped at Partial since this control provides recommendations rather than applying/enforcing the recommended actions.  


### Tag(s)
- [Azure Active Directory](#azure-active-directory)
- [Credentials](#credentials)
- [Identity](#identity)
- [MFA](#mfa)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/identity-secure-score
- https://techcommunity.microsoft.com/t5/azure-active-directory-identity/new-tools-to-block-legacy-authentication-in-your-organization/ba-p/1225302#
- https://docs.microsoft.com/en-us/defender-for-identity/cas-isp-unsecure-account-attributes
- https://techcommunity.microsoft.com/t5/microsoft-defender-for-identity/new-identity-security-posture-assessments-riskiest-lmps-and/m-p/1491675
  


## Azure AD Multi-Factor Authentication


Multi-factor authentication is a process where a user is prompted during the sign-in process for an additional form of identification, such as to enter a code on their cellphone or to provide a fingerprint scan.
If you only use a password to authenticate a user, it leaves an insecure vector for attack. If  the password is weak or has been exposed elsewhere, is it really the user signing in with the  username and password, or is it an attacker? When you require a second form of authentication, security is increased as this additional factor isn't something that's easy for an attacker to  obtain or duplicate.

- [Mapping File](AzureADMultiFactorAuthentication.yaml)
- [Navigator Layer](layers/AzureADMultiFactorAuthentication.json)

### Technique(s)
- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
  


### Mapping Comments


Note that MFA that is triggered in response to privileged operations (such as assigning a user a privileged role) are considered functionality of the Azure AD Privileged Identity Management control.  Consult the mapping for this control for the ATT&CK (sub-)techniques it maps to.  This mapping specifically deals with MFA when it is enabled as a security default.  


### Tag(s)
- [Azure Active Directory](#azure-active-directory)
- [Azure Security Center Recommendation](#azure-security-center-recommendation)
- [Credentials](#credentials)
- [Identity](#identity)
- [MFA](#mfa)
- [Passwords](#passwords)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks
  


## Azure AD Password Policy


A password policy is applied to all user accounts that are created and managed directly in Azure Active Directory (AD). Some of these password policy settings can't be modified, though you can configure custom banned passwords for Azure AD password protection or account lockout parameters.

- [Mapping File](AzureADPasswordPolicy.yaml)
- [Navigator Layer](layers/AzureADPasswordPolicy.json)

### Technique(s)
- [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
  


### Mapping Comments


Most scores have been assessed as Partial because this control increases the strength of user passwords thereby reducing the likelihood of a successful brute force attack.  But given sufficient resources, an adversary may still successfully execute the attack vectors included  in this mapping.  


### Tag(s)
- [Azure Active Directory](#azure-active-directory)
- [Credentials](#credentials)
- [Identity](#identity)
- [Passwords](#passwords)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-sspr-policy#password-policies-that-only-apply-to-cloud-user-accounts
  


## Azure AD Privileged Identity Management


Privileged Identity Management (PIM) is a service in Azure Active Directory (Azure AD) that enables you to manage, control, and monitor access to important resources in your organization. These resources include resources in Azure AD, Azure, and other Microsoft Online Services such as Microsoft 365 or Microsoft Intune.

- [Mapping File](PrivilegedIdentityManagement.yaml)
- [Navigator Layer](layers/PrivilegedIdentityManagement.json)

### Technique(s)
- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)
  


### Tag(s)
- [Azure Active Directory](#azure-active-directory)
- [Identity](#identity)
- [MFA](#mfa)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure
  


## Azure Active Directory Password Protection


Azure AD Password Protection detects and blocks known weak passwords and their variants,  and can also block additional weak terms that are specific to your organization. Azure AD Password Protection provides a global banned password list that is automatically applied to all users in an Azure AD tenant.  The Azure AD Identity Protection team constantly analyzes Azure AD security telemetry data looking for commonly used weak or compromised passwords.  When weak terms are found, they're added to the global banned password list. To support your own business and security needs, you can define entries in a custom banned  password list. When users change or reset their passwords, these banned  password lists are checked to enforce the use of strong passwords.


- [Mapping File](AzureADPasswordProtection.yaml)
- [Navigator Layer](layers/AzureADPasswordProtection.json)

### Technique(s)
- [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
  


### Mapping Comments


All scores have been assessed as Partial because this control increases the strength of user passwords thereby reducing the likelihood of a successful brute force attack.  Due to the fact that a user's password is not checked  against the banned list of passwords unless the user changes or resets their  password (which is an infrequent event), there is still ample opportunity  for attackers to utilize this technique to gain access. This is what prevented the score from being elevated to Significant.
  


### Tag(s)
- [Azure Active Directory](#azure-active-directory)
- [Credentials](#credentials)
- [Identity](#identity)
- [Passwords](#passwords)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-password-ban-bad
  


## Azure Alerts for Network Layer


Security Center network-layer analytics are based on sample IPFIX data, which are packet headers collected by Azure core routers. Based on this data feed, Security Center uses machine learning models to identify and flag malicious traffic activities. Security Center also uses the Microsoft Threat Intelligence database to enrich IP addresses.

- [Mapping File](AlertsNetworkLayer.yaml)
- [Navigator Layer](layers/AlertsNetworkLayer.json)

### Technique(s)
- [T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
  


### Mapping Comments


Associated with the Azure Security Center.
The alerts can pick up outbound Denial of Service (DOS) attacks, though that's not an ATT&CK technique  per se (description oriented towards inbound DOS), also is a form of resource hijacking (though not in ATT&CK description, which is oriented towards cryptomining).  


### Tag(s)
- [Analytics](#analytics)
- [Azure Security Center](#azure-security-center)
- [Network](#network)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-azurenetlayer
  


## Azure Automation Update Management


"Use Azure Automation Update Management or a third-party solution to ensure that the most recent security updates are installed on your Windows and Linux VMs. "

- [Mapping File](AzureAutomationUpdateMGT.yaml)
- [Navigator Layer](layers/AzureAutomationUpdateMGT.json)

### Technique(s)
- [T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [T1072 - Software Deployment Tools](https://attack.mitre.org/techniques/T1072/)
- [T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1195 - Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)
- [T1203 - Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)
- [T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)
- [T1211 - Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211/)
- [T1212 - Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212/)
- [T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)
- [T1554 - Compromise Client Software Binary](https://attack.mitre.org/techniques/T1554/)
  


### Mapping Comments


Generally applies to techniques that leverage vulnerabilities in unpatched software, which tend to be a subset of possible methods for a given TTP.   


### Tag(s)
- [Linux](#linux)
- [Windows](#windows)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/automation/update-management/overview
  


## Azure Backup


"The Azure Backup service provides simple, secure, and cost-effective solutions to back up your data and recover it from the Microsoft Azure cloud."

- [Mapping File](AzureBackup.yaml)
- [Navigator Layer](layers/AzureBackup.json)

### Technique(s)
- [T1485 - Data Destruction](https://attack.mitre.org/techniques/T1485/)
- [T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [T1491 - Defacement](https://attack.mitre.org/techniques/T1491/)
- [T1561 - Disk Wipe](https://attack.mitre.org/techniques/T1561/)
  


### Mapping Comments


Azure Backup service provides defense against destruction/manipulation of data at rest. Scoring as "Significant" since it is an essential practice against data destruction et al, though there is an argument for a Partial score since it does not prevent so much as enable recovery.  


### Tag(s)
- [Azure Security Center Recommendation](#azure-security-center-recommendation)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/backup/backup-overview
  


## Azure DDOS Protection Standard


Azure DDoS Protection Standard, combined with application design best practices, provides enhanced DDoS mitigation features to defend against DDoS attacks. 
It is automatically tuned to help protect your specific Azure resources in a virtual network.

- [Mapping File](AzureDDOS.yaml)
- [Navigator Layer](layers/AzureDDOS.json)

### Technique(s)
- [T1498 - Network Denial of Service](https://attack.mitre.org/techniques/T1498/)
- [T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)
  


### Tag(s)
- [Azure Security Center Recommendation](#azure-security-center-recommendation)
- [Network](#network)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview
  


## Azure DNS Alias Records


Azure DNS alias records are qualifications on a DNS record set. They can reference other Azure resources from within your DNS zone.   For example, you can create an alias record set that references an Azure public IP address instead of an A record. Your alias record set points to an Azure public IP address service instance dynamically. As a result, the alias record set seamlessly updates itself during DNS resolution.


- [Mapping File](AzureDNSAliasRecords.yaml)
- [Navigator Layer](layers/AzureDNSAliasRecords.json)

### Technique(s)
- [T1584 - Compromise Infrastructure](https://attack.mitre.org/techniques/T1584/)
  


### Tag(s)
- [DNS](#dns)
- [Network](#network)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/dns/dns-alias#prevent-dangling-dns-records
  


## Azure DNS Analytics


"DNS Analytics helps you to: identify clients that try to resolve malicious domain names, identify stale resource records, identify frequently queried domain names and talkative DNS clients,  view request load on DNS servers, and view dynamic DNS registration failures.
The solution collects, analyzes, and correlates Windows DNS analytic and audit logs and other related data from your DNS servers."

- [Mapping File](AzureDNSAnalytics.yaml)
- [Navigator Layer](layers/AzureDNSAnalytics.json)

### Technique(s)
- [T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- [T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [T1566 - Phishing](https://attack.mitre.org/techniques/T1566/)
- [T1568 - Dynamic Resolution](https://attack.mitre.org/techniques/T1568/)
  


### Mapping Comments


For temporal score, generally high with respect to access to known bad domains: "The event-related data is collected near real time from the analytic and audit logs provided by enhanced DNS logging and diagnostics in Windows Server 2012 R2.". DNS logs and analytics can be used in a response context, for example to identify client access to previously unknown malicious domains.  "Noisy" client alerts may be useful for identifying some C2 over DNS.  


### Tag(s)
- [DNS](#dns)
- [Network](#network)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/azure-monitor/insights/dns-analytics
  


## Azure Dedicated HSM


"Azure Dedicated HSM is an Azure service that provides cryptographic key storage in Azure ... for customers who require FIPS 140-2 Level 3-validated devices and complete and exclusive control of the HSM appliance."

- [Mapping File](AzureDedicatedHSM.yaml)
- [Navigator Layer](layers/AzureDedicatedHSM.json)

### Technique(s)
- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
- [T1553 - Subvert Trust Controls](https://attack.mitre.org/techniques/T1553/)
- [T1588 - Obtain Capabilities](https://attack.mitre.org/techniques/T1588/)
  


### Mapping Comments


Note there is also a Managed HSM service.  


### Tag(s)
- [Credentials](#credentials)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/dedicated-hsm/overview
- https://docs.microsoft.com/en-us/azure/key-vault/managed-hsm/
  


## Azure Defender for App Service


Azure Defender for App Service monitors VM instances and their management interfaces, App Service apps and their requests/responses, and App Service internal logs to detect threats to App Service resources and provide security recommendations to mitigate them.

- [Mapping File](AzureDefenderForAppService.yaml)
- [Navigator Layer](layers/AzureDefenderForAppService.json)

### Technique(s)
- [T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [T1005 - Data from Local System](https://attack.mitre.org/techniques/T1005/)
- [T1012 - Query Registry](https://attack.mitre.org/techniques/T1012/)
- [T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [T1036 - Masquerading](https://attack.mitre.org/techniques/T1036/)
- [T1047 - Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)
- [T1053 - Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)
- [T1055 - Process Injection](https://attack.mitre.org/techniques/T1055/)
- [T1056 - Input Capture](https://attack.mitre.org/techniques/T1056/)
- [T1057 - Process Discovery](https://attack.mitre.org/techniques/T1057/)
- [T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)
- [T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [T1113 - Screen Capture](https://attack.mitre.org/techniques/T1113/)
- [T1123 - Audio Capture](https://attack.mitre.org/techniques/T1123/)
- [T1134 - Access Token Manipulation](https://attack.mitre.org/techniques/T1134/)
- [T1140 - Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)
- [T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1203 - Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)
- [T1204 - User Execution](https://attack.mitre.org/techniques/T1204/)
- [T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)
- [T1211 - Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211/)
- [T1212 - Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212/)
- [T1482 - Domain Trust Discovery](https://attack.mitre.org/techniques/T1482/)
- [T1496 - Resource Hijacking](https://attack.mitre.org/techniques/T1496/)
- [T1543 - Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)
- [T1547 - Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)
- [T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
- [T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)
- [T1558 - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/)
- [T1559 - Inter-Process Communication](https://attack.mitre.org/techniques/T1559/)
- [T1566 - Phishing](https://attack.mitre.org/techniques/T1566/)
- [T1574 - Hijack Execution Flow](https://attack.mitre.org/techniques/T1574/)
- [T1584 - Compromise Infrastructure](https://attack.mitre.org/techniques/T1584/)
- [T1594 - Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594/)
- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
  


### Mapping Comments


The AppServices_KnownCredentialAccessTools alert is used to detect suspicious processes associated with credential theft. This is clearly linked to the Credential Access tactic, but does not clearly detect any specific technique or set of techniques, so it has been omitted from this mapping.  


### Tag(s)
- [Azure Defender](#azure-defender)
- [Azure Defender for App Service](#azure-defender-for-app-service)
- [Azure Security Center](#azure-security-center)
- [Azure Security Center Recommendation](#azure-security-center-recommendation)
- [Linux](#linux)
- [Windows](#windows)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/security-center/alerts-reference
- https://docs.microsoft.com/en-us/azure/security-center/defender-for-app-service-introduction
- https://azure.microsoft.com/en-us/services/app-service/
- https://docs.microsoft.com/en-us/azure/security-center/defender-for-servers-introduction
  


## Azure Defender for Container Registries


Azure Defender for container registries includes a vulnerability scanner to scan the images in your Azure Resource Manager-based Azure Container Registry registries and provide deeper visibility into your images' vulnerabilities. The integrated scanner is powered by Qualys. Azure Container Registry is a managed, private Docker registry service based on the open-source Docker Registry 2.0.

- [Mapping File](AzureDefenderForContainerRegistries.yaml)
- [Navigator Layer](layers/AzureDefenderForContainerRegistries.json)

### Technique(s)
- [T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1525 - Implant Container Image](https://attack.mitre.org/techniques/T1525/)
  


### Mapping Comments


This mapping file covers Docker container registries security features along with the Azure Defender for Container Registries scanner. The scanning capability of the control is only available for Linux images in registries accessible from the public internet with shell access which limits the general applicability.  


### Tag(s)
- [Azure Defender](#azure-defender)
- [Azure Security Center Recommendation](#azure-security-center-recommendation)
- [Containers](#containers)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/security-center/defender-for-container-registries-introduction
- https://docs.microsoft.com/en-us/azure/container-registry/container-registry-intro
  


## Azure Defender for Key Vault


Azure Defender detects unusual and potentially harmful attempts to access or exploit Key Vault accounts. When anomalous activities occur, Azure Defender shows alerts and optionally sends them via email to relevant members of your organization. These alerts include the details of the suspicious activity and recommendations on how to investigate and remediate threats.

- [Mapping File](AzureDefenderForKeyVault.yaml)
- [Navigator Layer](layers/AzureDefenderForKeyVault.json)

### Technique(s)
- [T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)
- [T1580 - Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/)
  


### Mapping Comments


This control provides alerts for suspicious activity for Azure Key Vault. Documentation has been offered on how to respond to alerts but no specific tool or feature is offered for response.   


### Tag(s)
- [Azure Defender](#azure-defender)
- [Azure Security Center Recommendation](#azure-security-center-recommendation)
- [Credentials](#credentials)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/security-center/defender-for-key-vault-introduction
- https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-azurekv
  


## Azure Defender for Kubernetes


Azure Defender for Kubernetes provides cluster-level threat protection by monitoring your Azure Kubernetes Service (AKS) managed services through the logs retrieved by AKS. Examples of security events that Azure Defender for Kubernetes monitors include exposed Kubernetes dashboards, creation of high privileged roles, and the creation of sensitive mounts.

- [Mapping File](AzureDefenderForKubernetes.yaml)
- [Navigator Layer](layers/AzureDefenderForKubernetes.json)

### Technique(s)
- [T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [T1070 - Indicator Removal on Host](https://attack.mitre.org/techniques/T1070/)
- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1525 - Implant Container Image](https://attack.mitre.org/techniques/T1525/)
  


### Tag(s)
- [Azure Defender](#azure-defender)
- [Azure Security Center Recommendation](#azure-security-center-recommendation)
- [Containers](#containers)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/security-center/defender-for-kubernetes-introduction
- https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-akscluster
  


## Azure Defender for Resource Manager


Azure Defender for Resource Manager automatically monitors the  resource management operations in your organization, whether they're  performed through the Azure portal, Azure REST APIs, Azure CLI, or  other Azure programmatic clients. Alerts are generated by threats  detected in Azure Resource Manager logs and Azure Activity logs.  Azure Defender runs advanced security analytics to detect threats  and alert you about suspicious activity.


- [Mapping File](AlertsForResourceManager.yaml)
- [Navigator Layer](layers/AlertsForResourceManager.json)

### Technique(s)
- [T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [T1069 - Permission Groups Discovery](https://attack.mitre.org/techniques/T1069/)
- [T1082 - System Information Discovery](https://attack.mitre.org/techniques/T1082/)
- [T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)
- [T1526 - Cloud Service Discovery](https://attack.mitre.org/techniques/T1526/)
- [T1538 - Cloud Service Dashboard](https://attack.mitre.org/techniques/T1538/)
- [T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)
- [T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/)
- [T1580 - Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/)
  


### Tag(s)
- [Azure Defender](#azure-defender)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/security-center/defender-for-resource-manager-introduction
- https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-resourcemanager
  


## Azure Defender for Storage


Azure Defender for Storage can detect unusual and potentially harmful attempts to access or exploit storage accounts. Security alerts may trigger due to suspicious access patterns, suspicious activities, and upload of malicious content. Alerts include details of the incident that triggered them, as well as recommendations on how to investigate and remediate threats. Alerts can be exported to Azure Sentinel or any other third-party SIEM or any other external tool.

- [Mapping File](AzureDefenderForStorage.yaml)
- [Navigator Layer](layers/AzureDefenderForStorage.json)

### Technique(s)
- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1080 - Taint Shared Content](https://attack.mitre.org/techniques/T1080/)
- [T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [T1485 - Data Destruction](https://attack.mitre.org/techniques/T1485/)
- [T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)
- [T1537 - Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)
  


### Tag(s)
- [Azure Defender](#azure-defender)
- [Azure Security Center Recommendation](#azure-security-center-recommendation)
- [Azure Sentinel](#azure-sentinel)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/security-center/defender-for-storage-introduction
- https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-azurestorage
  


## Azure Firewall


Azure Firewall is a managed, cloud-based network security service that protects your Azure Virtual Network resources. 
It's a fully stateful firewall as a service (FWaaS) with built-in high availability and unrestricted cloud scalability.

- [Mapping File](AzureFirewall.yaml)
- [Navigator Layer](layers/AzureFirewall.json)

### Technique(s)
- [T1008 - Fallback Channels](https://attack.mitre.org/techniques/T1008/)
- [T1018 - Remote System Discovery](https://attack.mitre.org/techniques/T1018/)
- [T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- [T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
- [T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [T1095 - Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1095/)
- [T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)
- [T1205 - Traffic Signaling](https://attack.mitre.org/techniques/T1205/)
- [T1219 - Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [T1498 - Network Denial of Service](https://attack.mitre.org/techniques/T1498/)
- [T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)
- [T1563 - Remote Service Session Hijacking](https://attack.mitre.org/techniques/T1563/)
- [T1571 - Non-Standard Port](https://attack.mitre.org/techniques/T1571/)
- [T1590 - Gather Victim Network Information](https://attack.mitre.org/techniques/T1590/)
- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
  


### Tag(s)
- [Azure Security Center Recommendation](#azure-security-center-recommendation)
- [Network](#network)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/firewall/overview
  


## Azure Key Vault


Azure Key Vault provides a way to store and manage secrets, keys, and certificates used throughout Azure and for internally connected resources. This control allows for fine grained permissions for authentication and authorization for access while providing monitoring for all activity with the key vault.

- [Mapping File](AzureKeyVault.yaml)
- [Navigator Layer](layers/AzureKeyVault.json)

### Technique(s)
- [T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)
- [T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
- [T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)
  


### Tag(s)
- [Azure Security Center Recommendation](#azure-security-center-recommendation)
- [Credentials](#credentials)
- [Passwords](#passwords)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/key-vault/general/overview
  


## Azure Network Traffic Analytics


"Traffic Analytics is a cloud-based solution that provides visibility into user and application activity in cloud networks. Traffic analytics analyzes Network Watcher network security group (NSG) flow logs to provide insights into traffic flow in your Azure cloud."

- [Mapping File](AzureTrafficAnalytics.yaml)
- [Navigator Layer](layers/AzureTrafficAnalytics.json)

### Technique(s)
- [T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)
- [T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
- [T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [T1072 - Software Deployment Tools](https://attack.mitre.org/techniques/T1072/)
- [T1090 - Proxy](https://attack.mitre.org/techniques/T1090/)
- [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)
- [T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)
- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1199 - Trusted Relationship](https://attack.mitre.org/techniques/T1199/)
- [T1482 - Domain Trust Discovery](https://attack.mitre.org/techniques/T1482/)
- [T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)
- [T1542 - Pre-OS Boot](https://attack.mitre.org/techniques/T1542/)
- [T1563 - Remote Service Session Hijacking](https://attack.mitre.org/techniques/T1563/)
- [T1570 - Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/)
- [T1571 - Non-Standard Port](https://attack.mitre.org/techniques/T1571/)
- [T1602 - Data from Configuration Repository](https://attack.mitre.org/techniques/T1602/)
  


### Mapping Comments


Network Traffic Analytics can make queries with respect to Network Security Groups. Mappings made with some reasonable assumptions on NSGs such as a group for management systems.  


### Tag(s)
- [Analytics](#analytics)
- [Network](#network)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/network-watcher/traffic-analytics
  


## Azure Policy


Azure Policy evaluates resources in Azure by comparing the properties of those resources to business rules. These business rules, described in JSON format, are known as policy definitions. Azure Policy helps to enforce organizational standards and to assess compliance at-scale.

- [Mapping File](AzurePolicy.yaml)
- [Navigator Layer](layers/AzurePolicy.json)

### Technique(s)
- [T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)
- [T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)
- [T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
- [T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)
- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)
- [T1485 - Data Destruction](https://attack.mitre.org/techniques/T1485/)
- [T1505 - Server Software Component](https://attack.mitre.org/techniques/T1505/)
- [T1525 - Implant Container Image](https://attack.mitre.org/techniques/T1525/)
- [T1526 - Cloud Service Discovery](https://attack.mitre.org/techniques/T1526/)
- [T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)
- [T1535 - Unused/Unsupported Cloud Regions](https://attack.mitre.org/techniques/T1535/)
- [T1537 - Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)
- [T1538 - Cloud Service Dashboard](https://attack.mitre.org/techniques/T1538/)
- [T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)
- [T1580 - Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/)
- [T1590 - Gather Victim Network Information](https://attack.mitre.org/techniques/T1590/)
  


### Mapping Comments


This mapping is focused on the list of built-in policy definitions provided by Azure Policy.  


### Tag(s)
- [Azure Security Center Recommendation](#azure-security-center-recommendation)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/governance/policy/overview
- https://docs.microsoft.com/en-us/azure/governance/policy/samples/built-in-policies#api-for-fhir
  


## Azure Private Link


Azure Private Link enables you to access Azure PaaS Services (for example, Azure Storage and SQL Database) and Azure hosted customer-owned/partner services over a private endpoint in your virtual network.
Traffic between your virtual network and the service travels the Microsoft backbone network. Exposing your service to the public internet is no longer necessary. You can create your own private link service in your virtual network and deliver it to your customers. Setup and consumption using Azure Private Link is consistent across Azure PaaS, customer-owned, and shared partner services.

- [Mapping File](AzurePrivateLink.yaml)
- [Navigator Layer](layers/AzurePrivateLink.json)

### Technique(s)
- [T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)
- [T1498 - Network Denial of Service](https://attack.mitre.org/techniques/T1498/)
- [T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)
- [T1557 - Man-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
- [T1565 - Data Manipulation](https://attack.mitre.org/techniques/T1565/)
  


### Mapping Comments


This is a private network service, allowing connections between Azure, on-prem, and 3rd party services without traversing the Internet. Generally this reduces risk from MiTM, DOS, network-based data manipulation and network sniffing from untrusted network.  


### Tag(s)
- [Azure Security Center Recommendation](#azure-security-center-recommendation)
- [Network](#network)
  


### Reference(s)
- https://docs.microsoft.com/azure/private-link/private-link-overview
  


## Azure Security Center Recommendations


This feature of Azure Security Center assesses your workloads and raises threat prevention recommendations and security alerts.

- [Mapping File](SecurityCenterRecommendations.yaml)
- [Navigator Layer](layers/SecurityCenterRecommendations.json)

### Technique(s)
- [T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)
- [T1053 - Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)
- [T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [T1074 - Data Staged](https://attack.mitre.org/techniques/T1074/)
- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1080 - Taint Shared Content](https://attack.mitre.org/techniques/T1080/)
- [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
- [T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)
- [T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)
- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1222 - File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222/)
- [T1485 - Data Destruction](https://attack.mitre.org/techniques/T1485/)
- [T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)
- [T1505 - Server Software Component](https://attack.mitre.org/techniques/T1505/)
- [T1525 - Implant Container Image](https://attack.mitre.org/techniques/T1525/)
- [T1542 - Pre-OS Boot](https://attack.mitre.org/techniques/T1542/)
- [T1543 - Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)
- [T1546 - Event Triggered Execution](https://attack.mitre.org/techniques/T1546/)
- [T1554 - Compromise Client Software Binary](https://attack.mitre.org/techniques/T1554/)
- [T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)
- [T1564 - Hide Artifacts](https://attack.mitre.org/techniques/T1564/)
- [T1565 - Data Manipulation](https://attack.mitre.org/techniques/T1565/)
  


### Mapping Comments


Security Center recommendations include recommendations to enable security controls that have already been mapped separately (e.g. "Azure Defender for App Service should be enabled").    Rather than including the (sub-)techniques that these controls map to within this mapping, consult the mapping files for these controls.  To make this latter task easier, we have tagged all such controls with the "Azure Security Center Recommendation" tag.
All scores are capped at Partial since this control provides recommendations rather than applying/enforcing the recommended actions.
IoT related recommendations were not included in this mapping.  


### Tag(s)
- [Azure Security Center](#azure-security-center)
- [Azure Security Center Recommendation](#azure-security-center-recommendation)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/security-center/recommendations-reference
- https://docs.microsoft.com/en-us/azure/security-center/security-center-introduction
  


## Azure Sentinel Analytics 1-50


Out of the box Azure Sentinel Analytics (from the rule template list)

- [Mapping File](AzureSentinelAnalytics-1-50.yaml)
- [Navigator Layer](layers/AzureSentinelAnalytics-1-50.json)

### Technique(s)
- [T1070 - Indicator Removal on Host](https://attack.mitre.org/techniques/T1070/)
- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
- [T1134 - Access Token Manipulation](https://attack.mitre.org/techniques/T1134/)
- [T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [T1484 - Domain Policy Modification](https://attack.mitre.org/techniques/T1484/)
- [T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/)
- [T1566 - Phishing](https://attack.mitre.org/techniques/T1566/)
  


### Mapping Comments


Note: only mapped out of the box analytics. Did not score analytics that were specific ioc-based (e.g.  ip addresses or hashes ).  Did not score analytics that required a 3rd party integration (e.g. Alsid or TrendMicro). Refer to specific analytics by name in quotes.  


### Reference(s)
  


## Azure Sentinel Analytics 101-150


Out of the box Azure Sentinel Analytics (from the rule template list)

- [Mapping File](AzureSentinelAnalytics-101-150.yaml)
- [Navigator Layer](layers/AzureSentinelAnalytics-101-150.json)

### Technique(s)
- [T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [T1016 - System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/)
- [T1018 - Remote System Discovery](https://attack.mitre.org/techniques/T1018/)
- [T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)
- [T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)
- [T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- [T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
- [T1047 - Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)
- [T1049 - System Network Connections Discovery](https://attack.mitre.org/techniques/T1049/)
- [T1053 - Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)
- [T1055 - Process Injection](https://attack.mitre.org/techniques/T1055/)
- [T1056 - Input Capture](https://attack.mitre.org/techniques/T1056/)
- [T1057 - Process Discovery](https://attack.mitre.org/techniques/T1057/)
- [T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [T1070 - Indicator Removal on Host](https://attack.mitre.org/techniques/T1070/)
- [T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1082 - System Information Discovery](https://attack.mitre.org/techniques/T1082/)
- [T1083 - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)
- [T1102 - Web Service](https://attack.mitre.org/techniques/T1102/)
- [T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [T1106 - Native API](https://attack.mitre.org/techniques/T1106/)
- [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
- [T1113 - Screen Capture](https://attack.mitre.org/techniques/T1113/)
- [T1114 - Email Collection](https://attack.mitre.org/techniques/T1114/)
- [T1115 - Clipboard Data](https://attack.mitre.org/techniques/T1115/)
- [T1125 - Video Capture](https://attack.mitre.org/techniques/T1125/)
- [T1127 - Trusted Developer Utilities Proxy Execution](https://attack.mitre.org/techniques/T1127/)
- [T1134 - Access Token Manipulation](https://attack.mitre.org/techniques/T1134/)
- [T1135 - Network Share Discovery](https://attack.mitre.org/techniques/T1135/)
- [T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)
- [T1137 - Office Application Startup](https://attack.mitre.org/techniques/T1137/)
- [T1140 - Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)
- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)
- [T1217 - Browser Bookmark Discovery](https://attack.mitre.org/techniques/T1217/)
- [T1482 - Domain Trust Discovery](https://attack.mitre.org/techniques/T1482/)
- [T1484 - Domain Policy Modification](https://attack.mitre.org/techniques/T1484/)
- [T1518 - Software Discovery](https://attack.mitre.org/techniques/T1518/)
- [T1543 - Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)
- [T1546 - Event Triggered Execution](https://attack.mitre.org/techniques/T1546/)
- [T1547 - Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)
- [T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)
- [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)
- [T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
- [T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)
- [T1557 - Man-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
- [T1558 - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/)
- [T1560 - Archive Collected Data](https://attack.mitre.org/techniques/T1560/)
- [T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/)
- [T1567 - Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)
- [T1568 - Dynamic Resolution](https://attack.mitre.org/techniques/T1568/)
- [T1569 - System Services](https://attack.mitre.org/techniques/T1569/)
- [T1573 - Encrypted Channel](https://attack.mitre.org/techniques/T1573/)
- [T1574 - Hijack Execution Flow](https://attack.mitre.org/techniques/T1574/)
- [T1590 - Gather Victim Network Information](https://attack.mitre.org/techniques/T1590/)
- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
  


### Mapping Comments


Note: only mapped out of the box analytics. Did not score analytics that were specific ioc-based (e.g.  ip addresses or hashes ).  Did not score analytics that required a 3rd party integration
  (e.g. Alsid or TrendMicro). Refer to specific analytics by name in quotes.  


### Reference(s)
  


## Azure Sentinel Analytics 151-200


Out of the box Analytics for Azure Sentinel 

- [Mapping File](AzureSentinelAnalytics-151-200.yaml)
- [Navigator Layer](layers/AzureSentinelAnalytics-151-200.json)

### Technique(s)
- [T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [T1070 - Indicator Removal on Host](https://attack.mitre.org/techniques/T1070/)
- [T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
- [T1195 - Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)
- [T1496 - Resource Hijacking](https://attack.mitre.org/techniques/T1496/)
- [T1567 - Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)
- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
  


### Mapping Comments


Analytics rule templates. note did not score ioc-based or 3rd-party analytics.  


### Reference(s)
  


## Azure VPN Gateway


A VPN gateway is a specific type of virtual network gateway that is used to send encrypted traffic between an Azure virtual network and an on-premises location over the public Internet. 
You can also use a VPN gateway to send encrypted traffic between Azure virtual networks over the Microsoft network.

- [Mapping File](AzureVPN.yaml)
- [Navigator Layer](layers/AzureVPN.json)

### Technique(s)
- [T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)
- [T1557 - Man-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
- [T1565 - Data Manipulation](https://attack.mitre.org/techniques/T1565/)
  


### Tag(s)
- [Azure VPN Gateway](#azure-vpn-gateway)
- [Encryption](#encryption)
- [Network](#network)
- [VPN](#vpn)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-about-vpngateways
  


## Azure Web Application Firewall


Azure Web Application Firewall (WAF) provides centralized protection of your web applications  from common exploits and vulnerabilities.


- [Mapping File](AzureWebApplicationFirewall.yaml)
- [Navigator Layer](layers/AzureWebApplicationFirewall.json)

### Technique(s)
- [T1001 - Data Obfuscation](https://attack.mitre.org/techniques/T1001/)
- [T1008 - Fallback Channels](https://attack.mitre.org/techniques/T1008/)
- [T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- [T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
- [T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [T1056 - Input Capture](https://attack.mitre.org/techniques/T1056/)
- [T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
- [T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1203 - Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)
- [T1205 - Traffic Signaling](https://attack.mitre.org/techniques/T1205/)
- [T1491 - Defacement](https://attack.mitre.org/techniques/T1491/)
- [T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)
- [T1526 - Cloud Service Discovery](https://attack.mitre.org/techniques/T1526/)
- [T1567 - Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)
- [T1572 - Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
  


### Tag(s)
- [Azure Security Center Recommendation](#azure-security-center-recommendation)
- [WAF](#waf)
- [Web](#web)
- [Web Access Firewall](#web-access-firewall)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/web-application-firewall/overview
  


## Cloud App Security Policies


Microsoft Cloud App Security is a Cloud Access Security Broker (CASB) that supports various deployment modes including log collection, API connectors, and reverse proxy. It provides rich visibility, control over data travel, and sophisticated analytics to identify and combat cyberthreats across all your Microsoft and third-party cloud services.

- [Mapping File](CloudAppSecurity.yaml)
- [Navigator Layer](layers/CloudAppSecurity.json)

### Technique(s)
- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [T1119 - Automated Collection](https://attack.mitre.org/techniques/T1119/)
- [T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)
- [T1187 - Forced Authentication](https://attack.mitre.org/techniques/T1187/)
- [T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [T1213 - Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)
- [T1219 - Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [T1484 - Domain Policy Modification](https://attack.mitre.org/techniques/T1484/)
- [T1526 - Cloud Service Discovery](https://attack.mitre.org/techniques/T1526/)
- [T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)
- [T1531 - Account Access Removal](https://attack.mitre.org/techniques/T1531/)
- [T1535 - Unused/Unsupported Cloud Regions](https://attack.mitre.org/techniques/T1535/)
- [T1565 - Data Manipulation](https://attack.mitre.org/techniques/T1565/)
- [T1567 - Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)
- [T1578 - Modify Cloud Compute Infrastructure](https://attack.mitre.org/techniques/T1578/)
  


### Tag(s)
- [CASB](#casb)
  


### Reference(s)
- https://docs.microsoft.com/en-us/cloud-app-security/policies-cloud-discovery
- https://docs.microsoft.com/en-us/cloud-app-security/policies-information-protection
  


## Conditional Access


The modern security perimeter now extends beyond an organization's network to include user and device identity. Organizations can utilize these identity signals as part of their access control decisions.  Conditional Access is the tool used by Azure Active Directory to bring signals together, to make decisions, and enforce organizational policies. Conditional Access is at the heart of the new identity driven control plane.

- [Mapping File](ConditionalAccess.yaml)
- [Navigator Layer](layers/ConditionalAccess.json)

### Technique(s)
- [T1074 - Data Staged](https://attack.mitre.org/techniques/T1074/)
- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
- [T1213 - Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)
- [T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)
  


### Mapping Comments


At first glance, this control seems mappable to Exfiltration (sub-)techniques but upon further analysis, it doesn't really mitigate exfiltration but rather its prerequisite Collection (sub-)techniques.  


### Tag(s)
- [Azure Active Directory](#azure-active-directory)
- [Identity](#identity)
- [MFA](#mfa)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/overview
  


## Continuous Access Evaluation


Continuous Access Evaluation (CAE) provides the next level of identity security by terminating active user sessions to a subset of Microsoft services (Exchange and Teams) in real-time on changes such as account disable, password reset, and admin initiated user revocation.  CAE aims to improve the response time in situations where a policy setting that applies to a user changes but the user is able to circumvent the new policy setting because their OAuth access token was issued before the policy change.  It’s typical that security access tokens issued by Azure AD, like OAuth 2.0 access tokens, are valid for an hour.
CAE enables the scenario where users lose access to organizational SharePoint Online files, email, calendar, or tasks, and Teams from Microsoft 365 client apps within mins after critical security events (such as user account is deleted, MFA is enabled for a user, High user risk detected by Azure AD Identity Protection, etc.).

- [Mapping File](ContinuousAccessEvaluation.yaml)
- [Navigator Layer](layers/ContinuousAccessEvaluation.json)

### Technique(s)
- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
  


### Tag(s)
- [Azure Active Directory](#azure-active-directory)
- [Identity](#identity)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/concept-continuous-access-evaluation
  


## Docker Host Hardening


Azure Security Center identifies unmanaged containers hosted on IaaS Linux VMs, or other Linux machines running Docker containers. Security Center continuously assesses the configurations of these containers. It then compares them with the Center for Internet Security (CIS) Docker Benchmark. Security Center includes the entire ruleset of the CIS Docker Benchmark and alerts you if your containers don't satisfy any of the controls. When it finds misconfigurations, Security Center generates security recommendations.

- [Mapping File](DockerHostHardening.yaml)
- [Navigator Layer](layers/DockerHostHardening.json)

### Technique(s)
- [T1005 - Data from Local System](https://attack.mitre.org/techniques/T1005/)
- [T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)
- [T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)
- [T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [T1083 - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [T1525 - Implant Container Image](https://attack.mitre.org/techniques/T1525/)
- [T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)
  


### Tag(s)
- [Azure Security Center](#azure-security-center)
- [Containers](#containers)
- [Linux](#linux)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/security-center/harden-docker-hosts
  


## File Integrity Monitoring


File integrity monitoring (FIM), also known as change monitoring, examines  operating system files, Windows registries, application software, Linux  system files, and more, for changes that might indicate an attack. File Integrity Monitoring (FIM) informs you when changes occur to sensitive  areas in your resources, so you can investigate and address unauthorized  activity. 


- [Mapping File](FileIntegrityMonitoring.yaml)
- [Navigator Layer](layers/FileIntegrityMonitoring.json)

### Technique(s)
- [T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [T1037 - Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1037/)
- [T1053 - Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)
- [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [T1137 - Office Application Startup](https://attack.mitre.org/techniques/T1137/)
- [T1222 - File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222/)
- [T1543 - Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)
- [T1546 - Event Triggered Execution](https://attack.mitre.org/techniques/T1546/)
- [T1547 - Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)
- [T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)
- [T1553 - Subvert Trust Controls](https://attack.mitre.org/techniques/T1553/)
- [T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)
- [T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/)
- [T1574 - Hijack Execution Flow](https://attack.mitre.org/techniques/T1574/)
  


### Mapping Comments


The techniques included in this mapping result in Windows Registry or file system artifacts being created or modified which can be detected by this control.  
The detection score for most techniques included in this mapping was scored as Significant and where there are exceptions, comments have been provided. This Significant score assessment  was due to the following factors: Coverage - (High) The control was able to detect most of the sub-techniques, references and procedure examples of the mapped techniques. Accuracy - (High) Although this control does not include built-in intelligence to minimize  the false positive rate, the specific artifacts generated by the techniques in this mapping do not change frequently and therefore the potential for a high false-positive is reduced.  Temporal - (Medium) This control at worst scans for changes on an hourly basis.
  


### Tag(s)
- [Azure Defender](#azure-defender)
- [Azure Defender for Servers](#azure-defender-for-servers)
- [Azure Security Center](#azure-security-center)
- [Azure Security Center Recommendation](#azure-security-center-recommendation)
- [File system](#file-system)
- [Linux](#linux)
- [Registry](#registry)
- [Windows](#windows)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/security-center/security-center-file-integrity-monitoring
  


## Integrated Vulnerability Scanner Powered by Qualys


This control provides a on-demand and scheduled vulnerability scan for Windows and Linux endpoints that are being protected by Azure Defender. The scanner generates a list of possible vulnerabilities in Azure Security Center for possible remediation. 

- [Mapping File](VulnerabilityAssessmentQualys.yaml)
- [Navigator Layer](layers/VulnerabilityAssessmentQualys.json)

### Technique(s)
- [T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1203 - Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)
- [T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)
- [T1211 - Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211/)
- [T1212 - Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212/)
  


### Mapping Comments


Once this control is deployed, it will run a scan every four hours and scans can be run on demand. Documentation notes that within 48 hours of the disclosure of a critical vulnerability, Qualys incorporates the information into their processing and can identify affected machines.  


### Tag(s)
- [Azure Defender](#azure-defender)
- [Azure Security Center](#azure-security-center)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/security-center/deploy-vulnerability-assessment-vm
- https://docs.microsoft.com/en-us/azure/security-center/remediate-vulnerability-findings-vm
  


## Just-in-Time(JIT) VM Access


This control locks down inbound traffic to management ports for protocols such as RDP and SSH and only provides access upon request for a specified period of time. This reduces exposure to attacks while providing easy access when you need to connect to a virtual machine. Specific permissions are required to request access to virtual machines that have this control enabled and access can be requested through the Azure web UI, PowerShell, and a REST API.

- [Mapping File](JustInTimeVMAccess.yaml)
- [Navigator Layer](layers/JustInTimeVMAccess.json)

### Technique(s)
- [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
- [T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)
- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
  


### Tag(s)
- [Azure Defender for Servers](#azure-defender-for-servers)
- [Azure Security Center](#azure-security-center)
- [Azure Security Center Recommendation](#azure-security-center-recommendation)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/security-center/security-center-just-in-time?tabs=jit-config-asc%2Cjit-request-api
- https://docs.microsoft.com/en-us/azure/security-center/just-in-time-explained
  


## Linux auditd alerts and Log Analytics agent integration


This integration enables collection of auditd events in all supported Linux distributions, without any prerequisites. Auditd records are collected, enriched, and aggregated into events by using the Log Analytics agent for Linux agent.

- [Mapping File](LinuxAuditdAndLogAnalytics.yaml)
- [Navigator Layer](layers/LinuxAuditdAndLogAnalytics.json)

### Technique(s)
- [T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)
- [T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [T1070 - Indicator Removal on Host](https://attack.mitre.org/techniques/T1070/)
- [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
- [T1113 - Screen Capture](https://attack.mitre.org/techniques/T1113/)
- [T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)
- [T1505 - Server Software Component](https://attack.mitre.org/techniques/T1505/)
- [T1525 - Implant Container Image](https://attack.mitre.org/techniques/T1525/)
- [T1547 - Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)
- [T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/)
- [T1564 - Hide Artifacts](https://attack.mitre.org/techniques/T1564/)
  


### Tag(s)
- [Azure Defender](#azure-defender)
- [Linux](#linux)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/security-center/defender-for-servers-introduction
- https://docs.microsoft.com/en-us/azure/security-center/alerts-reference#alerts-linux
  


## Managed identities for Azure resources


Managed identities for Azure resources provide Azure services with an automatically managed identity in Azure Active Directory. You can use this identity to authenticate to any service that supports Azure AD authentication, without having to hard-code credentials in your code.

- [Mapping File](AzureADManagedIdentities.yaml)
- [Navigator Layer](layers/AzureADManagedIdentities.json)

### Technique(s)
- [T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
  


### Tag(s)
- [Azure Active Directory](#azure-active-directory)
- [Azure Security Center Recommendation](#azure-security-center-recommendation)
- [Identity](#identity)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview
  


## Microsoft Antimalware for Azure


Microsoft Antimalware for Azure is a free real-time protection that helps identify and remove viruses, spyware, and other malicious software. It generates alerts when known malicious or unwanted software tries to install itself or run on your Azure systems. 

- [Mapping File](MicrosoftAntimalwareForAzure.yaml)
- [Navigator Layer](layers/MicrosoftAntimalwareForAzure.json)

### Technique(s)
- [T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [T1204 - User Execution](https://attack.mitre.org/techniques/T1204/)
- [T1566 - Phishing](https://attack.mitre.org/techniques/T1566/)
  


### Mapping Comments


Signature based antimalware solutions are generally dependent on Indicators of Compromise(IOCs) such as file hashes and malware signatures. ATT&CK is primarily centered on behaviors and Tactics, Techniques, and Procedures(TTPs), hence the minimal amount of techinques and scoring.  


### Tag(s)
- [Azure Security Center](#azure-security-center)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/security/fundamentals/antimalware
- https://docs.microsoft.com/en-us/azure/security/fundamentals/antimalware-code-samples
  


## Microsoft Defender for Identity


Microsoft Defender for Identity (formerly Azure Advanced Threat Protection, also known as Azure ATP) is a cloud-based security solution that leverages your on-premises Active Directory signals to identify, detect, and investigate advanced threats, compromised identities, and malicious insider actions directed at your organization.

- [Mapping File](MicrosoftDefenderForIdentity.yaml)
- [Navigator Layer](layers/MicrosoftDefenderForIdentity.json)

### Technique(s)
- [T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)
- [T1047 - Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)
- [T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [T1069 - Permission Groups Discovery](https://attack.mitre.org/techniques/T1069/)
- [T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)
- [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
- [T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)
- [T1201 - Password Policy Discovery](https://attack.mitre.org/techniques/T1201/)
- [T1207 - Rogue Domain Controller](https://attack.mitre.org/techniques/T1207/)
- [T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)
- [T1482 - Domain Trust Discovery](https://attack.mitre.org/techniques/T1482/)
- [T1543 - Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)
- [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)
- [T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)
- [T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)
- [T1557 - Man-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
- [T1558 - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/)
- [T1569 - System Services](https://attack.mitre.org/techniques/T1569/)
  


### Mapping Comments


Understandably (to avoid enabling adversaries to circumvent the detection), many of the detections provided by this control do not provide a detailed description of the detection logic making it often times difficult to map to ATT&CK Techniques.  


### Tag(s)
- [Credentials](#credentials)
- [DNS](#dns)
- [Identity](#identity)
- [Microsoft 365 Defender](#microsoft-365-defender)
- [Windows](#windows)
  


### Reference(s)
- https://docs.microsoft.com/en-us/defender-for-identity/what-is
  


## Network Security Groups


You can use an Azure network security group to filter network traffic to and from Azure resources in an Azure virtual network. A network security group contains security rules that allow or deny inbound network traffic to, or outbound network traffic from, several types of Azure resources. For each rule, you can specify source and destination, port, and protocol.

- [Mapping File](NetworkSecurityGroups.yaml)
- [Navigator Layer](layers/NetworkSecurityGroups.json)

### Technique(s)
- [T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)
- [T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
- [T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [T1072 - Software Deployment Tools](https://attack.mitre.org/techniques/T1072/)
- [T1090 - Proxy](https://attack.mitre.org/techniques/T1090/)
- [T1095 - Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1095/)
- [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)
- [T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)
- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1199 - Trusted Relationship](https://attack.mitre.org/techniques/T1199/)
- [T1205 - Traffic Signaling](https://attack.mitre.org/techniques/T1205/)
- [T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)
- [T1219 - Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [T1482 - Domain Trust Discovery](https://attack.mitre.org/techniques/T1482/)
- [T1498 - Network Denial of Service](https://attack.mitre.org/techniques/T1498/)
- [T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)
- [T1542 - Pre-OS Boot](https://attack.mitre.org/techniques/T1542/)
- [T1557 - Man-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
- [T1563 - Remote Service Session Hijacking](https://attack.mitre.org/techniques/T1563/)
- [T1565 - Data Manipulation](https://attack.mitre.org/techniques/T1565/)
- [T1570 - Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/)
- [T1571 - Non-Standard Port](https://attack.mitre.org/techniques/T1571/)
- [T1602 - Data from Configuration Repository](https://attack.mitre.org/techniques/T1602/)
  


### Mapping Comments


Note: one can employ Application Security Groups (ASG) in Network Security Group (NSG) rules to map  rules to workloads etc. Not scoring ASG as a separate control. One can employ Adaptive Network Hardening (ANH)  to generate recommended NSG rules based on traffic, known trusted configuration, threat intelligence, and other inidcators of compromise. Not scoring ANH as a separate control.  


### Tag(s)
- [Adaptive Network Hardening](#adaptive-network-hardening)
- [Azure Security Center Recommendation](#azure-security-center-recommendation)
- [Network](#network)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview
- https://docs.microsoft.com/en-us/azure/virtual-network/network-security-group-how-it-works
- https://docs.microsoft.com/en-us/azure/security-center/security-center-adaptive-network-hardening
  


## Passwordless Authentication


Features like multi-factor authentication (MFA) are a great way to secure your organization, but users often get frustrated with the additional security layer on top of having to remember their passwords. Passwordless authentication methods are more convenient because the password is removed and replaced with something you have, plus something you are or something you know.

- [Mapping File](PasswordlessAuthentication.yaml)
- [Navigator Layer](layers/PasswordlessAuthentication.json)

### Technique(s)
- [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
  


### Tag(s)
- [Azure Active Directory](#azure-active-directory)
- [Credentials](#credentials)
- [Identity](#identity)
- [Passwords](#passwords)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-passwordless
  


## Role Based Access Control


Access management for cloud resources is a critical function for any organization that is using the cloud. Azure role-based access control (Azure RBAC) helps you manage who has access to Azure resources, what they can do with those resources, and what areas they have access to.


- [Mapping File](AzureADRoleBasedAccessControl.yaml)
- [Navigator Layer](layers/AzureADRoleBasedAccessControl.json)

### Technique(s)
- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)
- [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)
- [T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)
- [T1538 - Cloud Service Dashboard](https://attack.mitre.org/techniques/T1538/)
- [T1578 - Modify Cloud Compute Infrastructure](https://attack.mitre.org/techniques/T1578/)
- [T1580 - Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/)
  


### Mapping Comments


RBAC enables organizations to limit the number of users within the organization with an IAM role that has administrative privileges.  This enables limiting the number of users within the tenant that have privileged access thereby resulting in a reduced attack surface and a coverage score factor of Partial.  Most sub-techniques have been scored as Partial for this reason.  


### Tag(s)
- [Azure Active Directory](#azure-active-directory)
- [Azure Security Center Recommendation](#azure-security-center-recommendation)
- [Identity](#identity)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/role-based-access-control/overview
  


## SQL Vulnerability Assessment


SQL vulnerability assessment is a service that provides visibility into your security state. The service employs a knowledge base of rules that flag security vulnerabilities. It highlights deviations from best practices, such as misconfigurations, excessive permissions, and unprotected sensitive data.

- [Mapping File](SQLVulnerabilityAssessment.yaml)
- [Navigator Layer](layers/SQLVulnerabilityAssessment.json)

### Technique(s)
- [T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1112 - Modify Registry](https://attack.mitre.org/techniques/T1112/)
- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1505 - Server Software Component](https://attack.mitre.org/techniques/T1505/)
  


### Tag(s)
- [Azure Defender for SQL](#azure-defender-for-sql)
- [Database](#database)
  


### Reference(s)
- https://docs.microsoft.com/en-us/azure/azure-sql/database/sql-vulnerability-assessment
- https://docs.microsoft.com/en-us/azure/azure-sql/database/sql-database-vulnerability-assessment-rules
  


# Tags

## Adaptive Network Hardening

### Controls
- [Network Security Groups](#network-security-groups)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Adaptive_Network_Hardening.json)

## Analytics

### Controls
- [Azure Alerts for Network Layer](#azure-alerts-for-network-layer)
- [Azure Network Traffic Analytics](#azure-network-traffic-analytics)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Analytics.json)

## Azure Active Directory

### Controls
- [Azure AD Identity Protection](#azure-ad-identity-protection)
- [Azure AD Identity Secure Score](#azure-ad-identity-secure-score)
- [Azure AD Multi-Factor Authentication](#azure-ad-multi-factor-authentication)
- [Azure AD Password Policy](#azure-ad-password-policy)
- [Azure AD Privileged Identity Management](#azure-ad-privileged-identity-management)
- [Azure Active Directory Password Protection](#azure-active-directory-password-protection)
- [Conditional Access](#conditional-access)
- [Continuous Access Evaluation](#continuous-access-evaluation)
- [Managed identities for Azure resources](#managed-identities-for-azure-resources)
- [Passwordless Authentication](#passwordless-authentication)
- [Role Based Access Control](#role-based-access-control)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Azure_Active_Directory.json)

## Azure Defender

### Controls
- [Advanced Threat Protection for Azure SQL Database](#advanced-threat-protection-for-azure-sql-database)
- [Alerts for Windows Machines](#alerts-for-windows-machines)
- [Azure Defender for App Service](#azure-defender-for-app-service)
- [Azure Defender for Container Registries](#azure-defender-for-container-registries)
- [Azure Defender for Key Vault](#azure-defender-for-key-vault)
- [Azure Defender for Kubernetes](#azure-defender-for-kubernetes)
- [Azure Defender for Resource Manager](#azure-defender-for-resource-manager)
- [Azure Defender for Storage](#azure-defender-for-storage)
- [File Integrity Monitoring](#file-integrity-monitoring)
- [Integrated Vulnerability Scanner Powered by Qualys](#integrated-vulnerability-scanner-powered-by-qualys)
- [Linux auditd alerts and Log Analytics agent integration](#linux-auditd-alerts-and-log-analytics-agent-integration)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Azure_Defender.json)

## Azure Defender for App Service

### Controls
- [Azure Defender for App Service](#azure-defender-for-app-service)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Azure_Defender_for_App_Service.json)

## Azure Defender for SQL

### Controls
- [Advanced Threat Protection for Azure SQL Database](#advanced-threat-protection-for-azure-sql-database)
- [SQL Vulnerability Assessment](#sql-vulnerability-assessment)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Azure_Defender_for_SQL.json)

## Azure Defender for Servers

### Controls
- [Adaptive Application Controls](#adaptive-application-controls)
- [Alerts for Windows Machines](#alerts-for-windows-machines)
- [File Integrity Monitoring](#file-integrity-monitoring)
- [Just-in-Time(JIT) VM Access](#just-in-time(jit)-vm-access)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Azure_Defender_for_Servers.json)

## Azure Security Center

### Controls
- [Adaptive Application Controls](#adaptive-application-controls)
- [Advanced Threat Protection for Azure SQL Database](#advanced-threat-protection-for-azure-sql-database)
- [Alerts for Azure Cosmos DB](#alerts-for-azure-cosmos-db)
- [Azure Alerts for Network Layer](#azure-alerts-for-network-layer)
- [Azure Defender for App Service](#azure-defender-for-app-service)
- [Azure Security Center Recommendations](#azure-security-center-recommendations)
- [Docker Host Hardening](#docker-host-hardening)
- [File Integrity Monitoring](#file-integrity-monitoring)
- [Integrated Vulnerability Scanner Powered by Qualys](#integrated-vulnerability-scanner-powered-by-qualys)
- [Just-in-Time(JIT) VM Access](#just-in-time(jit)-vm-access)
- [Microsoft Antimalware for Azure](#microsoft-antimalware-for-azure)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Azure_Security_Center.json)

## Azure Security Center Recommendation

### Controls
- [Adaptive Application Controls](#adaptive-application-controls)
- [Advanced Threat Protection for Azure SQL Database](#advanced-threat-protection-for-azure-sql-database)
- [Azure AD Multi-Factor Authentication](#azure-ad-multi-factor-authentication)
- [Azure Backup](#azure-backup)
- [Azure DDOS Protection Standard](#azure-ddos-protection-standard)
- [Azure Defender for App Service](#azure-defender-for-app-service)
- [Azure Defender for Container Registries](#azure-defender-for-container-registries)
- [Azure Defender for Key Vault](#azure-defender-for-key-vault)
- [Azure Defender for Kubernetes](#azure-defender-for-kubernetes)
- [Azure Defender for Storage](#azure-defender-for-storage)
- [Azure Firewall](#azure-firewall)
- [Azure Key Vault](#azure-key-vault)
- [Azure Policy](#azure-policy)
- [Azure Private Link](#azure-private-link)
- [Azure Security Center Recommendations](#azure-security-center-recommendations)
- [Azure Web Application Firewall](#azure-web-application-firewall)
- [File Integrity Monitoring](#file-integrity-monitoring)
- [Just-in-Time(JIT) VM Access](#just-in-time(jit)-vm-access)
- [Managed identities for Azure resources](#managed-identities-for-azure-resources)
- [Network Security Groups](#network-security-groups)
- [Role Based Access Control](#role-based-access-control)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Azure_Security_Center_Recommendation.json)

## Azure Sentinel

### Controls
- [Azure Defender for Storage](#azure-defender-for-storage)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Azure_Sentinel.json)

## Azure VPN Gateway

### Controls
- [Azure VPN Gateway](#azure-vpn-gateway)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Azure_VPN_Gateway.json)

## CASB

### Controls
- [Cloud App Security Policies](#cloud-app-security-policies)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/CASB.json)

## Containers

### Controls
- [Azure Defender for Container Registries](#azure-defender-for-container-registries)
- [Azure Defender for Kubernetes](#azure-defender-for-kubernetes)
- [Docker Host Hardening](#docker-host-hardening)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Containers.json)

## Credentials

### Controls
- [Azure AD Identity Protection](#azure-ad-identity-protection)
- [Azure AD Identity Secure Score](#azure-ad-identity-secure-score)
- [Azure AD Multi-Factor Authentication](#azure-ad-multi-factor-authentication)
- [Azure AD Password Policy](#azure-ad-password-policy)
- [Azure Active Directory Password Protection](#azure-active-directory-password-protection)
- [Azure Dedicated HSM](#azure-dedicated-hsm)
- [Azure Defender for Key Vault](#azure-defender-for-key-vault)
- [Azure Key Vault](#azure-key-vault)
- [Microsoft Defender for Identity](#microsoft-defender-for-identity)
- [Passwordless Authentication](#passwordless-authentication)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Credentials.json)

## DNS

### Controls
- [Alerts for DNS](#alerts-for-dns)
- [Azure DNS Alias Records](#azure-dns-alias-records)
- [Azure DNS Analytics](#azure-dns-analytics)
- [Microsoft Defender for Identity](#microsoft-defender-for-identity)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/DNS.json)

## Database

### Controls
- [Advanced Threat Protection for Azure SQL Database](#advanced-threat-protection-for-azure-sql-database)
- [Alerts for Azure Cosmos DB](#alerts-for-azure-cosmos-db)
- [SQL Vulnerability Assessment](#sql-vulnerability-assessment)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Database.json)

## Encryption

### Controls
- [Azure VPN Gateway](#azure-vpn-gateway)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Encryption.json)

## File system

### Controls
- [File Integrity Monitoring](#file-integrity-monitoring)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/File_system.json)

## Identity

### Controls
- [Azure AD Identity Protection](#azure-ad-identity-protection)
- [Azure AD Identity Secure Score](#azure-ad-identity-secure-score)
- [Azure AD Multi-Factor Authentication](#azure-ad-multi-factor-authentication)
- [Azure AD Password Policy](#azure-ad-password-policy)
- [Azure AD Privileged Identity Management](#azure-ad-privileged-identity-management)
- [Azure Active Directory Password Protection](#azure-active-directory-password-protection)
- [Conditional Access](#conditional-access)
- [Continuous Access Evaluation](#continuous-access-evaluation)
- [Managed identities for Azure resources](#managed-identities-for-azure-resources)
- [Microsoft Defender for Identity](#microsoft-defender-for-identity)
- [Passwordless Authentication](#passwordless-authentication)
- [Role Based Access Control](#role-based-access-control)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Identity.json)

## Linux

### Controls
- [Azure Automation Update Management](#azure-automation-update-management)
- [Azure Defender for App Service](#azure-defender-for-app-service)
- [Docker Host Hardening](#docker-host-hardening)
- [File Integrity Monitoring](#file-integrity-monitoring)
- [Linux auditd alerts and Log Analytics agent integration](#linux-auditd-alerts-and-log-analytics-agent-integration)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Linux.json)

## MFA

### Controls
- [Azure AD Identity Secure Score](#azure-ad-identity-secure-score)
- [Azure AD Multi-Factor Authentication](#azure-ad-multi-factor-authentication)
- [Azure AD Privileged Identity Management](#azure-ad-privileged-identity-management)
- [Conditional Access](#conditional-access)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/MFA.json)

## Microsoft 365 Defender

### Controls
- [Azure AD Identity Protection](#azure-ad-identity-protection)
- [Microsoft Defender for Identity](#microsoft-defender-for-identity)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Microsoft_365_Defender.json)

## Network

### Controls
- [Alerts for DNS](#alerts-for-dns)
- [Azure Alerts for Network Layer](#azure-alerts-for-network-layer)
- [Azure DDOS Protection Standard](#azure-ddos-protection-standard)
- [Azure DNS Alias Records](#azure-dns-alias-records)
- [Azure DNS Analytics](#azure-dns-analytics)
- [Azure Firewall](#azure-firewall)
- [Azure Network Traffic Analytics](#azure-network-traffic-analytics)
- [Azure Private Link](#azure-private-link)
- [Azure VPN Gateway](#azure-vpn-gateway)
- [Network Security Groups](#network-security-groups)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Network.json)

## Passwords

### Controls
- [Azure AD Multi-Factor Authentication](#azure-ad-multi-factor-authentication)
- [Azure AD Password Policy](#azure-ad-password-policy)
- [Azure Active Directory Password Protection](#azure-active-directory-password-protection)
- [Azure Key Vault](#azure-key-vault)
- [Passwordless Authentication](#passwordless-authentication)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Passwords.json)

## Registry

### Controls
- [File Integrity Monitoring](#file-integrity-monitoring)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Registry.json)

## VPN

### Controls
- [Azure VPN Gateway](#azure-vpn-gateway)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/VPN.json)

## WAF

### Controls
- [Azure Web Application Firewall](#azure-web-application-firewall)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/WAF.json)

## Web

### Controls
- [Azure Web Application Firewall](#azure-web-application-firewall)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Web.json)

## Web Access Firewall

### Controls
- [Azure Web Application Firewall](#azure-web-application-firewall)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Web_Access_Firewall.json)

## Windows

### Controls
- [Alerts for Windows Machines](#alerts-for-windows-machines)
- [Azure Automation Update Management](#azure-automation-update-management)
- [Azure Defender for App Service](#azure-defender-for-app-service)
- [File Integrity Monitoring](#file-integrity-monitoring)
- [Microsoft Defender for Identity](#microsoft-defender-for-identity)

### Navigator Layer
- [View](/mappings/Azure/layers/tags/Windows.json)
