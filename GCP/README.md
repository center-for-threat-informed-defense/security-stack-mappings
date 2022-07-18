
Google Cloud Platform Security Control Mappings to MITRE ATT&CK®
================================================================


These mappings of the Google Cloud Platform (GCP) security controls to MITRE ATT&CK® are designed to empower organizations with independent data on which native GCP security controls are most useful in defending against the adversary TTPs that they care about. These mappings are part of a collection of mappings of native product security controls to ATT&CK based on a common methodology, scoring rubric, data model, and tool set. This full set of resources is available on the Center’s project [page](https://ctid.mitre-engenuity.org/our-work/gcp/).

[Aggregate Navigator Layer For All Controls (JSON)](layers/platform.json)

# <a name='contents'>Contents</a>

* Controls
    * [1. Access Transparency](#access-transparency)
    * [2. Actifio Go](#actifio-go)
    * [3. AdvancedProtectionProgram](#advancedprotectionprogram)
    * [4. AnthosConfigManagement](#anthosconfigmanagement)
    * [5. Artifact Registry](#artifact-registry)
    * [6. Assured Workloads](#assured-workloads)
    * [7. BeyondCorp Enterprise](#beyondcorp-enterprise)
    * [8. Binary Authorization](#binary-authorization)
    * [9. Certificate Authority Service](#certificate-authority-service)
    * [10. Chronicle](#chronicle)
    * [11. Cloud Armor](#cloud-armor)
    * [12. Cloud Asset Inventory](#cloud-asset-inventory)
    * [13. Cloud CDN](#cloud-cdn)
    * [14. Cloud Data Loss Prevention](#cloud-data-loss-prevention)
    * [15. Cloud Hardware Security Module (HSM)](#cloud-hardware-security-module-hsm)
    * [16. Cloud IDS](#cloud-ids)
    * [17. Cloud Identity](#cloud-identity)
    * [18. Cloud Key Management](#cloud-key-management)
    * [19. Cloud Logging](#cloud-logging)
    * [20. Cloud NAT](#cloud-nat)
    * [21. Cloud Storage](#cloud-storage)
    * [22. CloudVPN](#cloudvpn)
    * [23. Confidential VM and Compute Engine](#confidential-vm-and-compute-engine)
    * [24. Config Connector](#config-connector)
    * [25. Container Registry](#container-registry)
    * [26. Data Catalog](#data-catalog)
    * [27. Deployment Manager](#deployment-manager)
    * [28. Endpoint Management](#endpoint-management)
    * [29. Firewalls](#firewalls)
    * [30. Google Kubernetes Engine](#google-kubernetes-engine)
    * [31. Hybrid Connectivity](#hybrid-connectivity)
    * [32. Identity Aware Proxy](#identity-aware-proxy)
    * [33. Identity and Access Management](#identity-and-access-management)
    * [34. IdentityPlatform](#identityplatform)
    * [35. Packet Mirroring](#packet-mirroring)
    * [36. Policy Intelligence](#policy-intelligence)
    * [37. ReCAPTCHA Enterprise](#recaptcha-enterprise)
    * [38. ResourceManager](#resourcemanager)
    * [39. Secret Manager](#secret-manager)
    * [40. Security Command Center](#security-command-center)
    * [41. Shielded VM](#shielded-vm)
    * [42. Siemplify](#siemplify)
    * [43. Terraform on Google Cloud](#terraform-on-google-cloud)
    * [44. Titan Security Key](#titan-security-key)
    * [45. VMManager](#vmmanager)
    * [46. VPC Service Controls](#vpc-service-controls)
    * [47. Virtual Private Cloud](#virtual-private-cloud)
    * [48. Virus Total](#virus-total)
    * [49. Web Risk](#web-risk)
* Control Tags
    * [1. Access Control Policies](#tag-access-control-policies)
    * [2. Access Management](#tag-access-management)
    * [3. Adaptive Network Hardening](#tag-adaptive-network-hardening)
    * [4. Analytics](#tag-analytics)
    * [5. Antimalware](#tag-antimalware)
    * [6. Antivirus](#tag-antivirus)
    * [7. Auditing](#tag-auditing)
    * [8. Binary Authorization](#tag-binary-authorization)
    * [9. Certificate Service](#tag-certificate-service)
    * [10. Chronicle](#tag-chronicle)
    * [11. Cloud IDS](#tag-cloud-ids)
    * [12. Config Management](#tag-config-management)
    * [13. Configuration Management](#tag-configuration-management)
    * [14. Containers](#tag-containers)
    * [15. Credentials](#tag-credentials)
    * [16. Data Catalog](#tag-data-catalog)
    * [17. Data Loss Prevention](#tag-data-loss-prevention)
    * [18. Data Security](#tag-data-security)
    * [19. Database](#tag-database)
    * [20. Denial of Service](#tag-denial-of-service)
    * [21. Domain Name System (DNS)](#tag-domain-name-system-dns)
    * [22. Encryption](#tag-encryption)
    * [23. Firewall](#tag-firewall)
    * [24. Identity](#tag-identity)
    * [25. Internet of Things (IoT)](#tag-internet-of-things-iot)
    * [26. Intrusion Detection Service (IDS)](#tag-intrusion-detection-service-ids)
    * [27. Kubernetes](#tag-kubernetes)
    * [28. Logging](#tag-logging)
    * [29. Malware](#tag-malware)
    * [30. Multi-Factor Authentication](#tag-multi-factor-authentication)
    * [31. Network](#tag-network)
    * [32. Not Mappable](#tag-not-mappable)
    * [33. OS Security](#tag-os-security)
    * [34. Palo Alto Network's Threat Signatures](#tag-palo-alto-network-s-threat-signatures)
    * [35. Passwords](#tag-passwords)
    * [36. Patch Management](#tag-patch-management)
    * [37. Phishing](#tag-phishing)
    * [38. Policy](#tag-policy)
    * [39. Reports](#tag-reports)
    * [40. Role Based Access Control](#tag-role-based-access-control)
    * [41. SIEM](#tag-siem)
    * [42. Security Command Center](#tag-security-command-center)
    * [43. Storage](#tag-storage)
    * [44. Threat Detection](#tag-threat-detection)
    * [45. Threat Hunting](#tag-threat-hunting)
    * [46. VPN](#tag-vpn)
    * [47. Virtual Private Cloud](#tag-virtual-private-cloud)
    * [48. Vulnerability Analysis](#tag-vulnerability-analysis)
    * [49. Vulnerability Management](#tag-vulnerability-management)

# Controls
<a name='access-transparency'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 1. Access Transparency



Access Transparency logs record the actions that Google personnel take when accessing customer content. Access Transparency log entries include details such as the affected resource and action, the time of the action, the reason for the action, and information about the accessor.

- [Mapping File](AccessTransparency.yaml) ([YAML](AccessTransparency.yaml))
- [Navigator Layer](layers/AccessTransparency.json) ([JSON](layers/AccessTransparency.json))

### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1199 - Trusted Relationship](https://attack.mitre.org/techniques/T1199/)|Detect|Minimal|This control may expose and detect malicious access of customer data and resources by compromised Google personnel accounts. The trusted relationship between Google personnel who administer and allow customers to host their workloads on the cloud may be abused by insider threats or compromise of Google.|
|[T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)|Detect|Minimal|This control may expose and detect malicious access of data from cloud storage by compromised Google personnel accounts.|
  


### Tags
- [Access Management](#tag-access-management)
- [Auditing](#tag-auditing)
  


### References
- <https://cloud.google.com/cloud-provider-access-management/access-transparency/docs/overview>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='actifio-go'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 2. Actifio Go



Actifio GO is a Google Cloud backup and disaster recovery offering which enables powerful data protection for Google Cloud and hybrid workloads. Actifio GO supports Google workloads such as Compute Engine and VMware Engine, as well as hybrid workloads like VMware, SAP HANA, Oracle and SQL Server, and others.

- [Mapping File](ActifioGo.yaml) ([YAML](ActifioGo.yaml))
- [Navigator Layer](layers/ActifioGo.json) ([JSON](layers/ActifioGo.json))

### Mapping Comments


This mapping was scored as significant due to the control’s notable remediation capabilities.  


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)|Protect|Minimal|Actifio provides encryption in transit for data traveling between Actifio appliances, Actifio and VMware environments, and for data traversing the control channel utilizing the Actifio connector. This provides significant protection against Network Sniffing since adversaries would be unable to read encrypted traffic. However, Actifio only encrypts data in transit that interacts with Actifio components, rather than all traffic for a system. This is also only relevant when traffic is being backed up, which is a small amount of the time. In this case, it has been given a rating of Minimal.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Protect|Partial|Actifio uses two command line (CLI) interfaces for customer end-users and Actifio support personnel. All CLI access is via key based authentication only. This provides significant protection against brute force password attacks. However, this only provides protection for Actifio components, rather than all components for a system. This has resulted in a score of Partial.|
|[T1485 - Data Destruction](https://attack.mitre.org/techniques/T1485/)|Respond|Significant|Actifio is a copy data management plaform that virtualizes application data to improve an organizations resiliency and cloud mobility. Actifio allows an organization to take regular backups and provides several methods of restoring applications and/or VM data to a previous state. This provide significant capability to respond to a Data Destruction event since an organization could easily restore lost data back to the latest backup.|
|[T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)|Respond|Significant|Actifio is a copy data management plaform that virtualizes application data to improve an organizations resiliency and cloud mobility. Actifio allows an organization to take regular backups and provides several methods of restoring applications and/or VM data to a previous state. This provide significant capability to respond to an adversary maliciously encrypting  system data since an organization could restore encrypted data back to the latest backup.|
|[T1490 - Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)|Respond|Significant|Actifio is a copy data management plaform that virtualizes application data to improve an organizations resiliency and cloud mobility. Actifio allows an organization to take regular backups and provides several methods of restoring applications and/or VM data to a previous state. This provide significant capability to respond to an adversary deleting or removing built-in operating system data and services since an organization could restore system and services back to the latest backup.|
|[T1491 - Defacement](https://attack.mitre.org/techniques/T1491/)|Respond|Significant|Actifio is a copy data management plaform that virtualizes application data to improve an organizations resiliency and cloud mobility. Actifio allows an organization to take regular backups and provides several methods of restoring applications and/or VM data to a previous state. This provide significant capability to respond to Defacement since an organization could easily restore defaced images back to the latest backup.|
|[T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)|Protect|Partial|Actifio Sky can be configured with optional storage pool encryption. Administrative end-user credentials are hashed with a strong one-way salted SHA256 hash in the appliance database. Credentials used by the appliance to access other systems (vCenters, databases,) are stored in an AES256 encrypted form. This provides significant protection against adversaries searching compromised Actifio systems for insecurely stored credentials. However, this does not provide protection for other credentials stored on non-Actifio components. This has resulted in a score of partial.|
|[T1561 - Disk Wipe](https://attack.mitre.org/techniques/T1561/)|Respond|Significant|Actifio is a copy data management plaform that virtualizes application data to improve an organizations resiliency and cloud mobility. Actifio allows an organization to take regular backups and provides several methods of restoring applications and/or VM data to a previous state. This provide significant capability to respond to a Disk Wipe since an organization could restore wiped data back to the latest backup.|
|[T1565 - Data Manipulation](https://attack.mitre.org/techniques/T1565/)|Respond|Significant|Actifio is a copy data management plaform that virtualizes application data to improve an organizations resiliency and cloud mobility. Actifio allows an organization to take regular backups and provides several methods of restoring applications and/or VM data to a previous state. This provide significant capability to respond to Data Manipulation since an organization could restore manipulated data back to the latest backup.|
  


### Tags
- [Storage](#tag-storage)
  


### References
- <https://www.actifio.com/solutions/cloud/google/>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='advancedprotectionprogram'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 3. AdvancedProtectionProgram



The Advanced Protection Program safeguards users with high visibility and sensitive information from targeted online attacks.  Current capabilities include MFA, blocking harmful downloads while using chrome, and prevention of data requests from non-vetted apps.

New protections are automatically added to defend against today’s wide range of threats.

- [Mapping File](AdvancedProtectionProgram.yaml) ([YAML](AdvancedProtectionProgram.yaml))
- [Navigator Layer](layers/AdvancedProtectionProgram.json) ([JSON](layers/AdvancedProtectionProgram.json))

### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)|Protect|Significant|Advanced Protection Program enables the use of a security key for multi-factor authentication. Implementing MFA on remote service logons prevents adversaries from using valid accounts to access those services.<br/>|
|[T1078.002 - Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)|Protect|Significant|Advanced Protection Program enables the use of a security key for multi-factor authentication. Integrating multi-factor authentication (MFA) as part of organizational policy can greatly reduce the risk of an adversary gaining control of valid credentials that may be used for additional tactics such as initial access, lateral movement, and collecting information.<br/>|
|[T1078.004 - Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)|Protect|Significant|Advanced Protection Program enables the use of a security key for multi-factor authentication. Integrating multi-factor authentication (MFA) as part of organizational policy can greatly reduce the risk of an adversary gaining control of valid credentials that may be used for additional tactics such as initial access, lateral movement, and collecting information.<br/>|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Protect|Significant|Advanced Protection Program enables the use of a security key for multi-factor authentication. This provides significant protection against unauthorized users from accessing and manipulating accounts to retain access.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Protect|Significant|Advanced Protection Program enables the use of a security key for multi-factor authentication. This provides significant protection against Brute Force techniques attempting to gain access to accounts.|
|[T1110.001 - Password Guessing](https://attack.mitre.org/techniques/T1110/001/)|Protect|Significant|Advanced Protection Program enables the use of a security key for multi-factor authentication. This provides significant protection against Brute Force techniques attempting to gain access to accounts.|
|[T1110.002 - Password Cracking](https://attack.mitre.org/techniques/T1110/002/)|Protect|Significant|Advanced Protection Program enables the use of a security key for multi-factor authentication. This provides significant protection against Brute Force techniques attempting to gain access to accounts.|
|[T1110.003 - Password Spraying](https://attack.mitre.org/techniques/T1110/003/)|Protect|Significant|Advanced Protection Program enables the use of a security key for multi-factor authentication. This provides significant protection against Brute Force techniques attempting to gain access to accounts.|
|[T1110.004 - Credential Stuffing](https://attack.mitre.org/techniques/T1110/004/)|Protect|Significant|Advanced Protection Program enables the use of a security key for multi-factor authentication. This provides significant protection against Brute Force techniques attempting to gain access to accounts.|
|[T1114 - Email Collection](https://attack.mitre.org/techniques/T1114/)|Protect|Significant|Advanced Protection Program enables the use of a security key for multi-factor authentication. Enabling MFA reduces the usefulness of usernames and passwords that may be collected via email since adversaries won't have the associated security keys to gain access.<br/>|
|[T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)|Protect|Significant|Advanced Protection Program enables the use of a security key for multi-factor authentication. Enabling MFA for remote service accounts can mitigate an adversary's ability to leverage stolen credentials since they won't have the respective security key to gain access.<br/>|
|[T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)|Protect|Significant|Advanced Protection Program enables the use of a security key for multi-factor authentication. Enabling Advanced Protection Program for all users at an organization can prevent adversaries from maintaining access via created accounts because any accounts they create won't have the required security keys for MFA.<br/>|
|[T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)|Protect|Significant|Advanced Protection Program enables the use of a security key for multi-factor authentication. Restricting access via MFA provides significant protection against adversaries accessing data objects from cloud storage.<br/>|
|[T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)|Protect|Significant|Advanced Protection Program enables the use of a security key for multi-factor authentication. Integrating multi-factor authentication as part of organizational policy can greatly reduce the risk of an adversary gaining control of valid credentials that may be used for additional tactics such as initial access, lateral movement, and collecting information.<br/>|
  


### Tags
- [Multi-Factor Authentication](#tag-multi-factor-authentication)
- [Phishing](#tag-phishing)
  


### References
- <https://landing.google.com/advancedprotection/>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='anthosconfigmanagement'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 4. AnthosConfigManagement



Anthos Config Management enables platform operators to automatically deploy shared environment configurations and enforce approved security policies across Kubernetes clusters on-premises, on GKE, and in other public cloud platforms. It also lets platform admins configure Google Cloud services using the same resource model.


- [Mapping File](AnthosConfigManagement.yaml) ([YAML](AnthosConfigManagement.yaml))
- [Navigator Layer](layers/AnthosConfigManagement.json) ([JSON](layers/AnthosConfigManagement.json))

### Mapping Comments


Based on the medium detection coverage for the correlated cyber-attacks, most of the techniques and sub-techniques in this security solution were rated as partial.  


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Protect|Partial|Anthos Config Management lets you create and manage Kubernetes objects across multiple clusters at once. PodSecurityPolicies can be enforced to prevent Pods from using the root Linux user. Based on the medium detection coverage, this was scored as partial.|
|[T1078.001 - Default Accounts](https://attack.mitre.org/techniques/T1078/001/)|Protect|Partial|Anthos Config Management lets you create and manage Kubernetes objects across multiple clusters at once. PodSecurityPolicies can be enforced to prevent Pods from using the root Linux user. Based on the medium detection coverage, this sub-technique was scored as partial.|
|[T1078.004 - Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)|Protect|Partial|Anthos Config Management lets you create and manage Kubernetes objects across multiple clusters at once. PodSecurityPolicies can be enforced to prevent Pods from using the root Linux user. Based on the medium detection coverage, this sub-technique was scored as partial.|
|[T1525 - Implant Internal Image](https://attack.mitre.org/techniques/T1525/)|Detect|Partial||
|[T1525 - Implant Internal Image](https://attack.mitre.org/techniques/T1525/)|Protect|Partial|Prevent configuration drift with continuous monitoring of your cluster state, using the declarative model to apply policies that enforce compliance. This control can periodically check the integrity of images and containers used in cloud deployments to ensure that adversaries cannot implant malicious code to gain access to an environment.|
|[T1552.007 - Container API](https://attack.mitre.org/techniques/T1552/007/)|Protect|Partial|Adversaries may gather credentials via APIs within a containers environment. APIs in these environments, such as the Docker API and Kubernetes APIs. Anthos Config Management can manage configuration for any Kubernetes API, including policies for the Istio service mesh, resource quotas, and access control policies.|
|[T1609 - Container Administration Command](https://attack.mitre.org/techniques/T1609/)|Protect|Partial|Anthos Config Management lets you create and manage Kubernetes objects across multiple clusters at once. PodSecurityPolicies can be enforced to prevent Pods from using the root Linux user and prevents pods from running privileged containers. In hindsight this can ensure containers are not running as root by default.|
|[T1610 - Deploy Container](https://attack.mitre.org/techniques/T1610/)|Protect|Partial|Anthos Config Management's Policy Controller enables you to enforce fully programmable policies on your clusters. You can use these policies to shift security left and guard against violations during development and test time, as well as runtime violations. This control can be used to block adversaries that try to deploy new containers with malware or configurations policies that are not in compliance with security policies already defined.|
|[T1611 - Escape to Host](https://attack.mitre.org/techniques/T1611/)|Protect|Partial|Anthos Config Management lets you create and manage Kubernetes objects across multiple clusters at once. PodSecurityPolicies can be enforced to prevent Pods from using the root Linux user and prevents pods from running privileged containers. This control can be used to limit container access to host process namespaces, the host network, and the host file system, which may enable adversaries to break out of containers and gain access to the underlying host.|
|[T1613 - Container and Resource Discovery](https://attack.mitre.org/techniques/T1613/)|Protect|Significant|Adversaries may attempt to discover containers and other resources that are available within a containers environment. The "Network Policies" rule controls the network traffic inside clusters, denying direct remote access to internal systems through the use of network proxies, gateways, and firewalls|
  


### Tags
- [Configuration Management](#tag-configuration-management)
- [Containers](#tag-containers)
- [Policy](#tag-policy)
  


### References
- <https://cloud.google.com/anthos-config-management/ >
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='artifact-registry'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 5. Artifact Registry



Artifact Registry provides a single location for storing and managing your system packages and container images.

- [Mapping File](ArtifactRegistry.yaml) ([YAML](ArtifactRegistry.yaml))
- [Navigator Layer](layers/ArtifactRegistry.json) ([JSON](layers/ArtifactRegistry.json))

### Mapping Comments


This control may provide information about software vulnerabilities in the environment.   


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Protect|Partial|Once this control is deployed, it can detect known OS package vulnerabilities in various Linux OS packages (e.g., Debian, Ubuntu, Alpine, RHEL, CentOS, National Vulnerability Database)|
|[T1072 - Software Deployment Tools](https://attack.mitre.org/techniques/T1072/)|Protect|Minimal|Once this control is deployed, it can detect variations to store system packages and container images.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Protect|Partial|Once this control is deployed, it can detect known vulnerabilities in various Linux OS packages. This information can be used to patch, isolate, or remove vulnerable software and machines. This control does not directly protect against exploitation and is not effective against zero day attacks, vulnerabilities with no available patch, and other end-of-life packages.|
|[T1203 - Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)|Protect|Partial|Once this control is deployed, it can detect known vulnerabilities in various Linux OS packages. This information can be used to patch, isolate, or remove vulnerable software and machines. This control does not directly protect against exploitation and is not effective against zero day attacks, vulnerabilities with no available patch, and other end-of-life packages.|
|[T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)|Protect|Partial|Once this control is deployed, it can detect known vulnerabilities in various Linux OS packages. This information can be used to patch, isolate, or remove vulnerable software and machines. This control does not directly protect against exploitation and is not effective against zero day attacks, vulnerabilities with no available patch, and other end-of-life packages.|
|[T1211 - Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211/)|Protect|Partial|Once this control is deployed, it can detect variations to store system packages and images stored in the repository, which adversaries may target to establish persistence while evading cyber defenses.|
|[T1212 - Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212/)|Detect|Significant|Once this control is deployed, it can detect known OS package vulnerabilities in various Linux OS packages that could be used to escalate privileges and execute adversary-controlled code (e.g., Debian, Ubuntu, Alpine, RHEL, CentOS, National Vulnerability Database)|
|[T1525 - Implant Internal Image](https://attack.mitre.org/techniques/T1525/)|Protect|Partial|Once this control is deployed, it can detect known vulnerabilities in Docker containers. This information can be used to detect malicious implanted images in the environment. This control does not directly protect against exploitation.|
|[T1610 - Deploy Container](https://attack.mitre.org/techniques/T1610/)|Protect|Partial|Once this control is deployed, it can detect known vulnerabilities in Docker containers. This information can be used to detect malicious implanted images in the environment. This control does not directly protect against exploitation.|
  


### Tags
- [Containers](#tag-containers)
- [OS Security](#tag-os-security)
- [Vulnerability Analysis](#tag-vulnerability-analysis)
  


### References
- <https://cloud.google.com/container-analysis/docs/container-analysis>
- <https://cloud.google.com/container-analysis/docs/container-scanning-overview>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='assured-workloads'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 6. Assured Workloads



Assured Workloads provides Google Cloud customers with the ability to apply security controls to an environment, in support of compliance requirements, without compromising the quality of their cloud experience. Customers should only use Assured Workloads if their Google Cloud use case is actively subject to regulatory compliance.	

- [Mapping File](AssuredWorkloads.yaml) ([YAML](AssuredWorkloads.yaml))
- [Navigator Layer](layers/AssuredWorkloads.json) ([JSON](layers/AssuredWorkloads.json))

### Mapping Comments


Assure workloads doesn't appear to provide any specific mitigation for TTPs. Rather, it focuses on enabling customers to apply other security controls in ways to support regulatory compliance. As a result, we have not mapped any TTPs to this control.	  


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
  


### Tags
- [Not Mappable](#tag-not-mappable)
  


### References
- <https://cloud.google.com/assured-workloads/docs/concept-overview>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='beyondcorp-enterprise'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 7. BeyondCorp Enterprise



A zero trust solution that enables secure access with integrated threat and data protection. It provides secure access to critical applications and services, and increases visibility into unsafe user activity.

- [Mapping File](BeyondCorpEnterprise.yaml) ([YAML](BeyondCorpEnterprise.yaml))
- [Navigator Layer](layers/BeyondCorpEnterprise.json) ([JSON](layers/BeyondCorpEnterprise.json))

### Mapping Comments


This solution was rated as significant due to the control’s high threat protection coverage and temporal factors (e.g., real-time, periodical).  


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)|Protect|Significant|This control can help mitigate adversaries that may try to steal data over network protocols.  Data loss prevention can detect and block sensitive data being uploaded via web browsers. In Beyond Corp Enterprise, Data Loss Prevention (DLP) features to use with Chrome to implement sensitive data detection for files that are uploaded and downloaded, and for content that is pasted or dragged and dropped. An example includes a rule setting that is used to block files from being uploaded via Chrome browser.|
|[T1071.001 - Web Protocols](https://attack.mitre.org/techniques/T1071/001/)|Detect|Significant|Google chrome policies can be setup through the Google Admin console, which can ensure checks for sensitive data or help protect Chrome users from content that may contain malware. This also enables certain files to be sent for analysis, and in return the admin can then choose to allow or block uploads and downloads for those scanned and unscanned files. By specifying a list of URL patterns, these policies can determine which pages identified through Chrome violates a rule, and end users are prevented from accessing the page.|
|[T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)|Protect|Partial|Implementing BeyondCorp Enterprise enacts a zero trust model. No one can access your resources unless they meet all the rules and conditions. Instead of securing your resources at the network-level, access controls are instead applied to individual devices and users.|
|[T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)|Protect|Partial|To enable additional protections against data loss and malware in Chrome, you need to enable Chrome Enterprise connectors so content gathered in Chrome is uploaded to Google Cloud for analysis. The Chrome Enterprise connectors must be enabled for DLP rules to integrate with Chrome.|
|[T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)|Protect|Significant|Access Context Manager allows Google Cloud organization administrators to define fine-grained, attribute based access control for projects and resources. Access levels applied on resources with IAM Conditions enforce fine-grained access control based on a variety of attributes, including IP subnetworks. Adversaries may obtain leaked credentials; however, this control can block specific  adversaries from gaining access permission controls by admins granting an access level based on the IP address of the originating request.<br/><br/>|
|[T1566 - Phishing](https://attack.mitre.org/techniques/T1566/)|Detect|Significant|This control can help detect malicious links sent via phishing. The details include a list of samples of message delivery events.  Each item in the list includes the date, message ID, subject hash, message body hash, username of the recipient, attachment hashes, and your primary domain name.|
|[T1566 - Phishing](https://attack.mitre.org/techniques/T1566/)|Protect|Significant|This control can help detect malicious links sent via phishing. The details include a list of samples of message delivery events.  Each item in the list includes the date, message ID, subject hash, message body hash, username of the recipient, attachment hashes, and your primary domain name. As a result, this can be used to block senders.|
|[T1566.001 - Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)|Detect|Minimal|This control can help detect malicious links sent via phishing. The details include a list of samples of message delivery events.  Each item in the list includes the date, message ID, subject hash, message body hash, username of the recipient, attachment hashes, and your primary domain name. This can be used to block senders.|
|[T1567 - Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)|Protect|Significant|This control can help mitigate adversaries that may try to steal data over web services. A threat actor gaining access to a corporate network can plant code to perform reconnaissance, discover privileged users’ credentials, and adversaries can use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel. This can cause exfiltration to a command-and-control server out on the internet. Data loss prevention can be used to detect and block sensitive data being uploaded to web services via web browsers.|
|[T1567.002 - Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/)|Protect|Significant|This control can help mitigate adversaries that may try to steal data over web services. A threat actor gaining access to a corporate network can plant code to perform reconnaissance, discover privileged users’ credentials, and adversaries can use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel. This can cause exfiltration to a command-and-control server out on the internet. Data loss prevention can be used to detect and block sensitive data being uploaded to web services via web browsers.|
  


### Tags
- [Access Control Policies](#tag-access-control-policies)
- [Data Loss Prevention](#tag-data-loss-prevention)
  


### References
- <https://cloud.google.com/beyondcorp-enterprise/docs/overview>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='binary-authorization'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 8. Binary Authorization



Binary Authorization is a service that provides software supply-chain security for container-based applications.

- [Mapping File](BinaryAuthorization.yaml) ([YAML](BinaryAuthorization.yaml))
- [Navigator Layer](layers/BinaryAuthorization.json) ([JSON](layers/BinaryAuthorization.json))

### Mapping Comments


Binary authorization provides the capability to configure a policy that is enforced when an attempt is made to deploy a container image.  


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1036.001 - Invalid Code Signature](https://attack.mitre.org/techniques/T1036/001/)|Protect|Significant|Each image has a signer digitally sign using a private key. At deploy time, the enforcer uses the attester's public key to verify the signature in the attestation.|
|[T1053.007 - Container Orchestration Job](https://attack.mitre.org/techniques/T1053/007/)|Protect|Significant|Each image has a signer digitally sign using a private key. At deploy time, the enforcer uses the attester's public key to verify the signature in the attestation.|
|[T1204.003 - Malicious Image](https://attack.mitre.org/techniques/T1204/003/)|Protect|Significant|Each image has a signer digitally sign using a private key. At deploy time, the enforcer uses the attester's public key to verify the signature in the attestation.|
|[T1525 - Implant Internal Image](https://attack.mitre.org/techniques/T1525/)|Protect|Significant|Each image has a signer digitally sign using a private key. At deploy time, the enforcer uses the attester's public key to verify the signature in the attestation.|
|[T1554 - Compromise Client Software Binary](https://attack.mitre.org/techniques/T1554/)|Protect|Significant|Each image has a signer digitally sign using a private key. At deploy time, the enforcer uses the attester's public key to verify the signature in the attestation.|
|[T1601 - Modify System Image](https://attack.mitre.org/techniques/T1601/)|Protect|Significant|Each image has a signer digitally sign using a private key. At deploy time, the enforcer uses the attester's public key to verify the signature in the attestation.|
|[T1610 - Deploy Container](https://attack.mitre.org/techniques/T1610/)|Protect|Significant|Based on configured policies, Binary Authorization allows or blocks deployment of container images.|
|[T1612 - Build Image on Host](https://attack.mitre.org/techniques/T1612/)|Protect|Significant|Each container image  generated has a signer digitally sign using a private key to generate the attestation report. At deploy time, the enforcer uses the attester's public key to verify the signature or will block this process.|
  


### Tags
- [Binary Authorization](#tag-binary-authorization)
  


### References
- <https://cloud.google.com/binary-authorization/docs/overview>
- <https://cloud.google.com/binary-authorization/docs/attestations>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='certificate-authority-service'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 9. Certificate Authority Service



Google Cloud Certificate Authority Service (CAS) is a highly available & scalable service that enables you to simplify, automate, and customize the deployment, management, and security of private certificate authorities (CA).

- [Mapping File](CertificateAuthorityService.yaml) ([YAML](CertificateAuthorityService.yaml))
- [Navigator Layer](layers/CertificateAuthorityService.json) ([JSON](layers/CertificateAuthorityService.json))

### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)|Protect|Minimal|This control may mitigate against Network Sniffing by providing certificates for internal endpoints and applications to use with asymmetric encryption. This control helps protect the issuing Certificate Authority with the use of Google's IAM and policy controls.|
  


### Tags
- [Certificate Service](#tag-certificate-service)
- [Network](#tag-network)
  


### References
- <https://cloud.google.com/certificate-authority-service/docs>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='chronicle'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 10. Chronicle



Chronicle is Google Cloud's data aggregation platform and threat detection system designed to collect massive amounts of security telemetry, detect malicious events, and report based on known indicators of compromise. Most of the attacks were correlated using Chronicle's documentation and the threat detection rules available on their GitHub repo.

- [Mapping File](Chronicle.yaml) ([YAML](Chronicle.yaml))
- [Navigator Layer](layers/Chronicle.json) ([JSON](layers/Chronicle.json))

### Mapping Comments


This mapping is given a score of minimal due to low threat detection fidelity from specific (sub-)techniques found in MITRE’s ATT&CK framework. 

Chronicle is able to ingest and aggregate raw logs from multiple data formats, to include: json, csv, xml, and syslog.   


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)|Detect|Minimal|Chronicle is able to detect suspicious command-line process attempted to escalate privileges.  Examples of credential access system events include:<br/>(e.g.,"re.regex($selection.target.registry.registry_value_data, `.*DumpCreds.*`) or re.regex($selection.target.registry.registry_value_data, `.*Mimikatz.*`) or re.regex($selection.target.registry.registry_value_data, `.*PWCrack.*`) or $selection.target.registry.registry_value_data = "HTool/WCE" or re.regex($selection.target.registry.registry_value_data, `.*PSWtool.*`) or re.regex($selection.target.registry.registry_value_data, `.*PWDump.*`)).<br/><br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/ioc_sigma/antivirus/antivirus_password_dumper_detection.yaral|
|[T1003.001 - LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)|Detect|Minimal|Chronicle is able to detect suspicious command-line process attempted to escalate privileges. For example: access credential material stored in the procecss memory of the Local Security Authority Subsystem Service (LSASS) on Windows machines (e.g., lsass\.exe). <br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/tree/main/soc_prime_rules/threat_hunting/windows|
|[T1003.003 - NTDS](https://attack.mitre.org/techniques/T1003/003/)|Detect|Minimal|Chronicle is able to trigger an alert based on process creations and  attacks against the NTDS database on Windows platforms (e.g., execution of "ntdsutil.exe")<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/tree/main/soc_prime_rules/threat_hunting/windows|
|[T1011 - Exfiltration Over Other Network Medium](https://attack.mitre.org/techniques/T1011/)|Detect|Minimal|Chronicle is able to trigger an alert based off suspicious system processes or command-line arguments that could indicate exfiltration of data over other network mediums.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/tree/main/suspicious<br/><br/>|
|[T1016 - System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/)|Detect|Minimal|Chronicle is able to trigger an alert based off processes and command-line arguments that may indicate adversary reconnaissance and information discovery techniques for network configuration settings (e.g., "net config", "ipconfig.exe", "nbtstat.exe).<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/possible_system_network_configuration_discovery__sysmon_windows_logs.yaral|
|[T1018 - Remote System Discovery](https://attack.mitre.org/techniques/T1018/)|Detect|Minimal|Chronicle attempts to identify remote <br/>systems via ping sweep. This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/ioc_sigma/process_creation/remote_system_discovery___ping_sweep.yaral|
|[T1020 - Automated Exfiltration](https://attack.mitre.org/techniques/T1020/)|Detect|Minimal|Chronicle is able to trigger an alert based off suspicious sytem processes, such as using bitsadmin to automatically exfiltrate data from Windows machines (e.g., ".*\\bitsadmin\.exe").<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/main/soc_prime_rules/threat_hunting/windows/data_exfiltration_attempt_via_bitsadmin.yaral|
|[T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)|Detect|Minimal|Chronicle is able to detect an alert based on system events, such as remote service connections.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/tree/main/soc_prime_rules/threat_hunting/windows|
|[T1021.002 - SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)|Detect|Minimal|Chronicle is able to trigger an alert for net use commands detected for SMB/Windows admin shares (e.g., " net use.* (C|ADMIN|IPC)$").<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/possible_system_network_connections_discovery__sysmon_windows_logs.yaral|
|[T1021.004 - SSH](https://attack.mitre.org/techniques/T1021/004/)|Detect|Minimal|Chronicle is able to trigger an alert based on accounts and authorized device access to a certain IP range (e.g., "Attempted Lateral Movement via SSH metadata pivoting").<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/tree/main/gcp_cloudaudit|
|[T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)|Detect|Minimal|Chronicle is able to trigger an alert based off suspicious command line arguments or processes that indicate obfuscation techniques to evade cyber defenses. For example, when cmd.exe has been obfuscated.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/detect_cmd_exe_obfuscation.yaral<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/ursnif_trojan_detection__cmd_obfuscation.yaral|
|[T1027.004 - Compile After Delivery](https://attack.mitre.org/techniques/T1027/004/)|Detect|Minimal|Chronicle can trigger an alert based on delivery of encrypted or encoded payloads with uncompiled code. <br/><br/>This technique was scored as minimal based on low detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/process_creation/suspicious_powershell_parameter_substring.yaral<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/process_creation/encoded_iex.yaral|
|[T1033 - System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/)|Detect|Minimal|Chronicle is able to trigger an alert based off command-line arguments that could indicate adversary's attempting to get information about system users (e.g., primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system).<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/possible_system_owner_user_discovery__sysmon_windows_logs.yaral|
|[T1036 - Masquerading](https://attack.mitre.org/techniques/T1036/)|Detect|Minimal|Chronicle is able to trigger an alert based on Windows starting uncommon processes  (e.g., Detects Winword starting uncommon sub process MicroScMgmt.exe used for CVE-2015-1641).<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/proactive_exploit_detection/process_creation/exploit_for_cve_2015_1641.yaral|
|[T1036.005 - Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)|Detect|Minimal|Chronicle can trigger an alert based on malware masquerading as legitimate process for example, Adobe's Acrobat Reader (e.g., re.regex($selection.target.process.file.full_path, `.*\\AcroRD32\.exe).<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/ioc_sigma/sysmon/detects_malware_acrord32_exe_execution_process.yaral|
|[T1037 - Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1037/)|Detect|Minimal|Chronicle is able to trigger an alert based on registry modifications related to custom logon scripts. (e.g., "REGISTRY_CREATION", ""REGISTRY_MODIFICATION", "HKCU|HKEY_CURRENT_USER").<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/mitre_attack/T1547_001_windows_registry_run_keys_startup_folder.yaral|
|[T1037.003 - Network Logon Script](https://attack.mitre.org/techniques/T1037/003/)|Detect|Minimal|Chronicle triggers an alert based on suspicious connections (e.g., Netlogon connections).<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/proactive_exploit_detection/system/vulnerable_netlogon_secure_channel_connection_allowed.yaral<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/sysmon/logon_scripts__userinitmprlogonscript.yaral|
|[T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)|Detect|Minimal|Chronicle is able to trigger an alert based off suspicious system processes or command-line arguments that could indicate exfiltration of data over the C2 channel.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/sysmon/possible_data_exfiltration_via_smtp.yaral<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/data_exfiltration_attempt_via_bitsadmin.yaral<br/><br/>|
|[T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)|Detect|Minimal|Chronicle is able to trigger an alert based off suspicious system processes that could indicate exfiltration attempts using cURL from Windows machines (e.g., C:\\Windows\\System32\\curl.exe).<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/suspicious_curl_usage.yaral|
|[T1049 - System Network Connections Discovery](https://attack.mitre.org/techniques/T1049/)|Detect|Minimal|Chronicle is able to trigger an alert based off command-line arguments that could indicate adversary's attempting to get information about network connections (e.g., "net config", "net use", "net file").<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/possible_system_network_connections_discovery__sysmon_windows_logs.yaral|
|[T1052 - Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052/)|Detect|Minimal|Chronicle is able to trigger alerts based on system events, such as: USB device detected.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/info/usb_new_device.yaral<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/usb_device_plugged.yaral|
|[T1052.001 - Exfiltration over USB](https://attack.mitre.org/techniques/T1052/001/)|Detect|Minimal|Chronicle is able to trigger an alert based on events, such as "new USB device is connected to a system".<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/usb_device_plugged.yaral<br/>|
|[T1053 - Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)|Detect|Minimal|Chronicle is able to trigger an alert based on  suspicious modifications to the infrastructure, such as: new task scheduling to execute programs. <br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/sysmon/a_scheduled_task_was_created.yaral<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/mitre_attack/T1053_005_windows_creation_of_scheduled_task.yaral|
|[T1053.005 - Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)|Detect|Minimal|Chronicle is able to trigger an alert based on scheduled tasks using the command line (e.g., "schtasks /create"). <br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/mitre_attack/T1053_005_windows_creation_of_scheduled_task.yaral|
|[T1055 - Process Injection](https://attack.mitre.org/techniques/T1055/)|Detect|Minimal|Chronicle can trigger an alert based on suspicious running processes that could be used to evade defenses and escalate privileges. (e.g., directory traversal attempts via attachment downloads).<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/process_creation/mavinject_process_injection.yaral|
|[T1056 - Input Capture](https://attack.mitre.org/techniques/T1056/)|Detect|Minimal|Chronicle is able to trigger an alert based on adversary methods of obtaining credentials or collecting information (e.g., web skimming attacks). <br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/cloud_security/proxy/the_gocgle_malicious_campaign.yaral|
|[T1056.003 - Web Portal Capture](https://attack.mitre.org/techniques/T1056/003/)|Detect|Minimal|Chronicle is able to trigger an alert based on adversary methods of obtaining credentials or collecting information (e.g., web skimming attacks). <br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/cloud_security/proxy/the_gocgle_malicious_campaign.yaral|
|[T1056.004 - Credential API Hooking](https://attack.mitre.org/techniques/T1056/004/)|Detect|Minimal|Chronicle is able to trigger an alert based on adversary methods of obtaining credentials or collecting information (e.g., web skimming attacks). <br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/cloud_security/proxy/the_gocgle_malicious_campaign.yaral|
|[T1057 - Process Discovery](https://attack.mitre.org/techniques/T1057/)|Detect|Minimal|Chronicle is able to trigger an alert based off command-line arguments that could indicate adversary's attempting to get information about running processes on Windows machines (e.g., "tasklist.exe", "Get-Process.*").<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/possible_process_enumeration__sysmon_windows_logs.yaral<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/sysmon/fake_zoom_installer_exe__devil_shadow_botnet.yaral|
|[T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)|Detect|Minimal|Chronicle is able to trigger an alert  based on system events of interest, for example: decoding Windows payloads using \"certutil.exe\" functionality.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/process_creation/suspicious_certutil_command.yaral|
|[T1059.003 - Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)|Detect|Minimal|Chronicle is able to trigger an alert based on suspicious behavior seen in the Windows command line.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/tree/main/soc_prime_rules/threat_hunting/windows<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/process_creation/suspicious_certutil_command.yaral|
|[T1059.007 - JavaScript](https://attack.mitre.org/techniques/T1059/007/)|Detect|Minimal|Chronicle triggers an alert based on webshell connections which are used to establish persistent access to a compromised machine [backdoor]. (e.g., `.*/config/keystore/.*\.js.*).<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/proactive_exploit_detection/webserver/oracle_weblogic_exploit.yaral|
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Detect|Minimal|Chronicle is able to trigger alert based on suspicious command line behavior that could indicate remote code exploitation attempts (e.g., detect exploits using child processes spawned by Windows DNS processes).<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/proactive_exploit_detection/process_creation/cve_2020_1350_dns_remote_code_exploit__sigred___via_cmdline.yaral|
|[T1070 - Indicator Removal on Host](https://attack.mitre.org/techniques/T1070/)|Detect|Minimal|Chronicle is able to trigger an alert when logs are cleared from the infrastructure.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/main/gcp_cloudaudit/gcp_log_deletion.yaral|
|[T1070.001 - Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)|Detect|Minimal|Chronicle is able to trigger an alert based on suspicious system events used to evade defenses, such as deletion of Windows security event logs. <br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/main/gcp_cloudaudit/gcp_log_deletion.yaral|
|[T1070.002 - Clear Linux or Mac System Logs](https://attack.mitre.org/techniques/T1070/002/)|Detect|Minimal|Chronicle is able to trigger an alert based on system events, such as deletion of cloud audit logs. <br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/main/gcp_cloudaudit/gcp_log_deletion.yaral|
|[T1070.004 - File Deletion](https://attack.mitre.org/techniques/T1070/004/)|Detect|Minimal|Chronicle is able to trigger an alert based off system processes that indicate when backup catalogs are deleted from a windows machine. <br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/backup_catalog_deleted.yaral|
|[T1070.006 - Timestomp](https://attack.mitre.org/techniques/T1070/006/)|Detect|Minimal|Chronicle is able to trigger an alert based off modifications to file time attributes to hide changes to existing files on Windows machines.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/file_creation_time_changed_via_powershell.yaral|
|[T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)|Detect|Minimal|Chronicle is able to trigger an alert based on suspicious modifications to the network infrastructure. <br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/tree/main/gcp_cloudaudit<br/><br/>https://github.com/chronicle/detection-rules/blob/main/gcp_cloudaudit/gcp_vpc_network_changes.yaral|
|[T1071.001 - Web Protocols](https://attack.mitre.org/techniques/T1071/001/)|Detect|Minimal|Chronicle is able to trigger an alert  based on system events of interest, for example: detection of the Sunburst C2 channel used as backdoor access in the SolarWinds compromise.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/ioc_sigma/dns/solarwinds_backdoor_c2_host_name_detected___via_dns.yaral|
|[T1072 - Software Deployment Tools](https://attack.mitre.org/techniques/T1072/)|Detect|Minimal|Chronicle is able to trigger alerts based off suspicious activity on a Linux host that could indicate a bind or reverse shell with Netcat tool.  Note: This rule requires installation of auditbeat on the host machine to properly function. <br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/linux/possible_bind_or_reverse_shell_via_netcat__auditbeat_for_linux.yaral|
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Detect|Minimal|Chronicle is able to trigger an alert based on RDP logons from non-private IP ranges. <br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/active_directory_security/security/remote_desktop_from_internet__via_audit.yaral|
|[T1082 - System Information Discovery](https://attack.mitre.org/techniques/T1082/)|Detect|Minimal|Chronicle is able to trigger an alert based on suspicious network behavior seen in malware RAT, such as Netwire activity via WScript or detect the utilization of wmic.exe in order to obtain specific system information.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/process_creation/detect_enumeration_via_wmi.yaral|
|[T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)|Detect|Minimal|Chronicle is able to trigger an alert based off command line arguments and suspicious system processes that could indicate adversary's account discovery techniques.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/account_discovery_activity_detector__sysmon_behavior.yaral|
|[T1087.004 - Cloud Account](https://attack.mitre.org/techniques/T1087/004/)|Detect|Minimal|Chronicle is able to trigger an alert based off command line arguments and suspicious system processes that could indicate adversary's account discovery techniques (e.g., "net user /domain", "C:\\Windows\\System32\\net.exe", "C:\\Windows\\System32\\query.exe).<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/account_discovery_activity_detector__sysmon_behavior.yaral|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Detect|Minimal|Chronicle is able to trigger an alert to ensure multi-factor authentication is enabled for all non-service and administrator accounts.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/main/gcp_cloudaudit/gcp_multifactor_authentication.yaral|
|[T1098.001 - Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)|Detect|Minimal|Chronicle is able to trigger an alert based on changes to Cloud Storage IAM permissions.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/main/gcp_cloudaudit/gcp_gcs_iam_changes.yaral|
|[T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)|Detect|Minimal|Chronicle is able to trigger an alert based off suspicious system processes that could indicate tool transfer attempts using cURL from Windows machines (e.g., C:\\Windows\\System32\\curl.exe).<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/suspicious_curl_usage.yaral|
|[T1106 - Native API](https://attack.mitre.org/techniques/T1106/)|Detect|Minimal|Chronicle is able to trigger an alert for suspicious events related to the API (e.g., "API keys created for a project"). <br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/gcp_cloudaudit/gcp_no_project_api_keys.yaral|
|[T1112 - Modify Registry](https://attack.mitre.org/techniques/T1112/)|Detect|Minimal|Chronicle is able to trigger an alert based on events of interest, such as: "Command-line execution of the Windows Registry Editor".<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/info/command_line_regedit.yaral|
|[T1127 - Trusted Developer Utilities Proxy Execution](https://attack.mitre.org/techniques/T1127/)|Detect|Minimal|Chronicle triggers an alert based on common command line arguments used by adversaries to proxy execution of code through trusted utilities.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/process_creation/suspicious_certutil_command.yaral<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/process_creation/detection_of_winrs_usage.yaral|
|[T1127.001 - MSBuild](https://attack.mitre.org/techniques/T1127/001/)|Detect|Minimal|Chronicle triggers an alert based on common command line arguments for msbuild.exe which is used by adversaries to execute code through a trusted Windows utility.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/mixed_other/security/possible_msbuild_abuse__via_cmdline.yaral|
|[T1132 - Data Encoding](https://attack.mitre.org/techniques/T1132/)|Detect|Minimal|Chronicle is able to trigger an alert based on known indicators used by the adversary, such as data encoding techniques.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/ioc_sigma/windows/powershell_encoded_command__sysmon.yaral<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/process_creation/emotet_process_creation.yaral<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/process_creation/suspicious_powershell_parameter_substring.yaral|
|[T1132.001 - Standard Encoding](https://attack.mitre.org/techniques/T1132/001/)|Detect|Minimal|Chronicle is able to trigger an alert based on known indicators used by the adversary, such as data encoding techniques for commands &/or C&C traffic.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/process_creation/suspicious_powershell_parameter_substring.yaral|
|[T1134 - Access Token Manipulation](https://attack.mitre.org/techniques/T1134/)|Detect|Minimal|Chronicle is able to trigger an alert based on modifications to user access controls.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/cloud_security/sysmon/suspicious_command_line_contains_azure_tokencache_dat_as_argument__via_cmdline.yaral<br/><br/><br/><br/>|
|[T1134.005 - SID-History Injection](https://attack.mitre.org/techniques/T1134/005/)|Detect|Minimal|Chronicle is able to trigger an alert based on successful and failed changes to SID-History. <br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/active_directory_security/windows/addition_of_sid_history_to_active_directory_object.yaral|
|[T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)|Detect|Minimal|Chronicle is able to trigger based on suspicious system event logs, such as newly created local user accounts on Windows machines.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/detects_local_user_creation.yaral|
|[T1136.001 - Local Account](https://attack.mitre.org/techniques/T1136/001/)|Detect|Minimal|Chronicle is able to trigger based on suspicious system event logs, such as newly created local user accounts in Windows AD environments (e.g., event 4720).<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/detects_local_user_creation.yaral|
|[T1137 - Office Application Startup](https://attack.mitre.org/techniques/T1137/)|Detect|Minimal|Chronicle is able to trigger an alert based off suspicious  system processes, for example: command line executable started from Microsoft's Office-based applications.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/sysmon/office_starup_folder_persistance.yaral<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/sysmon/office_applications_suspicious_process_activity.yaral|
|[T1137.001 - Office Template Macros](https://attack.mitre.org/techniques/T1137/001/)|Detect|Minimal|Chronicle is able to trigger an alert based off suspicious  system processes, for example: detects Windows command line executable started from Microsoft's Word or Excel (e.g.., ".*\\WINWORD\.EXE", ".*\\EXCEL\.EXE"). <br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/office_macro_starts_cmd.yaral|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Detect|Minimal|Chronicle triggers an alert based on suspicious behavior, such as exploitation attempts against web servers and/or applications (e.g., F5 BIG-IP CVE 2020-5902).<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/proactive_exploit_detection/big_ip/possible_f5_big_ip_tmui_attack_cve_2020_5902_part_1.yaral<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/proactive_exploit_detection/big_ip/possible_f5_big_ip_tmui_attack_cve_2020_5902_part_2.yaral|
|[T1195 - Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)|Detect|Minimal|Chronicle is able to trigger alerts based on unusual file write events by 3rd party software, specifically SolarWinds executable.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/file_event/unusual_solarwinds_file_creation__via_filewrite.yaral<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/suspicious/unusual_location_svchost_write.yaral|
|[T1195.002 - Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)|Detect|Minimal|Chronicle is able to trigger an alert based on unusual file write events by 3rd party software (e.g., SolarWinds executable ".*\\solarwinds\.businesslayerhost\.exe").<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/file_event/unusual_solarwinds_file_creation__via_filewrite.yaral<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/security/unusual_solarwinds_child_process__via_cmdline.yaral|
|[T1202 - Indirect Command Execution](https://attack.mitre.org/techniques/T1202/)|Detect|Minimal|Chronicle is able to trigger an alert based off suspicious  event IDs that indicate adversary's abuse of Windows system utilities to perform indirect command-line arguments or code execution. For example: malicious usage of bash.exe using Windows sub-system for Linux (e.g., WSL).<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/process_creation/lolbas_wsl_exe__via_cmdline.yaral|
|[T1203 - Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)|Detect|Minimal|Chronicle is able to trigger an alert based on Antivirus notifications that report an exploitation framework (e.g., Metapreter, Metasploit, Powersploit).<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/detect_service_creation_by_metasploit_on_victim_machine.yaral<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/proxy/exploit_framework_user_agent.yaral|
|[T1204 - User Execution](https://attack.mitre.org/techniques/T1204/)|Detect|Minimal|Chronicle is able to trigger an alert based on suspicious user activity (e.g., clicking on a malicious links).<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor. <br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/proxy/microsoft_teams_phishing_email.yaral<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/process_creation/detect_possible_execution_of_phishing_attachment.yaral|
|[T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)|Detect|Minimal|Chronicle is able to trigger an alert based on suspicious system events IDs (e.g., anonymous users changing machine passwords). <br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/proactive_exploit_detection/security/anonymous_user_changed_machine_password.yaral|
|[T1212 - Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212/)|Detect|Minimal|Chronicle triggers alerts based on credential exploit attempts (e.g., read /dev/cmdb/sslvpn_websession file, this file contains login and passwords in (clear-text)).<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/proactive_exploit_detection/webserver/cve_2018_13379_fortigate_ssl_vpn_arbitrary_file_reading.yaral|
|[T1218 - Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)|Detect|Minimal|Chronicle is able to trigger an alert based on attempts to evade defenses, such as: bypass execution of digitally signed binaries.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/process_creation/mavinject_process_injection.yaral|
|[T1218.003 - CMSTP](https://attack.mitre.org/techniques/T1218/003/)|Detect|Minimal|Chronicle is able to trigger an alert when adversaries attempt to abuse Microsoft's Connection Manager Profile Installer to proxy the execution of malicious code.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/sysmon/cmstp_exe_execution_detector__sysmon_behavior.yaral|
|[T1218.005 - Mshta](https://attack.mitre.org/techniques/T1218/005/)|Detect|Minimal|Chronicle is able to trigger an alert based on using MSHTA to call a remote HTML application on Windows (e.g., "mshta.+http").<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/mitre_attack/T1218_005_windows_mshta_remote_usage.yaral<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/ioc_sigma/windows/mshta_spwaned_by_svchost_as_seen_in_lethalhta__sysmon.yaral|
|[T1218.010 - Regsvr32](https://attack.mitre.org/techniques/T1218/010/)|Detect|Minimal|Chronicle is able to trigger an alert based on suspicious behavior in Windows with the use of regsvr32.exe and a possible fileless attack via this executable.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/ole_controls_registered_via_regsvr32_exe__sysmon_behavior.yaral<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/ioc_sigma/process_creation/fileless_attack_via_regsvr32_exe.yaral|
|[T1484 - Domain Policy Modification](https://attack.mitre.org/techniques/T1484/)|Detect|Minimal|Chronicle is able to trigger an alert based off suspicious system events, such as modifications to Windows password policies (event ID 643 or 4739). <br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/detect_windows_password_policy_changes.yaral|
|[T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)|Detect|Minimal|Chronicle is able to trigger an alert based on suspicious events related to ransomware campaigns (e.g., $selection.target.file.md5 = "0c3ef20ede53efbe5eebca50171a589731a17037147102838bdb4a41c33f94e5").<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/ioc_sigma/sysmon/darkgate_cryptocurrency_mining_and_ransomware_campaign__sysmon.yaral<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/ioc_sigma/windows/formbook_malware__sysmon.yaral|
|[T1495 - Firmware Corruption](https://attack.mitre.org/techniques/T1495/)|Detect|Minimal|Chronicle is able to trigger an alert based off suspicious  logs that could indicate tampering with the component's firmware (e.g., detects driver load from a temporary directory).<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/suspicious_driver_load_from_temp.yaral|
|[T1497 - Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497/)|Detect|Minimal|Chronicle is able to trigger an alert based off suspicious system events that may indicate an adversary's attempt to check for the presence of security tools (e.g., Sysinternals).<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/usage_of_sysinternals_tools.yaral|
|[T1505 - Server Software Component](https://attack.mitre.org/techniques/T1505/)|Detect|Minimal|Chronicle is able to trigger alerts based off suspicious events and command line arguments that could indicate an adversary tampering with system components.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/sysmon/detection_of_com_hijacking.yaral|
|[T1505.003 - Web Shell](https://attack.mitre.org/techniques/T1505/003/)|Detect|Minimal|Chronicle triggers an alert based on webshell connections which are used to establish persistent access to a compromised machine [backdoor]. <br/><br/>For example: Detect webshell dropped into a keystore folder on the WebLogic server (`.*/config/keystore/.*\.js.*).<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/proactive_exploit_detection/webserver/oracle_weblogic_exploit.yaral|
|[T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)|Detect|Minimal|Chronicle is able to trigger an alert to notify personnel of GCP resources (e.g., storage buckets) that are publicly accessible to unauthenticated users. <br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/main/gcp_cloudaudit/gcp_gcs_public_accessible.yaral|
|[T1543 - Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)|Detect|Minimal|Chronicle is able to trigger an alert based on creation or modification to system-level processes on Windows machines.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/process_creation/suspicious_process_creation.yaral|
|[T1543.001 - Launch Agent](https://attack.mitre.org/techniques/T1543/001/)|Detect|Minimal|Chronicle is able to trigger an alert based on  property list files scheduled to automatically execute upon startup on macOS platforms (e.g., "`/Library/LaunchAgents/`").<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/mitre_attack/T1543_001_macos_launch_agent.yaral|
|[T1543.003 - Windows Service](https://attack.mitre.org/techniques/T1543/003/)|Detect|Minimal|Chronicle is able to trigger an alert based on system process modifications to existing Windows services which could indicate a malicious payload (e.g., "C:\\Windows\\System32\\sc.exe", "C:\\Windows\\System32\\cmd.exe"). <br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/underminer_exploit_kit_delivers_malware.yaral|
|[T1543.004 - Launch Daemon](https://attack.mitre.org/techniques/T1543/004/)|Detect|Minimal|Chronicle is able to trigger an alert based on  plist files scheduled to automatically execute upon startup on macOS platforms (e.g., "/Library/LaunchDaemons/").<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/mitre_attack/T1543_004_macos_launch_daemon.yaral|
|[T1546 - Event Triggered Execution](https://attack.mitre.org/techniques/T1546/)|Detect|Minimal|Chronicle is able to trigger an alert based on manipulation of default programs.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/mitre_attack/T1546_001_windows_change_default_file_association.yaral|
|[T1546.001 - Change Default File Association](https://attack.mitre.org/techniques/T1546/001/)|Detect|Minimal|Chronicle is able to trigger an alert based on manipulation of default programs used for a given extension found on Windows platforms (e.g., "cmd\.exe /c assoc").<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/mitre_attack/T1546_001_windows_change_default_file_association.yaral|
|[T1546.003 - Windows Management Instrumentation Event Subscription](https://attack.mitre.org/techniques/T1546/003/)|Detect|Minimal|Chronicle is able to trigger an alert based on suspicious events used by adversary's to establish persistence using Windows Management Instrumentation (WMI) command-line events (e.g. "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe").<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/process_creation/wmi_spawning_windows_powershell.yaral|
|[T1546.007 - Netsh Helper DLL](https://attack.mitre.org/techniques/T1546/007/)|Detect|Minimal|Chronicle is able to generate alerts based off suspicious events, for example: execution of arbitrary code triggered by Netsh Helper DLLs (Netshell (Netsh.exe)).<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/possible_system_network_configuration_discovery__sysmon_windows_logs.yaral|
|[T1546.008 - Accessibility Features](https://attack.mitre.org/techniques/T1546/008/)|Detect|Minimal|Chronicle is able to trigger an alert based off suspicious system processes that indicate usage and installation of a backdoor using built-in tools that are accessible from the login screen (e.g., sticky-keys attack).<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/sticky_key_like_backdoor_usage.yaral|
|[T1547 - Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)|Detect|Minimal|Chronicle is able to trigger an alert based on creation or changes of registry keys and run keys found on Windows platforms.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/mitre_attack/T1547_001_windows_registry_run_keys_startup_folder.yaral|
|[T1547.001 - Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)|Detect|Minimal|Chronicle is able to trigger an alert based on creation or changes of registry keys and run keys on Windows platforms (e.g., ""REGISTRY_MODIFICATION", ""REGISTRY_CREATION").<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/mitre_attack/T1547_001_windows_registry_run_keys_startup_folder.yaral<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/sysmon/suspicious_run_key_from_download.yaral|
|[T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)|Detect|Minimal|Chronicle is able to trigger an alert based on Custom Role changes.  <br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/gcp_cloudaudit/gcp_custom_role_changes.yaral|
|[T1548.002 - Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002/)|Detect|Minimal|Chronicle is able to trigger an alert based on system-level processes and other modifications to MacOS platforms (e.g., "FILE_MODIFICATION", "chflags hidden").<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/mitre_attack/T1564_001_macos_hidden_files_and_directories.yaral|
|[T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)|Detect|Minimal|Chronicle detects an attempt to scan registry hives for unsecured passwords.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/ioc_sigma/process_creation/t1214___credentials_in_registry.yaral|
|[T1560 - Archive Collected Data](https://attack.mitre.org/techniques/T1560/)|Detect|Minimal|Chronicle triggers an alert based on adversary indicators of compromise seen when encrypting or compressing data before exfiltration.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/tree/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/process_creation<br/><br/><br/><br/>|
|[T1562.004 - Disable or Modify System Firewall](https://attack.mitre.org/techniques/T1562/004/)|Detect|Minimal|Chronicle is able to trigger an alert based on processes, such as  VPC Network Firewall rule changes. <br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/gcp_cloudaudit/gcp_firewall_rule_changes.yaral|
|[T1564 - Hide Artifacts](https://attack.mitre.org/techniques/T1564/)|Detect|Minimal|Chronicle is able to trigger an alert based on processes, such as hidden artifacts.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/abusing_attrib_exe_to_change_file_attributes.yaral<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/process_creation/hiding_files_with_attrib_exe.yaral|
|[T1564.001 - Hidden Files and Directories](https://attack.mitre.org/techniques/T1564/001/)|Detect|Minimal|Chronicle is able to trigger an alert based on processes, such as manually setting a file to set a file as a system file on Windows (e.g., "attrib\.exe \+s") setting a file to hidden on Windows platforms (e.g., "attrib\.exe \+h"), or on macOS (e.g., "setfile -a V" or  "chflags hidden").<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/process_creation/hiding_files_with_attrib_exe.yaral|
|[T1569 - System Services](https://attack.mitre.org/techniques/T1569/)|Detect|Minimal|Chronicle is able to trigger an alerts based off command-line arguments and suspicious system process that could indicate abuse of system services. <br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/process_creation/suspicious_calculator_usage.yaral<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/abusing_attrib_exe_to_change_file_attributes.yaral|
|[T1569.002 - Service Execution](https://attack.mitre.org/techniques/T1569/002/)|Detect|Minimal|Chronicle is able to trigger an alerts based off command-line arguments and suspicious system process that could indicate abuse of Windows system service to execute malicious commands or code (e.g., "*\\execute\.bat"). <br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/smbexec_py_service_installation.yaral|
|[T1574 - Hijack Execution Flow](https://attack.mitre.org/techniques/T1574/)|Detect|Minimal|Chronicle is able to trigger alerts based on suspicious system processes that could indicate hijacking via malicious payloads.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/antivirus/detects_powershell_attack__via_av_ids.yaral|
|[T1574.007 - Path Interception by PATH Environment Variable](https://attack.mitre.org/techniques/T1574/007/)|Detect|Minimal|Chronicle is able to trigger alerts based on suspicious system processes that could indicate hijacking via malicious payloads (e.g., Windows Unquoted Search Path explotation ""C:\\InventoryWebServer.exe"").<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.|
|[T1578 - Modify Cloud Compute Infrastructure](https://attack.mitre.org/techniques/T1578/)|Detect|Minimal|Chronicle is able to trigger an alert based on changes to the infrastructure (e.g., VPC network changes).<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/gcp_cloudaudit/gcp_vpc_network_changes.yaral|
|[T1584 - Compromise Infrastructure](https://attack.mitre.org/techniques/T1584/)|Detect|Minimal|Chronicle monitors and generates alerts based on modifications to the computing infrastructure.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/tree/783e0e5947774785db1c55041b70176deeca6f46/gcp_cloudaudit<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/gcp_cloudaudit/gcp_dns_modification.yaral<br/><br/>|
|[T1584.002 - DNS Server](https://attack.mitre.org/techniques/T1584/002/)|Detect|Minimal|Chronicle monitors and generates alerts for DNS creation or deletion activity from non-service accounts.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/gcp_cloudaudit/gcp_dns_modification.yaral|
|[T1588 - Obtain Capabilities](https://attack.mitre.org/techniques/T1588/)|Detect|Minimal|Chronicle is able to trigger an alerts based off suspicious system processes, such as binaries in use on Windows machines. For example: PsExec is a free Microsoft tool that can be used to escalate privileges from administrator to SYSTEM with the -s argument, download files over a network share, and remotely create accounts.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/suspicious_psexec_execution.yaral|
|[T1588.002 - Tool](https://attack.mitre.org/techniques/T1588/002/)|Detect|Minimal|Chronicle is able to trigger an alerts based off command-line arguments and suspicious system process that could indicate a tool being used for malicious purposes on Windows machines. For example: PsExec is a free Microsoft tool that can be used to execute a program on another computer.<br/><br/>This technique was scored as minimal based on low or uncertain detection coverage factor.<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/windows/suspicious_psexec_execution.yaral<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/ioc_sigma/sysmon/psexec_detector.yaral<br/><br/>https://github.com/chronicle/detection-rules/blob/783e0e5947774785db1c55041b70176deeca6f46/soc_prime_rules/threat_hunting/process_creation/psexec_service_start.yaral|
  


### Tags
- [Analytics](#tag-analytics)
- [Chronicle](#tag-chronicle)
- [SIEM](#tag-siem)
- [Threat Detection](#tag-threat-detection)
  


### References
- <https://cloud.google.com/chronicle/docs/overview>
- <https://github.com/chronicle/detection-rules>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='cloud-armor'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 11. Cloud Armor



Cloud Armor protects applications by providing Layer 7 filtering and by scrubbing incoming requests for common web attacks or other Layer 7 attributes to potentially block traffic before it reaches load balanced backend services or backend buckets.

- [Mapping File](CloudArmor.yaml) ([YAML](CloudArmor.yaml))
- [Navigator Layer](layers/CloudArmor.json) ([JSON](layers/CloudArmor.json))

### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1018 - Remote System Discovery](https://attack.mitre.org/techniques/T1018/)|Protect|Partial|This control typically filters external network traffic and therefore can be effective for preventing external remote system discovery. Activity originating from inside the trusted network is not mitigated.|
|[T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046/)|Protect|Partial|This control typically filters external network traffic and therefore can be effective for preventing external network service scanning. Network service scanning originating from inside the trusted network is not mitigated.|
|[T1090 - Proxy](https://attack.mitre.org/techniques/T1090/)|Protect|Partial|Traffic to known anonymity networks and C2 infrastructure can be blocked through the use of network allow and block lists. However this can be circumvented by other techniques.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Protect|Significant|Google Cloud Armor security policies protect your application by providing Layer 7 filtering and by scrubbing incoming requests for common web attacks or other Layer 7 attributes. Google Cloud Armor detects malicious requests and drops them at the edge of Google's infrastructure.|
|[T1498 - Network Denial of Service](https://attack.mitre.org/techniques/T1498/)|Protect|Significant|Google Cloud Armor provides always-on DDoS protection against network or protocol-based volumetric DDoS attacks. It allows users to allow/deny traffic at the Google Cloud edge, closest to the source of traffic. This prevents unwelcome traffic from consuming resources.|
|[T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)|Protect|Significant|Google Cloud Armor provides always-on DDoS protection against network or protocol-based volumetric DDoS attacks. It allows users to allow/deny traffic at the Google Cloud edge, closest to the source of traffic. This prevents unwelcome traffic from consuming resources.|
  


### Tags
- [Firewall](#tag-firewall)
- [Network](#tag-network)
  


### References
- <https://cloud.google.com/armor>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='cloud-asset-inventory'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 12. Cloud Asset Inventory



Cloud Asset Inventory provides inventory services based on a time series database. Cloud Asset Inventory allows you to search asset metadata, export all asset metadata at a certain timestamp or export event change history during a specific timeframe, monitor asset changes by subscribing to real-time notifications, and analyze IAM policy to find out who has access to what.


- [Mapping File](CloudAssetInventory.yaml) ([YAML](CloudAssetInventory.yaml))
- [Navigator Layer](layers/CloudAssetInventory.json) ([JSON](layers/CloudAssetInventory.json))

### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Detect|Partial|This control may be able to detect when adversaries use valid cloud accounts to elevate privileges through manipulation of IAM or access policies. This monitoring can be fine tuned to specific assets, policies, and organizations.|
|[T1078.004 - Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)|Detect|Partial|This control may be able to detect when adversaries use valid cloud accounts to elevate privileges through manipulation of IAM or access policies. This monitoring can be fine tuned to specific assets, policies, and organizations.|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Detect|Partial|This control may be able to detect when adversaries use cloud accounts to elevate privileges through manipulation of IAM or access policies. This monitoring can be fine tuned to specific assets, policies, and organizations.|
|[T1098.001 - Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)|Detect|Partial|This control may be able to detect when adversaries use cloud accounts to elevate privileges through manipulation of IAM or access policies for the creation of additional accounts. This monitoring can be fine tuned to specific assets, policies, and organizations.|
  


### Tags
- [Access Management](#tag-access-management)
- [Credentials](#tag-credentials)
  


### References
- <https://cloud.google.com/asset-inventory/docs/overview>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='cloud-cdn'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 13. Cloud CDN



Cloud CDN (Content Delivery Network) uses Google's global edge network to serve content closer to users, which accelerates access to websites and applications.
Cloud CDN works with external HTTP(S) Load Balancing to deliver content to users. The external HTTP(S) load balancer provides the frontend IP addresses and ports that receive requests and the backends that respond to the requests.

- [Mapping File](CloudCDN.yaml) ([YAML](CloudCDN.yaml))
- [Navigator Layer](layers/CloudCDN.json) ([JSON](layers/CloudCDN.json))

### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1498 - Network Denial of Service](https://attack.mitre.org/techniques/T1498/)|Protect|Partial|Cloud CDN acts as a proxy between clients and origin servers. Cloud CDN can distribute requests for cacheable content across multiple points-of-presence (POPs), thereby providing a larger set of locations to absorb a DOS attack.<br/><br/>However, Cloud CDN doesn't provide protection against DOS attacks for uncached content.|
  


### Tags
- [Containers](#tag-containers)
- [Kubernetes](#tag-kubernetes)
- [Logging](#tag-logging)
  


### References
- <https://cloud.google.com/cdn/docs/overview>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='cloud-data-loss-prevention'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 14. Cloud Data Loss Prevention



Cloud DLP provides tools to classify, mask, tokenize, and transform sensitive elements to help you better manage the data that you collect, store, or use for business or analytics.

- [Mapping File](CloudDataLossPrevention.yaml) ([YAML](CloudDataLossPrevention.yaml))
- [Navigator Layer](layers/CloudDataLossPrevention.json) ([JSON](layers/CloudDataLossPrevention.json))

### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)|Protect|Partial|This control is able to scan cloud storage objects for sensitive data and transform that data into a secure or nonsensitive form. It is able to scan for a variety of common sensitive data types, such as API keys, credentials, or credit card numbers. This control is able to be scheduled daily, weekly, etc and can scan new changes to data. This control is able to scan Google Cloud Storage, BigQuery tables, and Datastore.|
  


### Tags
- [Storage](#tag-storage)
  


### References
- <https://cloud.google.com/dlp/docs>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='cloud-hardware-security-module-hsm'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 15. Cloud Hardware Security Module (HSM)



Google Cloud's Hardware Security Module (HSM) is a security feature available under Google Cloud Key Management Service that allows customers to host encryption keys and perform cryptographic operations in a FIPS 140-2 level 3 certified environment. 

- [Mapping File](CloudHSM.yaml) ([YAML](CloudHSM.yaml))
- [Navigator Layer](layers/CloudHSM.json) ([JSON](layers/CloudHSM.json))

### Mapping Comments


This control provides a secure alternative to storing encryption keys in the file system.  


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)|Protect|Partial|Google Cloud's HSM may protect against adversary's attempts to leverage unsecured credentials found on compromised systems. Variations of this technique are difficult to mitigate, so a partial score was granted for this control's medium to high coverage factor.|
|[T1552.001 - Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)|Protect|Partial|Google Cloud's HSM may protect against adversary's attempts to leverage passwords and unsecure credentials found in files on compromised systems.Variations of this technique are difficult to mitigate, so a partial score was granted for this control's medium to high coverage factor.|
|[T1552.004 - Private Keys](https://attack.mitre.org/techniques/T1552/004/)|Protect|Partial|Google Cloud's HSM may protect against adversary's attempts to compromise private key certificate files (e.g., .key, .pgp, .ppk, .p12). Variations of this technique are difficult to mitigate, so a partial score was granted for this control's medium to high coverage factor.|
|[T1553 - Subvert Trust Controls](https://attack.mitre.org/techniques/T1553/)|Protect|Partial|Google Cloud's HSM may protect against adversary's attempts to undermine trusted controls and conduct nefarious activity or execute malicious programs. Variations of this technique are difficult to mitigate, so a partial score was granted for this control's medium to high coverage factor.|
|[T1588 - Obtain Capabilities](https://attack.mitre.org/techniques/T1588/)|Protect|Partial|Google Cloud's HSM may protect against adversary's attempts to obtain capabilities by compromising code signing certificates that will be used to run compromised code and other tampered executables. Variations of this technique are difficult to mitigate, so a partial score was granted for this control's medium to high coverage factor.|
|[T1588.003 - Code Signing Certificates](https://attack.mitre.org/techniques/T1588/003/)|Protect|Partial|Google Cloud's HSM may protect against adversary's attempts to compromise code signing certificates that can used during targeting to run compromised code and other tampered executables. Variations of this technique are difficult to mitigate, so a partial score was granted for this control's medium to high coverage factor.|
|[T1588.004 - Digital Certificates](https://attack.mitre.org/techniques/T1588/004/)|Protect|Partial|Google Cloud's HSM may protect against adversary's attempts to compromise digital certificates that can used to encrypt data-in-transit or tamper with the certificate owner's communications.  Variations of this technique are difficult to mitigate, so a partial score was granted for this control's medium to high coverage factor.|
  


### Tags
- [Data Security](#tag-data-security)
- [Encryption](#tag-encryption)
  


### References
- <https://cloud.google.com/kms/docs/hsm>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='cloud-ids'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 16. Cloud IDS



Cloud IDS is an intrusion detection service that inspects network traffic and triggers alerts to intrusions, malware, spyware, or other cyber-attacks. Cloud IDS' default ruleset is powered by Palo Alto Network's advanced threat detection technologies and the vendor's  latest set of threat signatures (e.g., antivirus, anti-spyware, or vulnerability signatures). Cloud IDS is dependent on Cloud logging feature to collect network telemetry. Further threat detection rule can be crafted to generate alerts based on network traffic (e.g., PCAP, Netflow).

- [Mapping File](CloudIDS.yaml) ([YAML](CloudIDS.yaml))
- [Navigator Layer](layers/CloudIDS.json) ([JSON](layers/CloudIDS.json))

### Mapping Comments


This mapping was scored as significant due to the control’s notable detection accuracy, mappable threat coverage, and time-related factors (e.g., real-time).
The cyber-attacks mapped are considered a subset of the most notable threat detection available for Cloud IDS, but a thorough mapping to all of Palo Alto Network's advanced threat detection technologies wasn't possible due to constant updates, 3rd party vendor's extensive documentation, and new threat signatures.  


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1020 - Automated Exfiltration](https://attack.mitre.org/techniques/T1020/)|Detect|Significant|Often used by adversaries to compromise sensitive data, Palo Alto Network's spyware signatures is able to detect data exfiltration attempts over command and control communications.<br/><br/>Although there are ways an attacker could still exfiltrate data from a compromised system, this technique was scored as significant based on  Palo Alto Network's advanced threat detection technology which constantly updates to detect against the latest known variations of these attacks.|
|[T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)|Detect|Significant|Often used by adversaries to compromise sensitive data, Palo Alto Network's spyware signatures is able to detect data exfiltration attempts and anomalies over known command and control communications.<br/><br/>Although there are ways an attacker could still exfiltrate data from a compromised system, this technique was scored as significant based on  Palo Alto Network's advanced threat detection technology which constantly updates to detect against the latest known variations of these attacks.|
|[T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)|Detect|Significant|Often used by adversaries to compromise sensitive data, Palo Alto Network's spyware signatures is able to detect data exfiltration attempts over command and control communications.<br/><br/>Although there are ways an attacker could still exfiltrate data from a compromised system, this technique was scored as significant based on  Palo Alto Network's advanced threat detection technology which constantly updates to detect against the latest known variations of these attacks.|
|[T1055.002 - Portable Executable Injection](https://attack.mitre.org/techniques/T1055/002/)|Detect|Significant|Often used by adversaries to escalate privileges and automatically run on Windows systems, Palo Alto Network's antivirus signatures is able to detect malware found in portable executables (PE).<br/><br/>Although there are ways an attacker could avoid detection to deliver a malicious PE file, this technique was scored as significant based on Palo Alto Network's advanced threat detection technology which constantly updates to detect against the latest known variations of these attacks.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Detect|Significant|Often used by adversaries to gain access to a system, Palo Alto Network's vulnerability signature is able to detect multiple repetitive occurrences of a condition in a particular time that could indicate a brute force attack (e.g., failed logins).<br/><br/>Although there are ways an attacker could brute force a system while avoiding detection, this technique was scored as significant based on Palo Alto Network's advanced threat detection technology which constantly updates to detect against the latest known variations of these attacks.|
|[T1137 - Office Application Startup](https://attack.mitre.org/techniques/T1137/)|Detect|Significant|Often used by adversaries to establish persistence, Palo Alto Network's antivirus signatures is able to detect malware found in executables and Microsoft Office files (e.g., DOC, DOCX, RTF, XLS, XLSX, PPT, PPTX).<br/><br/>Although there are ways an attacker could modify the signature and deliver a malicious office file, this technique was scored as significant based on  Palo Alto Network's advanced threat detection technology which constantly updates to detect against the latest known variations of these attacks.|
|[T1137.001 - Office Template Macros](https://attack.mitre.org/techniques/T1137/001/)|Detect|Significant|Often used by adversaries to establish persistence, Palo Alto Network's antivirus signatures is able to detect malware found in executables and Microsoft Office templates<br/><br/>Although there are ways an attacker could deliver a malicious template, this technique was scored as significant based on Palo Alto Network's advanced threat detection technology which constantly updates to detect against the latest known variations of these attacks.|
|[T1137.006 - Add-ins](https://attack.mitre.org/techniques/T1137/006/)|Detect|Significant|Often used by adversaries to establish persistence, Palo Alto Network's antivirus signatures is able to detect malware found in executables and Microsoft Office add-ins.<br/><br/>Although there are ways an attacker could deliver a malicious file, this technique was scored as significant based on Palo Alto Network's advanced threat detection technology which constantly updates to detect against the latest known variations of these attacks.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Detect|Significant|Often used by adversaries to take advantage of software weaknesses in web applications, Palo Alto Network's vulnerability signatures are able to detect SQL-injection attacks that attempt to read or modify a system database using common web hacking techniques (e.g., OWASP top 10).<br/><br/>Although there are ways an attacker could leverage web application weaknesses to affect the sensitive data and databases, this technique was scored as significant based on Palo Alto Network's advanced threat detection technology which constantly updates to detect against the latest known variations of these attacks.|
|[T1204.002 - Malicious File](https://attack.mitre.org/techniques/T1204/002/)|Detect|Significant|Often used by adversaries to establish persistence, Palo Alto Network's antivirus signatures is able to detect malware found in portable document formats (PDF).<br/><br/>Although there are ways an attacker could modify the signature and deliver a malicious file, this technique was scored as significant based on  Palo Alto Network's advanced threat detection technology which constantly updates to detect against the latest known variations of these attacks.|
|[T1204.003 - Malicious Image](https://attack.mitre.org/techniques/T1204/003/)|Detect|Significant|Often used by adversaries to establish persistence, Palo Alto Network's antivirus signatures is able to detect download attempts or traffic generated from malicious programs designed to mine cryptocurrency without the user's knowledge.<br/><br/>Although there are ways an attacker could modify the attack to avoid detection, this technique was scored as significant based on  Palo Alto Network's advanced threat detection technology which constantly updates to detect against the latest known variations of these crypto-mining  attacks|
|[T1221 - Template Injection](https://attack.mitre.org/techniques/T1221/)|Detect|Significant|Often used by adversaries to establish persistence, Palo Alto Network's antivirus signatures is able to detect malware found in executables and Microsoft Office file templates (e.g., DOC, DOCX, RTF, XLS, XLSX, PPT, PPTX).<br/><br/>Although there are ways an attacker could modify the known attack signature to avoid detection, this technique was scored as significant based on  Palo Alto Network's advanced threat detection technology which constantly updates to detect against the latest known variations of these attacks.|
|[T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)|Detect|Significant|Often used by adversaries to affect availability and deprive legitimate user access, Palo Alto Network's vulnerability signatures are able to detect denial-of-service (DoS) attacks that attempt to render a target system unavailable by flooding the resources with traffic.<br/><br/>This technique was scored as significant based on  Palo Alto Network's advanced threat detection technology which constantly updates to detect against a variety of denial-of-service attacks.|
|[T1499.003 - Application Exhaustion Flood](https://attack.mitre.org/techniques/T1499/003/)|Detect|Significant|Often used by adversaries to affect availability and deprive legitimate user access, Palo Alto Network's vulnerability signatures are able to detect denial-of-service (DoS) attacks that attempt to crash a target system by flooding it with application traffic.<br/><br/>This was scored as minimal because there are other ways adversaries could<br/><br/>This technique was scored as significant based on  Palo Alto Network's advanced threat detection technology which constantly updates to detect against variations of these cyber-attacks.|
|[T1505.003 - Web Shell](https://attack.mitre.org/techniques/T1505/003/)|Detect|Significant|Often used by adversaries to establish persistence, Palo Alto Network's threat signatures is able to detect programs that use an internet connection to provide remote access to a compromised internal system.<br/><br/>Although there are multiple ways an attacker could establish unauthorized remote access to a compromised system, this technique was scored as significant based on Palo Alto Network's advanced threat detection technology which constantly updates to detect against variations of these cyber-attacks.|
|[T1546.006 - LC_LOAD_DYLIB Addition](https://attack.mitre.org/techniques/T1546/006/)|Detect|Significant|Often used by adversaries to  execute malicious content and establish persistence, Palo Alto Network's antivirus signatures is able to detect malicious content found in Mach object files (Mach-O). These are used by the adversary to load and execute malicious dynamic libraries after the binary is executed.<br/><br/>This technique was scored as significant based on Palo Alto Network's advanced threat detection technology which constantly updates to detect against variations of these cyber-attacks.|
|[T1566.002 - Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)|Detect|Significant|Often used by adversaries to gain access to a system, Palo Alto Network's vulnerability signatures are able to detect when a user attempts to connect to a malicious site with a phishing kit landing page.<br/><br/>Although there are other ways an adversary could attempt a phishing attack, this technique was scored as significant based on Palo Alto Network's advanced threat detection technology which constantly updates to detect against variations of these cyber-attacks.|
|[T1567 - Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)|Detect|Significant|Often used by adversaries to compromise sensitive data, Palo Alto Network's spyware signatures is able to detect data exfiltration attempts over command and control communications (e.g., WebShell).<br/><br/>Although there are ways an attacker could exfiltrate data from a compromised system, this technique was scored as significant based on  Palo Alto Network's advanced threat detection technology which constantly updates to detect against the latest known variations of these attacks.|
|[T1567.002 - Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/)|Detect|Significant|Often used by adversaries to compromise sensitive data, Palo Alto Network's spyware signatures is able to detect data exfiltration attempts over command and control communications (e.g., WebShell).<br/><br/>Although there are multiple ways an attacker could exfiltrate data from a compromised system, this technique was scored as significant based on  Palo Alto Network's advanced threat detection technology which constantly updates to detect against the latest known variations of these attacks.|
  


### Tags
- [Analytics](#tag-analytics)
- [Cloud IDS](#tag-cloud-ids)
- [Intrusion Detection Service (IDS)](#tag-intrusion-detection-service-ids)
- [Palo Alto Network's Threat Signatures](#tag-palo-alto-network-s-threat-signatures)
  


### References
- <https://cloud.google.com/intrusion-detection-system>
- <https://docs.paloaltonetworks.com/pan-os/10-0/pan-os-admin/threat-prevention/threat-signatures>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='cloud-identity'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 17. Cloud Identity



Cloud Identity is an Identity as a Service (IDaaS) and enterprise mobility management (EMM) product. It offers the identity services and endpoint administration that are available in Google Workspace as a stand-alone product. As an end-user, Cloud Identity protects user access with multi-factor authentication. As an administrator, one can use Cloud Identity to manage users, apps, and devices from a central location—the Google Admin console.

- [Mapping File](CloudIdentity.yaml) ([YAML](CloudIdentity.yaml))
- [Navigator Layer](layers/CloudIdentity.json) ([JSON](layers/CloudIdentity.json))

### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1021.004 - SSH](https://attack.mitre.org/techniques/T1021/004/)|Detect|Minimal|This control can be used to detect adversaries that may try to use Valid Accounts to log into remote machines using Secure Shell (SSH).|
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Protect|Partial|This control can be used to mitigate malicious attacks of cloud accounts by implementing multi-factor authentication techniques or password policies.|
|[T1078.002 - Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)|Protect|Partial|This control can be used to mitigate malicious attacks of domain accounts by implementing multi-factor authentication techniques or password policies.|
|[T1078.004 - Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)|Protect|Partial|This control can be used to mitigate malicious attacks of cloud accounts by implementing multi-factor authentication techniques or password policies.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Protect|Significant|This control may mitigate brute force attacks by enforcing multi-factor authentication, enforcing strong password policies, and rotating credentials periodically. These recommendations are IAM best practices but must be explicitly implemented by a cloud administrator.|
|[T1110.001 - Password Guessing](https://attack.mitre.org/techniques/T1110/001/)|Protect|Significant|This control may mitigate brute force attacks by enforcing multi-factor authentication, enforcing strong password policies, and rotating credentials periodically. These recommendations are IAM best practices but must be explicitly implemented by a cloud administrator.|
|[T1110.002 - Password Cracking](https://attack.mitre.org/techniques/T1110/002/)|Protect|Significant|This control may mitigate brute force attacks by enforcing multi-factor authentication, enforcing strong password policies, and rotating credentials periodically. These recommendations are IAM best practices but must be explicitly implemented by a cloud administrator.|
|[T1110.003 - Password Spraying](https://attack.mitre.org/techniques/T1110/003/)|Protect|Significant|This control may mitigate brute force attacks by enforcing multi-factor authentication, enforcing strong password policies, and rotating credentials periodically. These recommendations are IAM best practices but must be explicitly implemented by a cloud administrator.|
|[T1110.004 - Credential Stuffing](https://attack.mitre.org/techniques/T1110/004/)|Protect|Significant|This control may mitigate brute force attacks by enforcing multi-factor authentication, enforcing strong password policies, and rotating credentials periodically. These recommendations are IAM best practices but must be explicitly implemented by a cloud administrator.|
|[T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)|Protect|Minimal||
|[T1213 - Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)|Protect|Partial|MFA and enforcing the principal of least privilege can be used to control adversaries and possibly hinder them from gaining access to a victim network or a private code repository.|
|[T1213.003 - Code Repositories](https://attack.mitre.org/techniques/T1213/003/)|Protect|Partial|MFA and enforcing the principal of least privilege can be used to control adversaries and possibly hinder them from gaining access to a victim network or a private code repository.|
  


### Tags
- [Credentials](#tag-credentials)
- [Identity](#tag-identity)
- [Multi-Factor Authentication](#tag-multi-factor-authentication)
  


### References
- <https://cloud.google.com/identity>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='cloud-key-management'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 18. Cloud Key Management



A cloud-hosted key management service that allows a user manage symmetric and asymmetric cryptographic keys for cloud services the same way one does on-premises. It also manages encryption keys on Google cloud.

- [Mapping File](CloudKeyManagement.yaml) ([YAML](CloudKeyManagement.yaml))
- [Navigator Layer](layers/CloudKeyManagement.json) ([JSON](layers/CloudKeyManagement.json))

### Mapping Comments


Similar to AWS Key Management Service, AWS Cloud HSM, and Azure KeyVault.  


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)|Protect|Partial|Provides protection against attackers stealing application access tokens if they are stored within Cloud KMS.|
|[T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)|Protect|Minimal||
|[T1552.001 - Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)|Protect|Minimal|This control's protection is specific to a minority of this technique's sub-techniques and procedure examples resulting in a Minimal Coverage score and consequently an overall score of Minimal.|
|[T1552.004 - Private Keys](https://attack.mitre.org/techniques/T1552/004/)|Protect|Minimal|This control's protection is specific to a minority of this technique's sub-techniques and procedure examples resulting in a Minimal Coverage score and consequently an overall score of Minimal.|
|[T1552.005 - Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005/)|Protect|Significant|This control's protection is specific to a minority of this technique's sub-techniques and procedure examples resulting in a Minimal Coverage score and consequently an overall score of Minimal.|
|[T1553 - Subvert Trust Controls](https://attack.mitre.org/techniques/T1553/)|Protect|Significant|Protects against trust mechanisms and stealing of code signing certificates|
|[T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)|Protect|Partial|This control manages symmetric and asymmetric cryptographic keys for cloud services and protects against stealing credentials, certificates, keys from the organization.|
|[T1588 - Obtain Capabilities](https://attack.mitre.org/techniques/T1588/)|Protect|Partial|This control manages symmetric and asymmetric cryptographic keys for cloud services and protects against stealing credentials, certificates, keys from the organization.|
|[T1588.003 - Code Signing Certificates](https://attack.mitre.org/techniques/T1588/003/)|Protect|Partial|This control manages symmetric and asymmetric cryptographic keys for cloud services and protects against stealing credentials, certificates, keys from the organization.|
|[T1588.004 - Digital Certificates](https://attack.mitre.org/techniques/T1588/004/)|Protect|Partial|This control manages symmetric and asymmetric cryptographic keys for cloud services and protects against stealing credentials, certificates, keys from the organization.|
  


### Tags
- [Credentials](#tag-credentials)
  


### References
- <https://cloud.google.com/security-key-management>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='cloud-logging'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 19. Cloud Logging



Cloud Logging is a fully managed service that allows user to store, search, analyze, monitor, and alert on logging data and events from Google Cloud and Amazon Web Services.  User can collect logging data from over 150 common application components, on-premises systems, and hybrid cloud systems.

- [Mapping File](CloudLogging.yaml) ([YAML](CloudLogging.yaml))
- [Navigator Layer](layers/CloudLogging.json) ([JSON](layers/CloudLogging.json))

### Mapping Comments


This control is not mappable because it does not provide significant detection of malicious techniques. Some of the other security controls that this control maps to are Azure DNS Analytics, AWS CloudTrail, AWS S3, and AWS Audit Manager. The S3 server access logging feature was not mapped because it was deemed to be a data source that can be used with other detective controls rather than a security control in of itself.  


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
  


### Tags
- [Analytics](#tag-analytics)
- [Logging](#tag-logging)
- [Not Mappable](#tag-not-mappable)
  


### References
- <https://cloud.google.com/logging>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='cloud-nat'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 20. Cloud NAT



Cloud NAT (Network Address Translation) lets certain resources without external IP addresses create outbound connections to the internet.

- [Mapping File](CloudNAT.yaml) ([YAML](CloudNAT.yaml))
- [Navigator Layer](layers/CloudNAT.json) ([JSON](layers/CloudNAT.json))

### Mapping Comments


This control doesn't appear to provide coverage for any ATT&CK Techniques.  


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
  


### Tags
- [Not Mappable](#tag-not-mappable)
  


### References
- <https://cloud.google.com/nat/docs/overview>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='cloud-storage'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 21. Cloud Storage



Google's Cloud Storage is an object storage service that provides customers with replication, availability, access control, and data management. A feature to highlight is that Cloud Storage by default always encrypts data before it's written to disk on the server side. 

- [Mapping File](CloudStorage.yaml) ([YAML](CloudStorage.yaml))
- [Navigator Layer](layers/CloudStorage.json) ([JSON](layers/CloudStorage.json))

### Mapping Comments


There are other methods available for users to secure data with the use of client-side encryption and customer encryption-keys.  


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)|Protect|Significant|The cloud service provider's default encryption setting for data stored and written to disk in the cloud may protect against adversary's attempt to access data from improperly secured cloud storage. This technique was rated as significant due to the high protect coverage factor.|
|[T1565.001 - Stored Data Manipulation](https://attack.mitre.org/techniques/T1565/001/)|Protect|Significant|The cloud service provider's default encryption setting for data stored and written to disk in the cloud may protect against adversary's attempt to manipulate customer data-at-rest. This technique was rated as significant due to the high protect coverage factor.|
|[T1588.003 - Code Signing Certificates](https://attack.mitre.org/techniques/T1588/003/)|Protect|Partial|The cloud service provider's default encryption setting for data stored and written to disk in the cloud may protect against adversary's attempt to manipulate customer data-at-rest. This technique was rated as partial due to the medium to high protect coverage factor against variations of this attack.|
|[T1588.004 - Digital Certificates](https://attack.mitre.org/techniques/T1588/004/)|Protect|Partial|The cloud service provider's default encryption setting for data stored and written to disk in the cloud may protect against adversary's attempt to manipulate customer data-at-rest. This technique was rated as partial due to the medium to high protect coverage factor against variations of this attack.|
  


### Tags
- [Credentials](#tag-credentials)
- [Data Security](#tag-data-security)
- [Encryption](#tag-encryption)
- [Storage](#tag-storage)
  


### References
- <https://cloud.google.com/storage/docs/encryption>
- <https://cloud.google.com/storage>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='cloudvpn'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 22. CloudVPN



Cloud VPN securely connects your peer network to your Virtual Private Cloud (VPC) network through an IPsec VPN connection. Traffic traveling between the two networks is encrypted by one VPN gateway and then decrypted by the other VPN gateway. This action protects your data as it travels over the internet. You can also connect two instances of Cloud VPN to each other.

- [Mapping File](CloudVPN.yaml) ([YAML](CloudVPN.yaml))
- [Navigator Layer](layers/CloudVPN.json) ([JSON](layers/CloudVPN.json))

### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)|Protect|Significant|Cloud VPN enables traffic traveling between the two networks, and it is encrypted by one VPN gateway and then decrypted by the other VPN gateway. This action protects users' data as it travels over the internet. This control may prevent adversaries from sniffing network traffic.|
|[T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)|Protect|Partial|This control provides protections against adversaries who try to access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations.|
|[T1557 - Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)|Protect|Significant|Cloud VPN enables traffic traveling between the two networks, and it is encrypted by one VPN gateway and then decrypted by the other VPN gateway. This action protects users' data as it travels over the internet. This control may prevent adversaries from attempting to position themselves between two or more networks and modify traffic.|
|[T1557.002 - ARP Cache Poisoning](https://attack.mitre.org/techniques/T1557/002/)|Protect|Partial|Cloud VPN enables traffic traveling between the two networks, and it is encrypted by one VPN gateway and then decrypted by the other VPN gateway. This action protects users' data as it travels over the internet. This control may prevent adversaries from attempting to position themselves between two or more networks and modify traffic.|
|[T1565 - Data Manipulation](https://attack.mitre.org/techniques/T1565/)|Protect|Partial|This control provides protection against data from being manipulated by adversaries through target applications by encrypting important information.|
|[T1565.002 - Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002/)|Protect|Partial|This control provides protection against data from being manipulated by adversaries through target applications by encrypting important information. Since this control only provides protection against data in transit, it received a partial score.|
  


### Tags
- [Encryption](#tag-encryption)
- [Network](#tag-network)
  


### References
- <https://cloud.google.com/network-connectivity/docs/vpn/concepts/overview>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='confidential-vm-and-compute-engine'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 23. Confidential VM and Compute Engine



Confidential VM includes inline memory encryption to secure processing of sensitive data in memory. This type of virtual machine that uses AMD Secure Encrypted Virtualization to provide encryption of data during processing (e.g., data-in-use encryption). 

- [Mapping File](ConfidentialVM.yaml) ([YAML](ConfidentialVM.yaml))
- [Navigator Layer](layers/ConfidentialVM.json) ([JSON](layers/ConfidentialVM.json))

### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1565.003 - Runtime Data Manipulation](https://attack.mitre.org/techniques/T1565/003/)|Protect|Significant|Main memory encryption is performed using dedicated hardware within the memory controllers. Each controller includes a high-performance Advanced Encryption Standard (AES) engine. The AES engine encrypts data as it is written to DRAM or shared between sockets, and decrypts it when data is read.|
  


### Tags
- [Encryption](#tag-encryption)
  


### References
- <https://cloud.google.com/compute/confidential-vm/docs/about-cvm#security_and_privacy_features>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='config-connector'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 24. Config Connector



Config Connector is a Kubernetes addon that allows you to manage Google Cloud resources through Kubernetes.
Many cloud-native development teams work with a mix of configuration systems, APIs, and tools to manage their infrastructure. This mix is often difficult to understand, leading to reduced velocity and expensive mistakes. Config Connector provides a method to configure many Google Cloud services and resources using Kubernetes tooling and APIs.

- [Mapping File](ConfigConnector.yaml) ([YAML](ConfigConnector.yaml))
- [Navigator Layer](layers/ConfigConnector.json) ([JSON](layers/ConfigConnector.json))

### Mapping Comments


This control was not mapped as it is not considered a security control but rather an alternative to deploying and managing Google Cloud.  


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
  


### Tags
- [Not Mappable](#tag-not-mappable)
  


### References
- <https://cloud.google.com/config-connector/docs/overview>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='container-registry'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 25. Container Registry



Container Registry is Google Cloud's service that provides a single location for storing and managing container images that support Docker Image Manifest V2 and OCI image formats. Container Analysis is the vulnerability scanning feature in Container Registry that detects software weaknesses from the following sources: Debian, Ubuntu, Alpine, RHEL, CentOS, National Vulnerability Database.

- [Mapping File](ContainerRegistry.yaml) ([YAML](ContainerRegistry.yaml))
- [Navigator Layer](layers/ContainerRegistry.json) ([JSON](layers/ContainerRegistry.json))

### Mapping Comments


Google Cloud's Artifact Registry is the recommended service for managing containers. Container Registry provides a subset of the features found in Artifact Registry and will only receive critical security fixes.  


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Protect|Partial|Container Registry scans the repository for known software vulnerabilities and various system artifacts that could potentially be used to execute adversary-controlled code. Due to the medium threat protection coverage and temporal factor, this control was scored as partial.|
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Protect|Partial|Using Container Analysis, Container Registry scans the repository for vulnerabilities that could potentially be used to escalate privileges, such as default accounts with root permissions in Docker containers. Due to the medium threat protection coverage and scan results being available 48 hours after completion, this control was scored as partial.|
|[T1212 - Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212/)|Detect|Partial|Once this control is deployed, it can detect known vulnerabilities in various OS packages that could be used to escalate privileges and execute adversary-controlled code (e.g., Debian, Ubuntu, Alpine, RHEL, CentOS, National Vulnerability Database). Due to the medium threat detection coverage and temporal factor, the control was scored as partial.|
|[T1525 - Implant Internal Image](https://attack.mitre.org/techniques/T1525/)|Protect|Partial|Using Container Analysis and Vulnerability scanning, this security solution can detect known vulnerabilities in Docker containers. This information can be used to detect images that deviate from the baseline norm, and could indicate a malicious implanted images in the environment. Due to the medium threat detection coverage and temporal factor, the control was scored as partial.|
|[T1610 - Deploy Container](https://attack.mitre.org/techniques/T1610/)|Protect|Partial|Once this control is deployed, it can scan for known vulnerabilities in containers. This information can be used to detect malicious deployed containers used to evade defenses and execute processes in a target environment. Due to the medium threat detection coverage and temporal factor, the control was scored as partial.|
  


### Tags
- [Containers](#tag-containers)
- [Vulnerability Analysis](#tag-vulnerability-analysis)
  


### References
- <https://cloud.google.com/container-registry/docs/container-analysis>
- <https://cloud.google.com/artifact-registry/docs/transition/transition-from-gcr>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='data-catalog'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 26. Data Catalog



Google Cloud's Data Catalog enables customers to quickly query cloud assets, identify sensitive data, and automatically tag it for integration with Google Cloud's Data Loss Prevention (DLP) tool. 

- [Mapping File](DataCatalog.yaml) ([YAML](DataCatalog.yaml))
- [Navigator Layer](layers/DataCatalog.json) ([JSON](layers/DataCatalog.json))

### Mapping Comments


This control was not mapped because the Data Catalog service isn't considered a security control capable of defending against MITRE's ATT&CK techniques, and would require the use of a secondary product, such as DLP, for cyber defense.  


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
  


### Tags
- [Data Catalog](#tag-data-catalog)
- [Not Mappable](#tag-not-mappable)
  


### References
- <https://cloud.google.com/data-catalog>
- <https://cloud.google.com/data-catalog/docs/concepts/overview#how_works>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='deployment-manager'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 27. Deployment Manager



Google Cloud's Deployment Manager is an infrastructure management service that enables users to build predictable cloud resources using static or dynamic configuration file templates. 

- [Mapping File](DeploymentManager.yaml) ([YAML](DeploymentManager.yaml))
- [Navigator Layer](layers/DeploymentManager.json) ([JSON](layers/DeploymentManager.json))

### Mapping Comments


This control was not mapped because Deployment Manager   does not provide a security capability as a stand-alone tool and would require a 3rd party tool (e.g., Terraform) to mitigate denial of service type of cyber-attacks.  


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
  


### Tags
- [Not Mappable](#tag-not-mappable)
  


### References
- <https://cloud.google.com/deployment-manager/docs>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='endpoint-management'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 28. Endpoint Management



With Google endpoint management, you can make your organization's data more secure across your users' mobile devices, desktops, laptops, and other endpoints.

- [Mapping File](EndpointManagement.yaml) ([YAML](EndpointManagement.yaml))
- [Navigator Layer](layers/EndpointManagement.json) ([JSON](layers/EndpointManagement.json))

### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1052.001 - Exfiltration over USB](https://attack.mitre.org/techniques/T1052/001/)|Protect|Partial|This control can prevent exfiltration over USB by disabling USB file transfers on enrolled Android devices.|
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Respond|Partial|This control allows for blocking endpoints that have been compromised from accessing company networks or resources. This control also allows for deletion of any compromised accounts and data from compromised endpoints.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Protect|Partial|This control allows for enforcement of strong password requirements for all mobile devices, desktops, laptops, and other endpoints. This control also allows for use of Google Credential Provider for Windows (GCPW) to utilize Google single sign on for Windows devices that can leverage two-factor authentication and login challenges.|
|[T1567.002 - Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/)|Protect|Partial|This control may restrict which apps can be installed and accessed on enrolled devices, preventing exfiltration of sensitive information from compromised endpoints to cloud storage.|
  


### Tags
- [Identity](#tag-identity)
- [Patch Management](#tag-patch-management)
  


### References
- <https://support.google.com/a/answer/1734200?hl=en>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='firewalls'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 29. Firewalls



Google Cloud VPC Firewalls can allow or deny traffic based on the traffic's protocol, destination ports, sources, and destinations and. VPC firewalls are stateful and exist not only between your instances and other networks, but also between individual instances within the same network. Connections are allowed or denied on a per-instance basis.  Firewall activity can be captured via Firewall rules logging and analyzed with Firewall Insights.

- [Mapping File](Firewalls.yaml) ([YAML](Firewalls.yaml))
- [Navigator Layer](layers/Firewalls.json) ([JSON](layers/Firewalls.json))

### Mapping Comments


Documentation is segmented into 4 sections: VPC Firewall rules, Hierarchical firewall policies, Firewall insights, Firewall rules logging. These sections are listed under Firewall Insights and Virtual Private Cloud (VPC) rather than a generic Firewall documentation page. Its unclear if the data in these sections should correspond to the "Firewalls" control, or the parent control under which its documented.  


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1008 - Fallback Channels](https://attack.mitre.org/techniques/T1008/)|Protect|Partial|Google Cloud Firewalls can allow or deny traffic based on the traffic's protocol, destination ports, sources, and destinations. This functionality can be used to block communication with known fallback channels by filtering based on known bad IP addresses and domains. This mapping is given a score of Partial because it only protects against known fallback channels and not channels yet to be identified.|
|[T1018 - Remote System Discovery](https://attack.mitre.org/techniques/T1018/)|Protect|Partial|Google Cloud Firewalls can allow or deny traffic based on the traffic's protocol, destination ports, sources, and destinations. This functionality can be used to block adversaries from discovering endpoints behind the firewall. This mapping is given a score of Partial because it does not protect against discovering endpoints within the network and behind the firewall.|
|[T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)|Protect|Partial|Google Cloud Firewalls can allow or deny traffic based on the traffic's protocol, destination ports, sources, and destinations. This functionality can be used to only allow remote services from trusted hosts (i.e., only allow remote access traffic from certain hosts). This mapping is given a score of Partial because even though it can restrict remote services traffic from untrusted hosts for most of the sub-techniques (5 of 6), it cannot protect against an adversary using a trusted host that is permitted to use remote services as part of an attack.|
|[T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)|Protect|Partial|Google Cloud Firewalls can allow or deny traffic based on the traffic's protocol, destination ports, sources, and destinations. This functionality can be used to block adversaries from accessing resources from which to exfiltrate data as well as prevent resources from communicating with known-bad IP addresses and domains that might be used to receive exfiltrated data. This mapping is given a score of Partial because the known-bad IP addresses and domains would need to be known in advance.|
|[T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046/)|Protect|Partial|Google Cloud Firewalls can allow or deny traffic based on the traffic's protocol, destination ports, sources, and destinations. This functionality can be used to restrict access to the endpoints within the virtual private cloud and protect against network service scanning. This mapping is given a score of Partial because it only protects against network service scanning attacks that originate from outside the firewall and not from within network protected by the firewall.|
|[T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)|Protect|Partial|Google Cloud Firewalls can allow or deny traffic based on the traffic's protocol, destination ports, sources, and destinations. This functionality can be used to block adversaries from accessing resources from which to exfiltrate data as well as prevent resources from communicating with known-bad IP addresses and domains that might be used to receive exfiltrated data. This mapping is given a score of Partial because the known-bad IP addresses and domains would need to be known in advance and AWS Network Firewall wouldn't have deep packet inspection visibility into encrypted non-C2 protocols.|
|[T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)|Protect|Significant|Google Cloud Firewalls can allow or deny traffic based on the traffic's protocol, destination ports, sources, and destinations. This functionality can be used to block malicious or unwanted traffic leveraging application layer protocols. Given this supports all sub-techniques, the mapping is given a score of Significant.|
|[T1090 - Proxy](https://attack.mitre.org/techniques/T1090/)|Protect|Partial|Google Cloud Firewalls can allow or deny traffic based on the traffic's protocol, destination ports, sources, and destinations. This functionality can be used to block traffic from known bad IP addresses and to known bad domains that serve as proxies for adversaries. This mapping is given a score of partial because it only supports a subset of the sub-techniques (2 of 4) and because it only blocks known bad IP addresses and domains and does not protect against unknown ones.|
|[T1095 - Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1095/)|Protect|Significant|Google Cloud Firewalls can allow or deny traffic based on the traffic's protocol, destination ports, sources, and destinations. This functionality can be used to block malicious or unwanted traffic leveraging non-application layer protocols. Given this, the mapping is given a score of Significant.|
|[T1104 - Multi-Stage Channels](https://attack.mitre.org/techniques/T1104/)|Protect|Partial|Google Cloud Firewalls can allow or deny traffic based on the traffic's protocol, destination ports, sources, and destinations. This functionality can be used to block communication with known command and control channels by filtering based on known bad IP addresses and domains. This mapping is given a score of Partial because it only protects against known channels and not channels yet to be identified.|
|[T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)|Protect|Partial|Google Cloud Firewalls can allow or deny traffic based on the traffic's protocol, destination ports, sources, and destinations. This functionality can be used to only allow certain remote services to be available. Furthermore, it can enforce restrictions such that remote services are only from trusted hosts (i.e., only allow remote access traffic from certain hosts). This mapping is given a score of Partial because while it can limit which external remote services and hosts can be used to access the network, it cannot protect against the misuse of legitimate external remote services (e.g., it cannot protect against an adversary using a trusted host that is permitted to use remote services as part of an attack).|
|[T1187 - Forced Authentication](https://attack.mitre.org/techniques/T1187/)|Protect|Significant|Google Cloud Firewalls can allow or deny traffic based on the traffic's protocol, destination ports, sources, and destinations. This functionality can be used to block SMB and WebDAV traffic from exiting the network which can protect against adversaries from forcing authentication over SMB and WebDAV. This mapping is given a score of Significant because Google Cloud Firewalls can block this traffic or restrict where it can go to.|
|[T1205 - Traffic Signaling](https://attack.mitre.org/techniques/T1205/)|Protect|Partial|Google Cloud Firewalls can allow or deny traffic based on the traffic's protocol, destination ports, sources, and destinations. This functionality can be used to block traffic to unused ports from reaching hosts on the network which may help protect against traffic signaling from external systems. This mapping is given a score of partial because the Google Cloud Firewalls does not do anything to protect against traffic signaling among hosts within the network and behind the firewall.|
|[T1219 - Remote Access Software](https://attack.mitre.org/techniques/T1219/)|Protect|Partial|Google Cloud Firewalls can allow or deny traffic based on the traffic's protocol, destination ports, sources, and destinations. This functionality can be used to only allow remote access software from trusted hosts (i.e., only allow remote access traffic from certain hosts). This mapping is given a score of Partial because even though it can restrict remote access software traffic from untrusted hosts, it cannot protect against an adversary using a trusted host that is permitted to use remote access software as part of an attack.|
|[T1498 - Network Denial of Service](https://attack.mitre.org/techniques/T1498/)|Protect|Minimal|Google Cloud Firewalls can allow or deny traffic based on the traffic's protocol, destination ports, sources, and destinations. This functionality can be used to block the sources of smaller-scale network denial of service attacks. While Google Cloud Firewalls support both sub-techniques (2 of 2), this mapping is given a score of Minimal because often times it is necessary to block the traffic at an Internet Service Provider or Content Provider Network level.|
|[T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)|Protect|Partial|Google Cloud Firewalls can allow or deny traffic based on the traffic's protocol, destination ports, sources, and destinations. This functionality can be used to block adversaries from carrying out denial of service attacks by implementing restrictions on which IP addresses and domains can access the resources (e.g., allow lists) as well as which protocol traffic is permitted. That is, Google Cloud Firewalls could block the source of the denial-of-service attack. This mapping is given a score of Partial because it only supports a subset of the sub-techniques (3 of 4) and because the source of the attack would have to be known before rules could be put in place to protect against it.|
|[T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)|Protect|Partial|Google Cloud Firewalls can allow or deny traffic based on the traffic's protocol, destination ports, sources, and destinations. This functionality can be used to block adversaries from accessing resources such as cloud storage objects by implementing restrictions on which IP addresses and domains can access the resources (e.g., allow lists). However, since cloud storage objects are located outside the virtual private cloud where Google Cloud Firewalls protect, the mapping is only given a score of Partial.|
|[T1542 - Pre-OS Boot](https://attack.mitre.org/techniques/T1542/)|Protect|Minimal|Google Cloud Firewalls can allow or deny traffic based on the traffic's protocol, destination ports, sources, and destinations. This functionality can be used to block traffic over known TFTP ports. This mapping is given a score of Minimal because Google Cloud Firewalls only support a subset of sub-techniques (1 of 5) and don't do anything to protect against TFTP booting among hosts within the network and behind the firewall.|
|[T1571 - Non-Standard Port](https://attack.mitre.org/techniques/T1571/)|Protect|Significant|Google Cloud Firewalls can allow or deny traffic based on the traffic's protocol, destination ports, sources, and destinations. This functionality can be used to restrict which protocols and port numbers are allowed through the firewall and prevent adversaries from using non-standard ports. As a result, this mapping is given a score of Significant.|
|[T1572 - Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)|Protect|Partial|Google Cloud Firewalls can allow or deny traffic based on the traffic's protocol, destination ports, sources, and destinations. This functionality can be used to block traffic from known bad IP addresses and domains which could protect against protocol tunneling by adversaries. This mapping is given a score of partial because it only blocks known bad IP addresses and domains and does not protect against unknown ones.|
|[T1590 - Gather Victim Network Information](https://attack.mitre.org/techniques/T1590/)|Protect|Partial|Google Cloud Firewalls can allow or deny traffic based on the traffic's protocol, destination ports, sources, and destinations. This functionality can be used to restrict access to the endpoints within the virtual private cloud and protect against adversaries gathering information about the network. While this mapping supports most of the sub-techniques (4 of 6), it is only given a score of Partial because it only protects against attempts to gather information via scanning that originate from outside the firewall, and it does not protect against phishing.|
|[T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)|Protect|Partial|Google Cloud Firewalls can allow or deny traffic based on the traffic's protocol, destination ports, sources, and destinations. This functionality can be used to restrict access to the endpoints within the virtual private cloud and protect against active scanning. While this mapping supports both sub-techniques (2 of 2), this mapping is given a score of Partial because it only protects against active scanning attacks that originate from outside the firewall and not from within network protected by the firewall.|
  


### Tags
- [Firewall](#tag-firewall)
- [Logging](#tag-logging)
- [Network](#tag-network)
  


### References
- <https://cloud.google.com/firewalls>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='google-kubernetes-engine'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 30. Google Kubernetes Engine



Google Kubernetes Engine (GKE) provides the ability to secure containers across many layers of the stack, to include container images, container runtime, cluster network, and access to cluster API.

- [Mapping File](GKE.yaml) ([YAML](GKE.yaml))
- [Navigator Layer](layers/GKE.json) ([JSON](layers/GKE.json))

### Mapping Comments


This control provides information about security best practices and policies to apply when deploying Google Kubernetes Engine.  


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1053.007 - Container Orchestration Job](https://attack.mitre.org/techniques/T1053/007/)|Protect|Partial|GKE provides the ability to audit against a set of recommended benchmark [Center for Internet Security (CIS)]. This control may avoid privileged containers and running containers as root.|
|[T1525 - Implant Internal Image](https://attack.mitre.org/techniques/T1525/)|Detect|Partial|After scanning for vulnerabilities, this control may alert personnel of tampered container images that could be running in a Kubernetes cluster.|
|[T1609 - Container Administration Command](https://attack.mitre.org/techniques/T1609/)|Protect|Partial|This control may provide provide information about vulnerabilities within container images, such as the risk from remote management of a deployed container. With the right permissions, an adversary could escalate to remote code execution in the Kubernetes cluster.|
|[T1610 - Deploy Container](https://attack.mitre.org/techniques/T1610/)|Protect|Partial|Kubernetes role-based access control (RBAC), uses granular permissions to control access to resources within projects and objects within Kubernetes clusters.|
|[T1611 - Escape to Host](https://attack.mitre.org/techniques/T1611/)|Detect|Partial|GKE provides the ability to audit against a Center for Internet Security (CIS) Benchmark which is a set of recommendations for configuring Kubernetes to support a strong security posture. The Benchmark is tied to a specific Kubernetes release.|
|[T1611 - Escape to Host](https://attack.mitre.org/techniques/T1611/)|Protect|Partial|By default, GKE nodes use Google's Container-Optimized OS to enhance the security of GKE clusters, including: Read-only filesystem, limited user accounts, and disabled root login.|
|[T1613 - Container and Resource Discovery](https://attack.mitre.org/techniques/T1613/)|Protect|Partial|By default, GKE nodes use Google's Container-Optimized OS to enhance the security of GKE clusters, including: Locked down firewall, read-only filesystem, limited user accounts, and disabled root login.|
  


### Tags
- [Containers](#tag-containers)
- [Kubernetes](#tag-kubernetes)
  


### References
- <https://cloud.google.com/kubernetes-engine/docs/concepts/access-control>
- <https://cloud.google.com/kubernetes-engine/docs/concepts/cis-benchmarks#how_to_audit_benchmarks>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='hybrid-connectivity'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 31. Hybrid Connectivity



Google Cloud Hybrid Connectivity provides several options for connecting to Google Cloud with high-performance, guaranteed uptime, and flexible VPNs.

- [Mapping File](HybridConnectivity.yaml) ([YAML](HybridConnectivity.yaml))
- [Navigator Layer](layers/HybridConnectivity.json) ([JSON](layers/HybridConnectivity.json))

### Mapping Comments


This is not a security control and the controls that fall under the Hybrid Connectivity umbrella have their own mapping files.  


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
  


### Tags
- [Not Mappable](#tag-not-mappable)
- [VPN](#tag-vpn)
  


### References
- <https://cloud.google.com/hybrid-connectivity>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='identity-aware-proxy'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 32. Identity Aware Proxy



Identity Aware Proxy (IAP) includes a number of features that can be used to protect access to Google Cloud hosted resources and applications hosted on Google. IAP lets you establish a central authorization layer for applications accessed by HTTPS, so you can use an application-level access control model instead of relying on network-level firewalls.

- [Mapping File](IdentityAwareProxy.yaml) ([YAML](IdentityAwareProxy.yaml))
- [Navigator Layer](layers/IdentityAwareProxy.json) ([JSON](layers/IdentityAwareProxy.json))

### Mapping Comments


This mapping was scored as Partial due the control's low to medium threat protection fidelity from specific (sub-)techniques found in MITRE’s ATT&CK framework.  


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Protect|Partial|IAP applies the relevant IAM policy to check if the user is authorized to access the requested resource. If the user has the IAP-secured Web App User role on the Cloud console project where the resource exists, they're authorized to access the application. This control can mitigate against adversaries that try to obtain credentials of accounts, including cloud accounts.|
|[T1078.004 - Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)|Protect|Partial|Protects access to applications hosted within cloud and other premises.|
|[T1098.001 - Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)|Detect|Minimal|Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access to victim accounts and instances within the environment. IAP lets you enforce access control policies for applications and resources. This control may help mitigate against adversaries gaining access through cloud account by the configuration of access controls and firewalls, allowing limited access to systems.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Protect|Partial|When an application or resource is protected by IAP, it can only be accessed through the proxy by principals, also known as users, who have the correct Identity and Access Management (IAM) role. IAP secures authentication and authorization of all requests to App Engine, Cloud Load Balancing (HTTPS), or internal HTTP load balancing.<br/><br/>With adversaries that may try to attempt malicious activity via applications, the application Firewalls may be used to limit exposure of applications to prevent exploit traffic from reaching the application.|
|[T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)|Detect|Partial|Control can detect potentially malicious applications|
|[T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)|Protect|Minimal|This control may mitigate application access token theft if the application is configured to retrieve temporary security credentials using an IAM role.|
|[T1550.001 - Application Access Token](https://attack.mitre.org/techniques/T1550/001/)|Protect|Minimal|This control may mitigate or prevent stolen application access tokens from occurring.|
  


### Tags
- [Credentials](#tag-credentials)
- [Identity](#tag-identity)
  


### References
- <https://cloud.google.com/iap>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='identity-and-access-management'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 33. Identity and Access Management



Identity and Access Management (IAM) gives administrators fine-grained access control and visibility for centrally managing enterprise cloud resources. It gives more granular access to specific Google Cloud resources and prevents unwanted access to other resources. IAM lets users adopt the security principle of least privilege, so you grant only the necessary access to your resources.

- [Mapping File](IdentyAccessManagement.yaml) ([YAML](IdentyAccessManagement.yaml))
- [Navigator Layer](layers/IdentyAccessManagement.json) ([JSON](layers/IdentyAccessManagement.json))

### Mapping Comments


Similar to Azure AD for Managed Identities, Azure Role Based Access Control, AWS Identity and Access Management.  


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1069 - Permission Groups Discovery](https://attack.mitre.org/techniques/T1069/)|Protect|Minimal|Group permissions and settings are inherited using the IAM roles that are specifically granted to that group by admins. This control provides protection of possible adversaries that may determine which user accounts and groups memberships are available in cloud accounts. Received a score of Minimal because it only covers one of the sub-techniques.|
|[T1069.003 - Cloud Groups](https://attack.mitre.org/techniques/T1069/003/)|Protect|Minimal|Group permissions and settings are inherited using the IAM roles that are specifically granted to that group by admins. This control provides protection of possible adversaries that may determine which user accounts and groups memberships are available in cloud accounts. Received a score of Minimal because it only covers one of the sub-techniques.|
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Detect|Partial||
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Protect|Partial|This control may mitigate the impact of compromised valid accounts by enabling fine-grained access policies and implementing least-privilege policies. MFA can provide protection against an adversary that obtains valid credentials by requiring the adversary to complete an additional authentication process before access is permitted.|
|[T1078.004 - Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)|Protect|Partial|This control protects against malicious use of cloud accounts and gaining access to them.   This control may mitigate the impact of compromised valid accounts by enabling fine-grained access policies and implementing least-privilege policies. MFA can provide protection against an adversary that obtains valid credentials by requiring the adversary to complete an additional authentication process before access is permitted.|
|[T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)|Protect|Minimal|This control protects against adversaries gaining access to accounts within a specific environment or determining which accounts exists to follow on with malicious behavior. The usage of GCP IAM enables admins to grant access to cloud resources at fine-grained levels, possibly preventing adversaries of malicious use of cloud accounts and gaining access to them.  This control receives a minimal score since it only covers one of the few sub-techniques.|
|[T1087.004 - Cloud Account](https://attack.mitre.org/techniques/T1087/004/)|Protect|Partial|This control can be used to implement the least-privilege principle for account management and thereby limit the accounts that can be used for account discovery. This control receives a minimal score since it only covers one of the few sub-techniques.|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Protect|Partial|Privileged roles and permissions can be granted to entire groups of users by default, and admins can control unwanted access by utilizing machine learning to recommend smart access control permissions within an organization. This control can  help mitigate adversaries from gaining access to unwanted account.|
|[T1098.001 - Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)|Protect|Partial|Privileged roles and permissions can be granted to entire groups of users by default, and admins can control unwanted access by utilizing machine learning to recommend smart access control permissions within an organization. This control can  help mitigate adversaries from gaining access to unwanted account.|
|[T1613 - Container and Resource Discovery](https://attack.mitre.org/techniques/T1613/)|Protect|Minimal|GCP Identity and Access Management allows admins to control access to Container Registry hosts with Cloud Storage permissions. Specific accounts can be assigned roles and Container Registry uses Cloud Storage buckets as the underlying storage for container images. This control can help mitigate  against adversaries that may attempt to discover resources including images and containers by controlling access to  images by granting permissions to the bucket for a registry.|
  


### Tags
- [Access Management](#tag-access-management)
- [Credentials](#tag-credentials)
- [Identity](#tag-identity)
- [Multi-Factor Authentication](#tag-multi-factor-authentication)
- [Role Based Access Control](#tag-role-based-access-control)
  


### References
- <https://cloud.google.com/iam>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='identityplatform'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 34. IdentityPlatform



Identity Platform is a customer identity and access management (CIAM) platform that helps organizations add identity and access management functionality to their applications, protect user accounts, and scale with confidence on Google Cloud.

- [Mapping File](IdentityPlatform.yaml) ([YAML](IdentityPlatform.yaml))
- [Navigator Layer](layers/IdentityPlatform.json) ([JSON](layers/IdentityPlatform.json))

### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Protect|Partial|Identity Platform lets you add Google-grade authentication to your apps and services, making it easier to secure user accounts and securely managing credentials. MFA can provide protection against an adversary that obtains valid credentials by requiring the adversary to complete an additional authentication process before access is permitted.|
|[T1078.003 - Local Accounts](https://attack.mitre.org/techniques/T1078/003/)|Protect|Partial|Identity Platform lets you add Google-grade authentication to your apps and services, making it easier to secure user accounts and securely managing credentials. MFA can provide protection against an adversary that obtains valid credentials by requiring the adversary to complete an additional authentication process before access is permitted.|
|[T1078.004 - Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)|Protect|Partial|Identity Platform lets you add Google-grade authentication to your apps and services, making it easier to secure user accounts and securely managing credentials. MFA can provide protection against an adversary that obtains valid credentials by requiring the adversary to complete an additional authentication process before access is permitted.|
|[T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)|Protect|Partial|Identity Platform is a customer identity and access management (CIAM) platform that helps organizations add identity and access management functionality to their applications, protect user accounts, and scale with confidence on Google Cloud. With this, permissions are limited to discover cloud accounts in accordance with least privilege and adversaries may be prevented from getting access to a listing of domain accounts.|
|[T1087.002 - Domain Account](https://attack.mitre.org/techniques/T1087/002/)|Protect|Partial|Identity Platform is a customer identity and access management (CIAM) platform that helps organizations add identity and access management functionality to their applications, protect user accounts, and scale with confidence on Google Cloud. With this, permissions are limited to discover cloud accounts in accordance with least privilege and adversaries may be prevented from getting access to a listing of domain accounts.|
|[T1087.004 - Cloud Account](https://attack.mitre.org/techniques/T1087/004/)|Protect|Partial|Identity Platform is a customer identity and access management (CIAM) platform that helps organizations add identity and access management functionality to their applications, protect user accounts, and scale with confidence on Google Cloud. With this, permissions are limited to discover cloud accounts in accordance with least privilege and adversaries may be prevented from getting access to a listing of cloud accounts.|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Protect|Significant|Identity Platform can help protect your app's users and prevent account takeovers by offering multi-factor authentication (MFA) and integrating with Google's intelligence for account protection. This will help mitigate adversaries from gaining access to permission levels.|
|[T1098.001 - Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)|Protect|Significant|Identity Platform can help protect your app's users and prevent account takeovers by offering multi-factor authentication (MFA) and integrating with Google's intelligence for account protection. This will help mitigate adversaries from gaining access to permission levels.|
|[T1098.002 - Exchange Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002/)|Protect|Significant|Identity Platform can help protect your app's users and prevent account takeovers by offering multi-factor authentication (MFA) and integrating with Google's intelligence for account protection. This will help mitigate adversaries from gaining access to permission levels.|
|[T1098.003 - Add Office 365 Global Administrator Role](https://attack.mitre.org/techniques/T1098/003/)|Protect|Significant|Identity Platform can help protect your app's users and prevent account takeovers by offering multi-factor authentication (MFA) and integrating with Google's intelligence for account protection. This will help mitigate adversaries from gaining access to permission levels.|
|[T1098.004 - SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004/)|Protect|Significant|Identity Platform can help protect your app's users and prevent account takeovers by offering multi-factor authentication (MFA) and integrating with Google's intelligence for account protection. This will help mitigate adversaries from gaining access to permission levels via files.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Protect|Significant|Multi-factor authentication (MFA) methods, such as SMS, can also be used to help protect user accounts from phishing attacks. MFA provides significant protection against password compromises, requiring the adversary to complete an additional authentication method before their access is permitted.|
|[T1110.001 - Password Guessing](https://attack.mitre.org/techniques/T1110/001/)|Protect|Significant|Multi-factor authentication (MFA) methods, such as SMS, can also be used to help protect user accounts from phishing attacks. MFA provides significant protection against password compromises, requiring the adversary to complete an additional authentication method before their access is permitted.|
|[T1110.002 - Password Cracking](https://attack.mitre.org/techniques/T1110/002/)|Protect|Significant|Multi-factor authentication (MFA) methods, such as SMS, can also be used to help protect user accounts from phishing attacks. MFA provides significant protection against password compromises, requiring the adversary to complete an additional authentication method before their access is permitted.|
|[T1110.003 - Password Spraying](https://attack.mitre.org/techniques/T1110/003/)|Protect|Significant|Multi-factor authentication (MFA) methods, such as SMS, can also be used to help protect user accounts from phishing attacks. MFA provides significant protection against password compromises, requiring the adversary to complete an additional authentication method before their access is permitted.|
|[T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)|Protect|Significant|Identity Platform multi-tenancy uses tenants to create unique silos of users and configurations within a single Identity Platform project. It provides provides secure, easy-to-use authentication if you're building a service on Google Cloud, on your own backend or on another platform; thereby, helping to mitigate adversaries from gaining access to systems.|
|[T1136.001 - Local Account](https://attack.mitre.org/techniques/T1136/001/)|Protect|Significant|Identity Platform multi-tenancy uses tenants to create unique silos of users and configurations within a single Identity Platform project. It provides provides secure, easy-to-use authentication if you're building a service on Google Cloud, on your own backend or on another platform; thereby, helping to mitigate adversaries from gaining access to systems and accounts.|
|[T1136.002 - Domain Account](https://attack.mitre.org/techniques/T1136/002/)|Protect|Significant|Identity Platform multi-tenancy uses tenants to create unique silos of users and configurations within a single Identity Platform project. It provides provides secure, easy-to-use authentication if you're building a service on Google Cloud, on your own backend or on another platform; thereby, helping to mitigate adversaries from gaining access to systems.|
|[T1136.003 - Cloud Account](https://attack.mitre.org/techniques/T1136/003/)|Protect|Significant|Identity Platform multi-tenancy uses tenants to create unique silos of users and configurations within a single Identity Platform project. It provides provides secure, easy-to-use authentication if you're building a service on Google Cloud, on your own backend or on another platform; thereby, helping to mitigate adversaries from gaining access to systems.|
|[T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)|Protect|Minimal|Identity Platform integrates tightly with Google Cloud services, and it leverages industry standards like OAuth 2.0 and OpenID Connect, so it can be easily integrated with your custom backend. This control may mitigate application access token theft if the application is configured to retrieve temporary security credentials using an IAM role.|
|[T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)|Protect|Minimal|This control may mitigate application access token theft if the application is  configured to retrieve temporary security credentials using an IAM role.|
|[T1550.001 - Application Access Token](https://attack.mitre.org/techniques/T1550/001/)|Protect|Minimal|This control may mitigate application access token theft if the application is  configured to retrieve temporary security credentials using an IAM role.|
|[T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)|Protect|Minimal|Identity Platform lets you add Google-grade authentication to your apps and services, making it easier to secure user accounts and securely managing credentials. MFA can be used to restrict access to cloud resources and APIs and provide protection against an adversaries that try to access  user credentials.|
|[T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/)|Protect|Minimal|Identity Platform provides Admin APIs to manage  users and authentication tokens. To prevent unwanted access to your users and tokens through these APIs, Identity Platform leverages IAM to manage permission to specific Identity Platform APIs. This control will ensure proper process and file permissions are in place to prevent adversaries from disabling or interfering with security/logging services.|
|[T1562.008 - Disable Cloud Logs](https://attack.mitre.org/techniques/T1562/008/)|Protect|Minimal|Identity Platform provides Admin APIs to manage  users and authentication tokens. To prevent unwanted access to your users and tokens through these APIs, Identity Platform leverages IAM to manage permission to specific Identity Platform APIs. This control will ensure proper process and file permissions are in place to prevent adversaries from disabling or interfering with security/logging services.|
|[T1580 - Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/)|Protect|Partial|Identity Platform is a customer identity and access management (CIAM) platform that helps organizations add identity and access management functionality to their applications, protect user accounts, and scale with confidence on Google Cloud. With this, permissions are limited to discover cloud accounts in accordance with least privilege.|
  


### Tags
- [Access Management](#tag-access-management)
- [Credentials](#tag-credentials)
- [Identity](#tag-identity)
- [Multi-Factor Authentication](#tag-multi-factor-authentication)
- [Passwords](#tag-passwords)
  


### References
- <https://cloud.google.com/identity-platform/docs/concepts>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='packet-mirroring'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 35. Packet Mirroring



This control is a feature found under Virtual Private Cloud tool that provides users with the ability to duplicate traffic to enable cyber forensic investigations.

- [Mapping File](PacketMirroring.yaml) ([YAML](PacketMirroring.yaml))
- [Navigator Layer](layers/PacketMirroring.json) ([JSON](layers/PacketMirroring.json))

### Mapping Comments


This tool provides the functional ability to clone traffic, but is not considered a stand-alone security control as it requires a secondary security tool (e.g., IDS/IPS) to enable cyber defense and digital forensics.  


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
  


### Tags
- [Not Mappable](#tag-not-mappable)
  


### References
- <https://cloud.google.com/vpc/docs/packet-mirroring>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='policy-intelligence'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 36. Policy Intelligence



Policy Intelligence helps enterprises understand and manage their policies to reduce their risk. By utilizing machine learning and analytics, policy intelligence provides more visibility and automation and  customers can increase their workload.

- [Mapping File](PolicyIntelligence.yaml) ([YAML](PolicyIntelligence.yaml))
- [Navigator Layer](layers/PolicyIntelligence.json) ([JSON](layers/PolicyIntelligence.json))

### Mapping Comments


Similar to Azure Role based access control and Azure policy   


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Protect|Partial|IAM Recommender helps admins remove unwanted access to GCP resources by using machine learning to make smart access control recommendations. With Recommender, security teams can automatically detect overly permissive access and rightsize them based on similar users in the organization and their access patterns. This control may mitigate adversaries that try to perform privilege escalation via permission levels and software exploitation.|
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Protect|Partial|Adversaries may obtain and abuse credentials of a cloud account by gaining access through means of Initial Access, Persistence, Privilege Escalation, or Defense Evasion. IAM Recommender helps enforce least privilege principals to ensure that permission levels are properly managed.|
|[T1078.004 - Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)|Detect|Minimal||
|[T1078.004 - Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)|Protect|Partial|Adversaries may obtain and abuse credentials of a cloud account by gaining access through means of Initial Access, Persistence, Privilege Escalation, or Defense Evasion. IAM Recommender helps enforce least privilege principals to ensure that permission levels are properly managed.|
|[T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)|Protect|Partial|This control can be used to limit permissions to discover user accounts in accordance with least privilege principles and thereby limits the accounts that can be used for account discovery.|
|[T1087.004 - Cloud Account](https://attack.mitre.org/techniques/T1087/004/)|Protect|Partial|This control can be used to limit permissions to discover cloud accounts in accordance with least privilege principles and thereby limits the accounts that can be used for account discovery.|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Protect|Partial|Utilization and enforcement of MFA for user accounts to ensure that IAM policies are implemented properly shall mitigate adversaries so that they may not gain access to user accounts. Enforce the principle of least privilege by ensuring that principals have only the permissions that they actually need.|
|[T1098.001 - Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)|Protect|Partial|Utilization and enforcement of MFA for user accounts to ensure that IAM policies are implemented properly shall mitigate adversaries so that they may not gain access to user accounts. Enforce the principle of least privilege by ensuring that principals have only the permissions that they actually need.|
|[T1212 - Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212/)|Protect|Partial|IAM Recommender helps admins remove unwanted access to GCP resources by using machine learning to make smart access control recommendations. With Recommender, security teams can automatically detect overly permissive access and rightsize them based on similar users in the organization and their access patterns. This control may mitigate adversaries that try to perform privilege escalation via permission levels and software exploitation.|
|[T1222 - File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222/)|Protect|Partial|Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files. Enforcing the principle of least privilege through IAM Recommender role recommendations help admins identify and remove excess permissions from users' principals, improving their resources' security configurations.|
|[T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)|Detect|Minimal|Adversaries may attempt to implant cloud or container images with malicious code to gain access to an environment. The IAM audit logs can be used to receive data access and activity logs who has accessed to certain resources.|
|[T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)|Protect|Partial|Recommender generates policy insights by comparing the permissions that each principal used during the past 90 days with the total permissions the principal has. This can be used to limit the permissions associated with creating and modifying platform images or containers that adversaries may try to access.|
|[T1538 - Cloud Service Dashboard](https://attack.mitre.org/techniques/T1538/)|Protect|Partial|This control may limit the number of users that have privileges to discover cloud infrastructure and may limit the discovery value of the dashboard in the event of a compromised account.|
|[T1548.002 - Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002/)|Protect|Partial|Adversaries may bypass UAC mechanisms to elevate process privileges. This control can be used to help enforce least privilege principals to ensure that permission levels are properly managed. Along with this, Policy Analyzer lets users know what principals have access to resources based on its corresponding IAM allow policies.|
|[T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/)|Protect|Partial|Adversaries that try to disable cloud logging capabilities have the advantage to limit the amount of the data that can be collected and can possibly control not being detected. This control may be used to ensure that permissions are in place to prevent adversaries from disabling or interfering with security/logging services.|
|[T1562.008 - Disable Cloud Logs](https://attack.mitre.org/techniques/T1562/008/)|Detect|Minimal|Adversaries that try to disable cloud logging capabilities have the advantage to limit the amount of the data that can be collected and can possibly control not being detected. This control may be used to routinely check role account permissions in IAM audit logs.|
|[T1578 - Modify Cloud Compute Infrastructure](https://attack.mitre.org/techniques/T1578/)|Protect|Partial|IAM Recommender helps admins remove unwanted access to GCP resources by using machine learning to make smart access control recommendations. With Recommender, security teams can automatically detect overly permissive access and rightsize them based on similar users in the organization and their access patterns. This control may mitigate adversaries that try to gain access to permissions from modifying infrastructure components.|
|[T1580 - Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/)|Protect|Minimal|IAM Recommender helps admins remove unwanted access to GCP resources by using machine learning to make smart access control recommendations. With Recommender, security teams can automatically detect overly permissive access and rightsize them based on similar users in the organization and their access patterns. This control may mitigate adversaries that try to enumerate users access keys through VM or snapshots.|
  


### Tags
- [Access Management](#tag-access-management)
- [Credentials](#tag-credentials)
- [Identity](#tag-identity)
- [Role Based Access Control](#tag-role-based-access-control)
  


### References
- <https://cloud.google.com/policy-intelligence>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='recaptcha-enterprise'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 37. ReCAPTCHA Enterprise



With reCAPTCHA Enterprise, you can protect your site from spam and abuse, and detect other types of fraudulent activities on the sites, such as credential stuffing, account takeover (ATO), and automated account creation. reCAPTCHA Enterprise offers enhanced detection with more granular scores, reason codes for risky events, mobile app SDKs, password breach/leak detection, Multi-factor authentication (MFA), and the ability to tune your site-specific model to protect enterprise businesses.

- [Mapping File](ReCAPTCHAEnterprise.yaml) ([YAML](ReCAPTCHAEnterprise.yaml))
- [Navigator Layer](layers/ReCAPTCHAEnterprise.json) ([JSON](layers/ReCAPTCHAEnterprise.json))

### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1078.004 - Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)|Protect|Partial|ReCAPTCHA Enterprise allows users to configure Multifactor Authentication (MFA) to verify user's identity by sending a verification code by email or SMS (known as an MFA challenge). When ReCAPTCHA Enterprise assesses that user activity to exceeds a predetermined threshold (by the developer), it can trigger an MFA challenge to verify the user. This increases the likelihood that a compromised account will be prevented from impacting the system.<br/><br/>Since ReCAPTCHA Enterprise does not require a MFA challenge for all user activity, it has been given a rating of Partial.<br/>|
|[T1110.004 - Credential Stuffing](https://attack.mitre.org/techniques/T1110/004/)|Detect|Significant|Password Checkup extension for Chrome displays a warning whenever a user signs in to a site using one of over 4 billion usernames and passwords that Google knows to be unsafe due to a third-party data breach. With reCAPTCHA Enterprise, you can identify credential stuffing attacks by utilizing Password Checkup to detect password leaks and breached credentials. Developers can factor this information into their score calculation for score-based site keys to help identify suspicious activity and take appropriate action.<br/>|
|[T1136.003 - Cloud Account](https://attack.mitre.org/techniques/T1136/003/)|Protect|Partial|ReCAPTCHA Enterprise can implement a number of mitigations to prevent the automated creation of multiple accounts such as adding checkbox challenges on pages where end users need to enter their credentials and assessing user activity for potential misuses on all pages where accounts are created.<br/><br/>Since this control doesn't prevent the manual creation of accounts, it has been given a rating of Partial.<br/>|
  


### Tags
- [Identity](#tag-identity)
- [Multi-Factor Authentication](#tag-multi-factor-authentication)
  


### References
- <https://cloud.google.com/recaptcha-enterprise>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='resourcemanager'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 38. ResourceManager



Google Cloud Platform provides resource containers such as organizations, folders, and projects that allow users to group and hierarchically organize other GCP resources. This hierarchical organization lets users easily manage common aspects of your resources such as access control and configuration settings. Resource Manager enables users to programmatically manage these resource containers.

- [Mapping File](ResourceManager.yaml) ([YAML](ResourceManager.yaml))
- [Navigator Layer](layers/ResourceManager.json) ([JSON](layers/ResourceManager.json))

### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Protect|Minimal|Adversaries may attempt to obtain credentials of existing account through privilege escalation or defense evasion. IAM audit logging in GCP can be used to determine roles and permissions, along with routinely checking user permissions to ensure only the expected users have the ability to list IAM identities or otherwise discover cloud accounts.|
|[T1078.004 - Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)|Protect|Minimal|Adversaries may attempt to obtain credentials of existing account through privilege escalation or defense evasion. IAM audit logging in GCP can be used to determine roles and permissions, along with routinely checking user permissions to ensure only the expected users have the ability to list IAM identities or otherwise discover cloud accounts.|
|[T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)|Detect|Minimal|Adversaries may attempt to get a listing of cloud accounts that are created and configured by an organization or admin. IAM audit logging in GCP can be used to determine roles and permissions, along with routinely checking user permissions to ensure only the expected users have the ability to list IAM identities or otherwise discover cloud accounts.|
|[T1087.004 - Cloud Account](https://attack.mitre.org/techniques/T1087/004/)|Detect|Minimal|Adversaries may attempt to get a listing of cloud accounts that are created and configured by an organization or admin. IAM audit logging in GCP can be used to determine roles and permissions, along with routinely checking user permissions to ensure only the expected users have the ability to list IAM identities or otherwise discover cloud accounts.|
|[T1087.004 - Cloud Account](https://attack.mitre.org/techniques/T1087/004/)|Protect|Minimal|This control may mitigate adversaries that attempt to get a listing of cloud accounts, such as use of calls to cloud APIs that perform account discovery.|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Protect|Minimal|GCP offers Identity and Access Management (IAM), which lets admins give more granular access to specific Google Cloud resources and prevents unwanted access to other resources. This allows configuration of access controls and firewalls to limit access to critical systems and domain controllers.|
|[T1098.001 - Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)|Protect|Minimal|GCP offers Identity and Access Management (IAM), which lets admins give more granular access to specific Google Cloud resources and prevents unwanted access to other resources. This allows configuration of access controls and firewalls to limit access to critical systems and domain controllers.|
|[T1552.007 - Container API](https://attack.mitre.org/techniques/T1552/007/)|Protect|Minimal|To control access to resources, GCP requires that accounts making API requests have appropriate IAM roles. IAM roles include permissions that allow users to perform specific actions on Google Cloud resources. This control may mitigate adversaries that gather credentials via APIs within a containers environment. Since this covers only one of the sub-techniques, it is given a Minimal scoring.|
|[T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/)|Protect|Partial|An adversary may disable cloud logging capabilities and integrations to limit what data is collected on their activities and avoid detection. GCP allows configuration of account policies to enable logging and IAM permissions and roles to determine your ability to access audit logs data in Google Cloud resources.|
|[T1562.001 - Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)|Protect|Partial|This control adopts the security principle of least privilege, which grants necessary access to user's resources when justified and needed. This control manages access control and ensures proper user permissions are in place to prevent adversaries that try to modify and/or disable security tools.|
|[T1562.002 - Disable Windows Event Logging](https://attack.mitre.org/techniques/T1562/002/)|Protect|Partial|This control adopts the security principle of least privilege, which grants necessary access to user's resources when justified and needed. This control manages access control and ensures proper user permissions are in place to prevent adversaries that try to interfere with logging.<br/>|
|[T1562.007 - Disable or Modify Cloud Firewall](https://attack.mitre.org/techniques/T1562/007/)|Detect|Partial|An adversary may disable cloud logging capabilities and integrations to limit what data is collected on their activities and avoid detection. GCP allows configuration of account policies to enable logging and IAM permissions and roles to determine your ability to access audit logs data in Google Cloud resources.|
|[T1562.007 - Disable or Modify Cloud Firewall](https://attack.mitre.org/techniques/T1562/007/)|Protect|Partial|This control adopts the security principle of least privilege, which grants necessary access to user's resources when justified and needed. This control manages access control and ensures proper user permissions are in place to prevent adversaries that try to modify and/or disable firewall.<br/><br/>|
|[T1562.008 - Disable Cloud Logs](https://attack.mitre.org/techniques/T1562/008/)|Protect|Partial|This control adopts the security principle of least privilege, which grants necessary access to user's resources when justified and needed. This control manages access control and ensures proper user permissions are in place to prevent adversaries that try to modify and/or disable cloud logging capabilities.<br/>|
|[T1580 - Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/)|Detect|Minimal|GCP allows configuration of account policies to enable logging and IAM permissions and roles that may detect compromised user attempts to discover infrastructure and resources.|
|[T1580 - Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/)|Protect|Significant|Resource Manager can easily modify your Cloud Identity and Access Management policies for your organization and folders, and the changes will apply across all the projects and resources. Create and manage IAM access control policies for your organization and projects. This control may prevent adversaries that try to discover resources by placing a limit on discovery of these resources with least privilege.|
|[T1613 - Container and Resource Discovery](https://attack.mitre.org/techniques/T1613/)|Protect|Partial|Google Cloud Platform provides resource containers such as organizations, folders, and projects that allow one to group and hierarchically organize other GCP resources. This control may mitigate by denying direct remote access to internal systems through the use of network proxies, gateways, and firewalls from adversaries that may attempt to discover containers and other resources that are available within a containers environment.|
  


### Tags
- [Access Management](#tag-access-management)
- [Configuration Management](#tag-configuration-management)
- [Credentials](#tag-credentials)
- [Identity](#tag-identity)
- [Network](#tag-network)
  


### References
- <https://cloud.google.com/resource-manager/docs/cloud-platform-resource-hierarchy>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='secret-manager'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 39. Secret Manager



Secret Manager allows you to store, manage, and access secrets as binary blobs or text strings. Secret Manager works well for storing configuration information such as database passwords, API keys, or TLS certificates needed by an application at runtime.

- [Mapping File](SecretManager.yaml) ([YAML](SecretManager.yaml))
- [Navigator Layer](layers/SecretManager.json) ([JSON](layers/SecretManager.json))

### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)|Protect|Minimal|This control provides secure methods for accessing secrets and passwords. This can reduce the incidents of credentials and other authentication material being transmitted in clear-text or by insecure encryption methods. Any communication between applications or endpoints after access to Secret Manager may not be secure.|
|[T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)|Protect|Partial|This control can provide protection against attackers stealing application access tokens if they are stored within Secret Manager. Secret Manager significantly raises the bar for access of stored tokens by requiring legitimate credentials with proper authorization. Applications may have to be modified to take advantage of Secret Manager and may not always be possible to utilize.|
|[T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)|Protect|Partial|This control provides a central, secure location for storage of credentials to reduce the possibility of attackers discovering unsecured credentials.|
|[T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)|Protect|Partial|This control may provide a more secure location for storing passwords. If an cloud user account, endpoint, or application is compromised, they may have limited access to passwords stored in Secret Manager.|
  


### Tags
- [Data Security](#tag-data-security)
  


### References
- <https://cloud.google.com/secret-manager/docs/overview>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='security-command-center'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 40. Security Command Center



Security Command Center (SCC) provides analysts with a centralized dashboard for cyber situational awareness by aggregating threat and vulnerability reports. SCC works by scanning for weaknesses or monitoring an organization's logging stream for anomalies (e.g., Google Workspace logs, containers, vulnerabilities in web applications, and hypervisor-level instrumentation). To further mitigate risks in the infrastructure, SCC easily integrates with other Google Cloud security solutions: Cloud DLP, Chronicle, Binary Authorization, Cloud Armor, and 3rd party solutions (e.g., SIEM, SOAR). The cyber-attacks in this solution are correlated to SCC's premium tier which included additional security features for: Event Threat Detection, Container Threat Detection, Virtual Machine Threat Detection, Web Security Scanner, and Security Health Analytics

- [Mapping File](SCC.yaml) ([YAML](SCC.yaml))
- [Navigator Layer](layers/SCC.json) ([JSON](layers/SCC.json))

### Mapping Comments


This mapping was rated as significant due to the control’s notable detection accuracy, mappable threat coverage, and time-related factors (e.g., real-time).

SCC also provides users with compliance mappings that scan environments against violations according to PCI-DSS v3.2.1, OWASP Top Ten, NIST 800-53, and ISO 27001. 

To improve cyber-situational awareness and detection against various threats, SCC ingests logging data from multiple sources. Cloud Audit Admin Activity logs are always enabled by default and cannot be disabled. SCC Premium consumes logs automatically when activated. SSH Logs and syslog inform the brute force detector, and the set of network logs (VPC Flow/Cloud Firewall/Cloud NAT/Cloud DNS).

Further automated response functionality can be extended in SCC to take actions against threats. A full list of automated actions can be found on GCP's GitHub.

Reference: https://github.com/GoogleCloudPlatform/security-response-automation   


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1014 - Rootkit](https://attack.mitre.org/techniques/T1014/)|Detect|Significant|SCC is able to detect when secure boot is not enabled. Adversaries may use this weakness to abuse pre-boot mechanisms and persist on compromised systems (e.g., rootkit). This technique was graded as significant due to the real-time temporal factor.|
|[T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/)|Protect|Minimal|Using Web Security Scanner, SCC is able to detect when passwords are transmitted in cleartext. Adversaries may use this traffic mirroring services to sniff traffic and intercept unencrypted credentials. This technique was graded as partial due to the low protect coverage when transmitting passwords in clear-text and there is more information that could be gathered during a network sniffing attacks.|
|[T1059.004 - Unix Shell](https://attack.mitre.org/techniques/T1059/004/)|Detect|Significant|SCC uses machine learning [NLP techniques] to evaluate content of an executed bash script. This security solution protects against potentially malicious scripts that are used to execute commands in compromised systems. Because of the high threat detection coverage provided by the ML model and near-real time temporal factor this control was graded as significant.|
|[T1070 - Indicator Removal on Host](https://attack.mitre.org/techniques/T1070/)|Detect|Significant|SCC is able to detect when audit logging has been disabled for a resource. Adversaries may use this weakness to hide their activity and remove evidence of their presence (e.g., clear command history, clear logs, file deletion). This technique was graded as significant due to the high detect coverage and real-time temporal factor.|
|[T1071.004 - DNS](https://attack.mitre.org/techniques/T1071/004/)|Detect|Significant|SCC is able to ingest Cloud DNS logs and detect DNS queries that could indicate active Log4j vulnerable to remote code execution. Because of the near-real time temporal factor for detection this control was graded as significant.|
|[T1078.001 - Default Accounts](https://attack.mitre.org/techniques/T1078/001/)|Detect|Significant|SCC is able to detect when default service accounts are used. Adversaries may use this attack as a means to gain initial access, privilege escalation, or defense evasion. This subtechnique was graded as significant due to the high detect coverage and near-real time temporal factor.|
|[T1078.004 - Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)|Detect|Significant|SCC ingests Cloud Audit logs to detect when an external member is added to a privileged group with sensitive permissions or roles. This security solution protects against compromised cloud accounts used to maintain persistence and harvest sensitive data. Because of the near-real time temporal factor to detect against this cyber-attack the control was graded as significant.|
|[T1098.001 - Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)|Detect|Significant|SCC ingests Cloud Audit logs to detect when permissions are changed in a privileged group (i.e., modify group to public) with sensitive permissions or roles. This security solution protects against compromised cloud accounts used to maintain persistence. Because of the near-real time temporal factor to detect against this cyber-attack the control was graded as significant.|
|[T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)|Detect|Significant|SCC uses machine learning [NLP techniques] to evaluate content of an executed bash script. This security solution protects against potentially malicious scripts that are used to transfer tools into a compromised environment and execute commands without binaries. Because of the high threat detection coverage provided by the ML model and near-real time temporal factor this control was graded as significant.|
|[T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)|Detect|Significant|SCC uses syslog to detect successful brute force attacks [via SSH] on a host. Because of the near-real time temporal factor when detecting cyber-attacks this control was graded as significant.|
|[T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)|Detect|Significant|SCC is able to detect attackers communicating with a compromised workload from a remote system (e.g., "reverse shell"). SCC specifically detects for stdin bound to a remote socket. Because of the high threat detection coverage and near-real time temporal factor this control was graded as significant.|
|[T1136.003 - Cloud Account](https://attack.mitre.org/techniques/T1136/003/)|Detect|Significant|SCC ingests admin activity from Cloud Audit logs to detect when new service accounts are created. This security solution protects against potential adversary generated accounts used for initial access or to maintain persistence. Because of the temporal factor to detect this attack the control was graded as significant.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Detect|Significant|Using Web Security Scanner, SCC is able to detect and provide guidance for web application security risks (e.g., Cross-Site Scripting, SQL injection, Server Side Request Forgery, Insecure Deserialization). Adversaries may exploit these web app weaknesses in a cloud-based environment to compromise the underlying instance or container. This technique was graded as significant due to the high detect coverage against varying forms of this attack.|
|[T1204.003 - Malicious Image](https://attack.mitre.org/techniques/T1204/003/)|Detect|Significant|SCC is able to detect a potentially malicious binary being executed that was not part of the original container image. Because of the high threat detection coverage and near-real time temporal factor this control was graded as significant.|
|[T1213.003 - Code Repositories](https://attack.mitre.org/techniques/T1213/003/)|Protect|Significant|Using Web Security Scanner, SCC is able to detect repositories (e.g., Git or SVN) that are exposed to the public. Adversaries may use this lapse in security configuration to collect information about the target. Because of the near-real time temporal factor to detect against this cyber-attack this was graded as significant.|
|[T1484 - Domain Policy Modification](https://attack.mitre.org/techniques/T1484/)|Detect|Significant|SCC ingests admin activity from Cloud Audit logs to detect when an external member is added to a privileged group with sensitive permissions or roles. This security solution protects against adversary created accounts used to establish or maintain persistence. Because of the temporal factor to detect this attack, the control was graded as significant.|
|[T1496 - Resource Hijacking](https://attack.mitre.org/techniques/T1496/)|Detect|Significant|SCC detect compromised hosts that attempt to connect to known malicious crypto-mining domains and IP addresses. Because of the near-real time temporal factor to detect against this cyber-attack the control was graded as significant.|
|[T1505.001 - SQL Stored Procedures](https://attack.mitre.org/techniques/T1505/001/)|Detect|Significant|SCC ingests MySQL/PostgreSQL/SQL Server data access logs to track cloud sql instances that are backed-up outside the organization. This security solution detects potential database exfiltration attacks that were attempted and completed to an external resource. Because of the near-real time temporal factor this control was graded as significant.|
|[T1505.003 - Web Shell](https://attack.mitre.org/techniques/T1505/003/)|Detect|Significant|SCC is able to detect attackers communicating with a compromised workload from a remote system (e.g., "web shell"). Because of the high threat detection coverage and near-real time temporal factor this control was graded as significant.|
|[T1525 - Implant Internal Image](https://attack.mitre.org/techniques/T1525/)|Detect|Significant|SCC is able to detect modifications that were not not part of the original container image. Because of the high threat detection coverage and near-real time temporal factor this control was graded as significant.|
|[T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)|Detect|Partial|SCC detect suspicious activity when accessing cloud storage objects (e.g.,  new IPs accessing storage objects or enumeration from unfamiliar user identities). Because of the real time temporal factor when detecting access to secure storage objects this control was graded as partial.|
|[T1542 - Pre-OS Boot](https://attack.mitre.org/techniques/T1542/)|Detect|Significant|SCC is able to detect when secure boot is not enabled. Adversaries may use this weakness to abuse pre-boot mechanisms and persist on compromised systems. This technique was graded as significant due to the high detect coverage and near real-time temporal factor.|
|[T1542.003 - Bootkit](https://attack.mitre.org/techniques/T1542/003/)|Detect|Significant|SCC is able to detect when secure boot is not enabled. Adversaries may use this weakness to abuse pre-boot mechanisms and persist on compromised systems (e.g., bootkit). This technique was graded as significant due to the high detect coverage and near real-time temporal factor.|
|[T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/)|Detect|Significant|SCC ingests VPC Audit logs to detect changes which would lead to changes in the security posture. This security solution protects against network modifications that are used to reduce the security perimeter, disable logs, and evade cyber-defense of a target environment. Because of the near-real time temporal factor this control was graded as significant.|
|[T1562.007 - Disable or Modify Cloud Firewall](https://attack.mitre.org/techniques/T1562/007/)|Detect|Significant|SCC is able to detect changes to VPC service controls that could modify and reduced the secured perimeter. This security solution protects against modifications that could lead to a lower security posture and defense evasion. Because of the near-real time temporal factor to detect against this cyber-attack the control was graded as significant.|
|[T1562.008 - Disable Cloud Logs](https://attack.mitre.org/techniques/T1562/008/)|Detect|Significant|SCC detect changes to the configuration which would lead to disable logging on an instance or container. This security solution protects against system modifications used to remove evidence and evade defenses. Because of the near-real time temporal factor this control was graded as significant.|
|[T1567 - Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)|Detect|Significant|SCC ingests BigQueryAudit data access logs used to track sensitive data that is saved outside of an organization or attempts to access protected resources. This security solution detects exfiltration attacks that were attempted and completed to an external or public resource. Because of the near-real time temporal factor this control was graded as significant.|
|[T1567.002 - Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/)|Detect|Significant|SCC ingests BigQueryAudit data access logs used to track sensitive data that is saved to a cloud storage (e.g., Google Drive). This security solution detects exfiltration attacks that were attempted and completed to an external or public resource. Because of the near-real time temporal factor this control was graded as significant.|
|[T1578 - Modify Cloud Compute Infrastructure](https://attack.mitre.org/techniques/T1578/)|Detect|Significant|SCC detect changes to the cloud infrastructure and resources which could indicate malicious behavior (e.g., delete instances, create snapshot, revert cloud instance). This security solution protects against modifications potentially used to remove evidence and evade defenses. Because of the near-real time temporal factor and high detection coverage this control was graded as significant.|
|[T1589.001 - Credentials](https://attack.mitre.org/techniques/T1589/001/)|Protect|Significant|SCC has the capability to disable user account after detecting a related account password leak. Because of the near-real time temporal factor to detect against this cyber-attack the control was graded as significant.|
  


### Tags
- [Analytics](#tag-analytics)
- [Security Command Center](#tag-security-command-center)
- [Vulnerability Management](#tag-vulnerability-management)
  


### References
- <https://cloud.google.com/security-command-center/docs/concepts-security-command-center-overview>
- <https://github.com/GoogleCloudPlatform/security-analytics>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='shielded-vm'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 41. Shielded VM



Shielded VMs are virtual machines (VMs) on Google Cloud hardened by a set of security controls that help defend against rootkits and bootkits. Shielded VMs leverage advanced platform security capabilities such as secure and measured boot, a virtual trusted platform module (vTPM), UEFI firmware, and integrity monitoring.

- [Mapping File](ShieldedVM.yaml) ([YAML](ShieldedVM.yaml))
- [Navigator Layer](layers/ShieldedVM.json) ([JSON](layers/ShieldedVM.json))

### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1014 - Rootkit](https://attack.mitre.org/techniques/T1014/)|Protect|Partial|This control is able to mitigate the use of rootkits that target any portion of the boot process, such as malicious modification of the Master Boot Record or UEFI. This control does not mitigate rootkits that exist in the kernel or userland.|
|[T1542 - Pre-OS Boot](https://attack.mitre.org/techniques/T1542/)|Protect|Significant|This control is able to mitigate malicious modification of any portion of the pre-os boot process through a combination of Secure Boot to verify signatures of firmware, Measured Boot to establish a known good boot baseline, and Integrity Monitoring to measure subsequent boots to previously established baselines.|
  


### Tags
- [Vulnerability Management](#tag-vulnerability-management)
  


### References
- <https://cloud.google.com/compute/shielded-vm/docs/shielded-vm>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='siemplify'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 42. Siemplify



Siemplify is a security orchestration, automation and response (SOAR) provider that is unified with Google's Chronicle security control to provide an intuitive workbench that enables security teams to manage risk better and reduce the cost of addressing threats.

- [Mapping File](siemplify.yaml) ([YAML](siemplify.yaml))
- [Navigator Layer](layers/siemplify.json) ([JSON](layers/siemplify.json))

### Mapping Comments


Siemplify primarily acts as a layer for alerts generated by other controls to be collected and trigger mitigation and remediation actions to be taken by other controls provided by the Google Cloud Platform. On its own, Siemplify does not provide additional coverage of Attack techniques and is not mappable.  


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
  


### Tags
- [Not Mappable](#tag-not-mappable)
  


### References
- <https://cloud.google.com/blog/products/identity-security/raising-the-bar-in-security-operations>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='terraform-on-google-cloud'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 43. Terraform on Google Cloud



Terraform is an open source tool that lets you provision Google Cloud resources with declarative configuration files—resources such as virtual machines, containers, storage, and networking. Terraform's infrastructure-as-code (IaC) approach supports DevOps best practices for change management, letting you manage Terraform configuration files in source control to maintain an ideal provisioning state for testing and production environments.

- [Mapping File](TerraformGoogle Cloud.yaml) ([YAML](TerraformGoogle Cloud.yaml))
- [Navigator Layer](layers/TerraformGoogle Cloud.json) ([JSON](layers/TerraformGoogle Cloud.json))

### Mapping Comments


In its current state, this control was scored as not mappable as it does not look reasonable to correlate to specific (sub-) techniques of MITRE’s ATT&CK.

While Terraform provides some security capabilities specific to Terraform processes (encryption between Terraform Clients, encrypting workspace variables, 
Isolation between Terraform executions and Cloud tenants) the capabilities don't necessarily benefit the entire organization. Terraform's primary function is to support the provisioning of Google resources with configuration management. Therefore, this control has been identified as not-mappable.  


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
  


### Tags
- [Not Mappable](#tag-not-mappable)
  


### References
- <https://cloud.google.com/docs/terraform>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='titan-security-key'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 44. Titan Security Key



The Titan Security Key provides a tamper resistant hardware security key that is used for 2-factor authentication.

- [Mapping File](TitanSecurityKey.yaml) ([YAML](TitanSecurityKey.yaml))
- [Navigator Layer](layers/TitanSecurityKey.json) ([JSON](layers/TitanSecurityKey.json))

### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1566 - Phishing](https://attack.mitre.org/techniques/T1566/)|Protect|Significant|This control is able to mitigate against a variety of phishing attacks by requiring an additional key for authentication outside of the user's password. Compared to other forms of 2-factor authentication, this control will not allow for authentication to an illegitimate service or website as the key can not be transmitted from the hardware device to any other device.|
  


### Tags
- [Identity](#tag-identity)
- [Multi-Factor Authentication](#tag-multi-factor-authentication)
  


### References
- <https://cloud.google.com/titan-security-key#section-3>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='vmmanager'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 45. VMManager



VM Manager is a suite of tools that can be used to manage operating systems for large virtual machine (VM) fleets running Windows and Linux on Compute Engine.

VM Manager helps drive efficiency through automation and reduces the operational burden of maintaining these VM fleets.

- [Mapping File](VMManager.yaml) ([YAML](VMManager.yaml))
- [Navigator Layer](layers/VMManager.json) ([JSON](layers/VMManager.json))

### Mapping Comments


This mapping was scored as Partial due to the medium threat protection coverage to specific (sub-) techniques of MITRE’s ATT&CK framework.  


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|Protect|Partial|VM Manager can apply on-demand and scheduled patches via automated patch deployment. This can remediate OS and software vulnerabilities that could otherwise be exploited. Since VM Manager doesn't directly prevent exploitation of active vulnerabilities (including zero day vulnerabilities) this control has resulted in a score of Partial.|
|[T1072 - Software Deployment Tools](https://attack.mitre.org/techniques/T1072/)|Protect|Partial|VM Manager can apply on-demand and scheduled patches via automated patch deployment. This can remediate OS and software vulnerabilities that could otherwise be exploited. Since VM Manager doesn't directly prevent exploitation of active vulnerabilities (including zero day vulnerabilities) this control has resulted in a score of Partial.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Protect|Partial|VM Manager can apply on-demand and scheduled patches via automated patch deployment. This can remediate OS and software vulnerabilities that could otherwise be exploited. Since VM Manager doesn't directly prevent exploitation of active vulnerabilities (including zero day vulnerabilities) this control has resulted in a score of Partial.|
|[T1203 - Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)|Protect|Partial|VM Manager can apply on-demand and scheduled patches via automated patch deployment. This can remediate OS and software vulnerabilities that could otherwise be exploited. Since VM Manager doesn't directly prevent exploitation of active vulnerabilities (including zero day vulnerabilities) this control has resulted in a score of Partial.|
|[T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)|Protect|Partial|VM Manager can apply on-demand and scheduled patches via automated patch deployment. This can remediate OS and software vulnerabilities that could otherwise be exploited. Since VM Manager doesn't directly prevent exploitation of active vulnerabilities (including zero day vulnerabilities) this control has resulted in a score of Partial.|
|[T1211 - Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211/)|Protect|Partial|VM Manager can apply on-demand and scheduled patches via automated patch deployment. This can remediate OS and software vulnerabilities that could otherwise be exploited. Since VM Manager doesn't directly prevent exploitation of active vulnerabilities (including zero day vulnerabilities) this control has resulted in a score of Partial.|
|[T1212 - Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212/)|Protect|Partial|VM Manager can apply on-demand and scheduled patches via automated patch deployment. This can remediate OS and software vulnerabilities that could otherwise be exploited. Since VM Manager doesn't directly prevent exploitation of active vulnerabilities (including zero day vulnerabilities) this control has resulted in a score of Partial.|
  


### Tags
- [Configuration Management](#tag-configuration-management)
- [Credentials](#tag-credentials)
- [Patch Management](#tag-patch-management)
- [Vulnerability Management](#tag-vulnerability-management)
  


### References
- <https://cloud.google.com/compute/docs/vm-manager>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='vpc-service-controls'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 46. VPC Service Controls



VPC Service Controls improves your ability to mitigate the risk of data exfiltration from Google Cloud services such as Cloud Storage and BigQuery. You can use VPC Service Controls to create perimeters that protect the resources and data of services that you explicitly specify.

- [Mapping File](VPCServiceControls.yaml) ([YAML](VPCServiceControls.yaml))
- [Navigator Layer](layers/VPCServiceControls.json) ([JSON](layers/VPCServiceControls.json))

### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)|Protect|Significant|This control is able to mitigate against abuse of compromised valid accounts by restricting access from those accounts to resources contained within the VPC perimeter the account belongs to. Resources and services contained in other VPC networks also cannot be accessed by user accounts that are not within the VPC network perimeter.|
|[T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)|Protect|Significant|This control may mitigate against access to cloud storage objects by limiting access to accounts and services contained within the VPC network perimeter that contains those cloud storage objects.|
|[T1537 - Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)|Protect|Significant|This control may mitigate against exfiltration attempts to external cloud accounts by limiting egress of data to accounts and services contained within the VPC network perimeter.|
|[T1567 - Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)|Protect|Partial|This control is able to mitigate against exfiltration of data over a web service. Data contained within a VPC network perimeter can not be moved to a Google cloud resource or service outside of the perimeter but may be moved to third party services or storage.|
|[T1619 - Cloud Storage Object Discovery](https://attack.mitre.org/techniques/T1619/)|Protect|Partial|This control may mitigate against discovery of cloud storage objects. This control is not able to protect metadata, such as cloud storage bucket names but can protect against discovery of the contents of a storage bucket.|
  


### Tags
- [Access Control Policies](#tag-access-control-policies)
- [Network](#tag-network)
- [Virtual Private Cloud](#tag-virtual-private-cloud)
  


### References
- <https://cloud.google.com/vpc-service-controls/docs/overview>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='virtual-private-cloud'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 47. Virtual Private Cloud



Google Cloud's Virtual Private Cloud (VPC) allows users to logically isolate resources and define security perimeters that filters [ingress and egress] traffic in a virtual network based on user identity or policies for cloud assets (e.g., instance or subnet).

- [Mapping File](VPC.yaml) ([YAML](VPC.yaml))
- [Navigator Layer](layers/VPC.json) ([JSON](layers/VPC.json))

### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1018 - Remote System Discovery](https://attack.mitre.org/techniques/T1018/)|Protect|Significant|VPC security perimeters can segment private resources to deny traffic based on organizational policy.|
|[T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046/)|Protect|Significant|VPC security perimeters can limit the impact from active scanning and lateral movement techniques used to exploit the target environment.|
|[T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)|Protect|Significant|VPC further segments the environment by providing configurable granular access controls which help limit user communications to critical systems.|
|[T1098.001 - Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)|Protect|Partial|VPC further segments the environment by providing configurable granular access controls which help limit user permissions to communicate with critical systems.|
|[T1135 - Network Share Discovery](https://attack.mitre.org/techniques/T1135/)|Protect|Significant|VPC security perimeters can limit the impact from active scanning and lateral movement techniques used to exploit the target environment.|
|[T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)|Protect|Significant|VPC security perimeters can segment private resources to further reduce user access and operate in a logically separate hosting environment.|
|[T1552.007 - Container API](https://attack.mitre.org/techniques/T1552/007/)|Protect|Significant|VPC security perimeters can segment private resources to provide access based on user identity or organizational ingress/egress policies (e.g., instance, subnet).|
|[T1557 - Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)|Protect|Partial|VPC security perimeter mitigates the impact from Adversary-in-the-Middle by creating virtual segmentation that limits the data and information broadcast on the network.|
|[T1570 - Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/)|Protect|Minimal|VPC security perimeters can segment private resources to deny ingress and egress traffic based on organizational policies. Because this tool does not prevent attacks from valid accounts or compromised machines, it was scored as  minimal.|
|[T1590 - Gather Victim Network Information](https://attack.mitre.org/techniques/T1590/)|Protect|Significant|VPC security perimeters can limit the impact from active scanning techniques used to gain further information about the target environment.|
|[T1590.004 - Network Topology](https://attack.mitre.org/techniques/T1590/004/)|Protect|Significant|VPC security perimeters can limit the impact from active scanning techniques used to gain further information about the target environment.|
|[T1590.005 - IP Addresses](https://attack.mitre.org/techniques/T1590/005/)|Protect|Significant|VPC security perimeters can limit the impact from active scanning techniques used to gain further information about the target environment.|
|[T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)|Protect|Significant|VPC security perimeters can limit the impact from active scanning and lateral movement techniques used to exploit the target environment.|
|[T1595.001 - Scanning IP Blocks](https://attack.mitre.org/techniques/T1595/001/)|Protect|Significant|VPC security perimeters can limit the impact from active scanning on private networks and lateral movement techniques used to exploit target environments.|
|[T1602 - Data from Configuration Repository](https://attack.mitre.org/techniques/T1602/)|Protect|Significant|VPC security perimeters can isolate resources and limit the impact from lateral movement techniques used to access sensitive data.|
  


### Tags
- [Network](#tag-network)
- [Virtual Private Cloud](#tag-virtual-private-cloud)
  


### References
- <https://cloud.google.com/vpc-service-controls/docs>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='virus-total'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 48. Virus Total



 VirusTotal analyzes suspicious files, domains, IPs and URLs to detect malware and other breaches, automatically share them with the security community. It's a web-based scanner that utilizes over 70 antivirus scanners and URL/blacklisting services, among other tools, to extract signals from uploaded content. 

- [Mapping File](VirusTotal.yaml) ([YAML](VirusTotal.yaml))
- [Navigator Layer](layers/VirusTotal.json) ([JSON](layers/VirusTotal.json))

### Mapping Comments


This mapping was scored as significant due to the control’s high threat protection coverage to specific ATT&CK (sub-)techniques and temporal factors (e.g., real-time).  


### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)|Protect|Significant|VirusTotal, now part of Google Cloud, provides threat context and reputation data to help analyze suspicious files, URLs, domains, and IP addresses to detect cybersecurity threats.|
|[T1566 - Phishing](https://attack.mitre.org/techniques/T1566/)|Protect|Significant|VirusTotal, now part of Google Cloud, provides threat context and reputation data to help analyze suspicious files, URLs, domains, and IP addresses to detect cybersecurity threats.  This control can help mitigate adversaries that try to send malware via emails using malicious links or attachments. The malware-scanner service scans the uploaded document for malware.<br/>If the document is infected, the service moves it to a quarantined bucket; otherwise the document is moved into another bucket that holds uninfected scanned documents.|
|[T1566.001 - Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)|Protect|Partial|VirusTotal, now part of Google Cloud, provides threat context and reputation data to help analyze suspicious files, URLs, domains, and IP addresses to detect cybersecurity threats.|
|[T1566.002 - Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)|Protect|Significant|VirusTotal, now part of Google Cloud, provides threat context and reputation data to help analyze suspicious files, URLs, domains, and IP addresses to detect cybersecurity threats.  This control can help mitigate adversaries sending malware through spearphishing emails. The malware-scanner service scans the uploaded document for malware. If the document is infected, the service moves it to a quarantined bucket; otherwise the document is moved into another bucket that holds uninfected scanned documents.|
|[T1598.003 - Spearphishing Link](https://attack.mitre.org/techniques/T1598/003/)|Protect|Significant|Adversaries may send spearphishing messages with a malicious link to elicit sensitive information that can be used during targeting. VirusTotal Graph is a visualization tool built on top of the VirusTotal data set. It analyzes the relationship between files, URLs, domains, IP addresses, and other items encountered.|
  


### Tags
- [Antimalware](#tag-antimalware)
- [Antivirus](#tag-antivirus)
- [Malware](#tag-malware)
  


### References
- <https://cloud.google.com/architecture/automating-malware-scanning-for-documents-uploaded-to-cloud-storage>
- <https://cloud.google.com/chronicle/docs/investigation/view-virustotal-information>
- <https://assets.virustotal.com/vt-360-outcomes.pdf>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='web-risk'></a>

## ![GCP icon](/security-stack-mappings/icons/gcp_icon.svg) 49. Web Risk



Web Risk is a Google Cloud service that lets client applications check URLs against Google's constantly updated lists of unsafe web resources. Unsafe web resources include social engineering sites—such as phishing and deceptive sites—and sites that host malware or unwanted software. With the Web Risk, you can quickly identify known bad sites, warn users before they click infected links, and prevent users from posting links to known infected pages from your site.

- [Mapping File](WebRisk.yaml) ([YAML](WebRisk.yaml))
- [Navigator Layer](layers/WebRisk.json) ([JSON](layers/WebRisk.json))

### Techniques

|Technique|Category|Value|Comment|
| :--- | :--- | :--- | :--- |
|[T1204.001 - Malicious Link](https://attack.mitre.org/techniques/T1204/001/)|Protect|Partial|Web Risk allows client applications to check URLs against Google's list of unsafe web resources. It also can provide warnings when attempting to access potentially unsafe sites. However, Google cannot guarantee that its information is comprehensive and error-free: some risky sites may not be identified, and some safe sites may be classified in error. This has resulted in an overall score of Partial.|
|[T1566 - Phishing](https://attack.mitre.org/techniques/T1566/)|Protect|Partial|Web Risk allows client applications to check URLs against Google's list of unsafe web resources. It also can provide warnings when attempting to access potentially unsafe sites. However, Google cannot guarantee that its information is comprehensive and error-free: some risky sites may not be identified, and some safe sites may be classified in error. This has resulted in an overall score of Partial.|
|[T1598 - Phishing for Information](https://attack.mitre.org/techniques/T1598/)|Protect|Partial|Web Risk allows client applications to check URLs against Google's list of unsafe web resources. It also can provide warnings when attempting to access potentially unsafe sites. However, Google cannot guarantee that its information is comprehensive and error-free: some risky sites may not be identified, and some safe sites may be classified in error. This has resulted in an overall score of Partial.|
|[T1598.003 - Spearphishing Link](https://attack.mitre.org/techniques/T1598/003/)|Protect|Partial|Web Risk allows client applications to check URLs against Google's list of unsafe web resources. It also can provide warnings when attempting to access potentially unsafe sites. However, Google cannot guarantee that its information is comprehensive and error-free: some risky sites may not be identified, and some safe sites may be classified in error. This has resulted in an overall score of Partial.|
  


### Tags
- [Network](#tag-network)
  


### References
- <https://cloud.google.com/web-risk/docs/overview>
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>


# Control Tags
<a name='tag-access-control-policies'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 1. Access Control Policies


### Controls
- [VPC Service Controls](#vpc-service-controls)

### Views
- [Navigator Layer](layers/tags/Access_Control_Policies.json) ([JSON](layers/tags/Access_Control_Policies.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-access-management'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 2. Access Management


### Controls
- [ResourceManager](#resourcemanager)

### Views
- [Navigator Layer](layers/tags/Access_Management.json) ([JSON](layers/tags/Access_Management.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-adaptive-network-hardening'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 3. Adaptive Network Hardening


### Controls
- [ResourceManager](#resourcemanager)

### Views
- [Navigator Layer](layers/tags/Adaptive_Network_Hardening.json) ([JSON](layers/tags/Adaptive_Network_Hardening.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-analytics'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 4. Analytics


### Controls
- [Security Command Center](#security-command-center)

### Views
- [Navigator Layer](layers/tags/Analytics.json) ([JSON](layers/tags/Analytics.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-antimalware'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 5. Antimalware


### Controls
- [Virus Total](#virus-total)

### Views
- [Navigator Layer](layers/tags/Antimalware.json) ([JSON](layers/tags/Antimalware.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-antivirus'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 6. Antivirus


### Controls
- [Virus Total](#virus-total)

### Views
- [Navigator Layer](layers/tags/Antivirus.json) ([JSON](layers/tags/Antivirus.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-auditing'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 7. Auditing


### Controls
- [Access Transparency](#access-transparency)

### Views
- [Navigator Layer](layers/tags/Auditing.json) ([JSON](layers/tags/Auditing.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-binary-authorization'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 8. Binary Authorization


### Controls
- [Binary Authorization](#binary-authorization)

### Views
- [Navigator Layer](layers/tags/Binary_Authorization.json) ([JSON](layers/tags/Binary_Authorization.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-certificate-service'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 9. Certificate Service


### Controls
- [Certificate Authority Service](#certificate-authority-service)

### Views
- [Navigator Layer](layers/tags/Certificate_Service.json) ([JSON](layers/tags/Certificate_Service.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-chronicle'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 10. Chronicle


### Controls
- [Chronicle](#chronicle)

### Views
- [Navigator Layer](layers/tags/Chronicle.json) ([JSON](layers/tags/Chronicle.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-cloud-ids'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 11. Cloud IDS


### Controls
- [Cloud IDS](#cloud-ids)

### Views
- [Navigator Layer](layers/tags/Cloud_IDS.json) ([JSON](layers/tags/Cloud_IDS.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-config-management'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 12. Config Management


### Controls
- [Cloud IDS](#cloud-ids)

### Views
- [Navigator Layer](layers/tags/Config_Management.json) ([JSON](layers/tags/Config_Management.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-configuration-management'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 13. Configuration Management


### Controls
- [VMManager](#vmmanager)

### Views
- [Navigator Layer](layers/tags/Configuration_Management.json) ([JSON](layers/tags/Configuration_Management.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-containers'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 14. Containers


### Controls
- [Google Kubernetes Engine](#google-kubernetes-engine)

### Views
- [Navigator Layer](layers/tags/Containers.json) ([JSON](layers/tags/Containers.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-credentials'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 15. Credentials


### Controls
- [VMManager](#vmmanager)

### Views
- [Navigator Layer](layers/tags/Credentials.json) ([JSON](layers/tags/Credentials.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-data-catalog'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 16. Data Catalog


### Controls
- [Data Catalog](#data-catalog)

### Views
- [Navigator Layer](layers/tags/Data_Catalog.json) ([JSON](layers/tags/Data_Catalog.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-data-loss-prevention'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 17. Data Loss Prevention


### Controls
- [BeyondCorp Enterprise](#beyondcorp-enterprise)

### Views
- [Navigator Layer](layers/tags/Data_Loss_Prevention.json) ([JSON](layers/tags/Data_Loss_Prevention.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-data-security'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 18. Data Security


### Controls
- [Secret Manager](#secret-manager)

### Views
- [Navigator Layer](layers/tags/Data_Security.json) ([JSON](layers/tags/Data_Security.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-database'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 19. Database


### Controls
- [Secret Manager](#secret-manager)

### Views
- [Navigator Layer](layers/tags/Database.json) ([JSON](layers/tags/Database.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-denial-of-service'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 20. Denial of Service


### Controls
- [Secret Manager](#secret-manager)

### Views
- [Navigator Layer](layers/tags/Denial_of_Service.json) ([JSON](layers/tags/Denial_of_Service.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-domain-name-system-dns'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 21. Domain Name System (DNS)


### Controls
- [Secret Manager](#secret-manager)

### Views
- [Navigator Layer](layers/tags/Domain_Name_System_(DNS).json) ([JSON](layers/tags/Domain_Name_System_(DNS).json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-encryption'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 22. Encryption


### Controls
- [Confidential VM and Compute Engine](#confidential-vm-and-compute-engine)

### Views
- [Navigator Layer](layers/tags/Encryption.json) ([JSON](layers/tags/Encryption.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-firewall'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 23. Firewall


### Controls
- [Firewalls](#firewalls)

### Views
- [Navigator Layer](layers/tags/Firewall.json) ([JSON](layers/tags/Firewall.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-identity'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 24. Identity


### Controls
- [Titan Security Key](#titan-security-key)

### Views
- [Navigator Layer](layers/tags/Identity.json) ([JSON](layers/tags/Identity.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-internet-of-things-iot'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 25. Internet of Things (IoT)


### Controls
- [Titan Security Key](#titan-security-key)

### Views
- [Navigator Layer](layers/tags/Internet_of_Things_(IoT).json) ([JSON](layers/tags/Internet_of_Things_(IoT).json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-intrusion-detection-service-ids'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 26. Intrusion Detection Service (IDS)


### Controls
- [Cloud IDS](#cloud-ids)

### Views
- [Navigator Layer](layers/tags/Intrusion_Detection_Service_(IDS).json) ([JSON](layers/tags/Intrusion_Detection_Service_(IDS).json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-kubernetes'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 27. Kubernetes


### Controls
- [Google Kubernetes Engine](#google-kubernetes-engine)

### Views
- [Navigator Layer](layers/tags/Kubernetes.json) ([JSON](layers/tags/Kubernetes.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-logging'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 28. Logging


### Controls
- [Firewalls](#firewalls)

### Views
- [Navigator Layer](layers/tags/Logging.json) ([JSON](layers/tags/Logging.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-malware'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 29. Malware


### Controls
- [Virus Total](#virus-total)

### Views
- [Navigator Layer](layers/tags/Malware.json) ([JSON](layers/tags/Malware.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-multi-factor-authentication'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 30. Multi-Factor Authentication


### Controls
- [Titan Security Key](#titan-security-key)

### Views
- [Navigator Layer](layers/tags/Multi-Factor_Authentication.json) ([JSON](layers/tags/Multi-Factor_Authentication.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-network'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 31. Network


### Controls
- [Web Risk](#web-risk)

### Views
- [Navigator Layer](layers/tags/Network.json) ([JSON](layers/tags/Network.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-not-mappable'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 32. Not Mappable


### Controls
- [Terraform on Google Cloud](#terraform-on-google-cloud)

### Views
- [Navigator Layer](layers/tags/Not_Mappable.json) ([JSON](layers/tags/Not_Mappable.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-os-security'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 33. OS Security


### Controls
- [Artifact Registry](#artifact-registry)

### Views
- [Navigator Layer](layers/tags/OS_Security.json) ([JSON](layers/tags/OS_Security.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-palo-alto-network-s-threat-signatures'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 34. Palo Alto Network's Threat Signatures


### Controls
- [Cloud IDS](#cloud-ids)

### Views
- [Navigator Layer](layers/tags/Palo_Alto_Network's_Threat_Signatures.json) ([JSON](layers/tags/Palo_Alto_Network's_Threat_Signatures.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-passwords'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 35. Passwords


### Controls
- [IdentityPlatform](#identityplatform)

### Views
- [Navigator Layer](layers/tags/Passwords.json) ([JSON](layers/tags/Passwords.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-patch-management'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 36. Patch Management


### Controls
- [VMManager](#vmmanager)

### Views
- [Navigator Layer](layers/tags/Patch_Management.json) ([JSON](layers/tags/Patch_Management.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-phishing'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 37. Phishing


### Controls
- [AdvancedProtectionProgram](#advancedprotectionprogram)

### Views
- [Navigator Layer](layers/tags/Phishing.json) ([JSON](layers/tags/Phishing.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-policy'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 38. Policy


### Controls
- [AnthosConfigManagement](#anthosconfigmanagement)

### Views
- [Navigator Layer](layers/tags/Policy.json) ([JSON](layers/tags/Policy.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-reports'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 39. Reports


### Controls
- [AnthosConfigManagement](#anthosconfigmanagement)

### Views
- [Navigator Layer](layers/tags/Reports.json) ([JSON](layers/tags/Reports.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-role-based-access-control'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 40. Role Based Access Control


### Controls
- [Policy Intelligence](#policy-intelligence)

### Views
- [Navigator Layer](layers/tags/Role_Based_Access_Control.json) ([JSON](layers/tags/Role_Based_Access_Control.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-siem'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 41. SIEM


### Controls
- [Chronicle](#chronicle)

### Views
- [Navigator Layer](layers/tags/SIEM.json) ([JSON](layers/tags/SIEM.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-security-command-center'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 42. Security Command Center


### Controls
- [Security Command Center](#security-command-center)

### Views
- [Navigator Layer](layers/tags/Security_Command_Center.json) ([JSON](layers/tags/Security_Command_Center.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-storage'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 43. Storage


### Controls
- [Cloud Storage](#cloud-storage)

### Views
- [Navigator Layer](layers/tags/Storage.json) ([JSON](layers/tags/Storage.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-threat-detection'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 44. Threat Detection


### Controls
- [Chronicle](#chronicle)

### Views
- [Navigator Layer](layers/tags/Threat_Detection.json) ([JSON](layers/tags/Threat_Detection.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-threat-hunting'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 45. Threat Hunting


### Controls
- [Chronicle](#chronicle)

### Views
- [Navigator Layer](layers/tags/Threat_Hunting.json) ([JSON](layers/tags/Threat_Hunting.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-vpn'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 46. VPN


### Controls
- [Hybrid Connectivity](#hybrid-connectivity)

### Views
- [Navigator Layer](layers/tags/VPN.json) ([JSON](layers/tags/VPN.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-virtual-private-cloud'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 47. Virtual Private Cloud


### Controls
- [Virtual Private Cloud](#virtual-private-cloud)

### Views
- [Navigator Layer](layers/tags/Virtual_Private_Cloud.json) ([JSON](layers/tags/Virtual_Private_Cloud.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-vulnerability-analysis'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 48. Vulnerability Analysis


### Controls
- [Container Registry](#container-registry)

### Views
- [Navigator Layer](layers/tags/Vulnerability_Analysis.json) ([JSON](layers/tags/Vulnerability_Analysis.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

<a name='tag-vulnerability-management'></a>
## ![tag icon](/security-stack-mappings/icons/tag-solid.svg) 49. Vulnerability Management


### Controls
- [VMManager](#vmmanager)

### Views
- [Navigator Layer](layers/tags/Vulnerability_Management.json) ([JSON](layers/tags/Vulnerability_Management.json))
  

<p class="text-center"><a href="#contents">Back to Contents</a></p>

