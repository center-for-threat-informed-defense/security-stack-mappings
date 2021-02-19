# Mapping Format

Below is the structure of the data format that captures the details of how a security control maps to ATT&CK techniques.  Details of each field are provided in the subsequent section along with some examples.


## Data Dictionary
### Top Level Metadata Fields
 
| Name | Type | Required | Description |
|------|------|----------|-------------|
| version | String | yes | The version of this data mapping format. |
| ATT&CK version | String |	yes | The version of the ATT&CK (Enterprise) matrix used to source the techniques included in this mapping. |
| creation date | String | yes | Creation time <br /> Format:  1/21/2021 |
| last update | String | no | Last update time <br /> Format:  1/21/2021 |
| name | String | yes |	The name of the security control being mapped in this file. |
| author | String | no | The name of the author of this mapping file. |
| contact | String | no | The email address of the author of this mapping file. |
| organization | String | no | The organization that produced this mapping file. |
| platform | String | yes | The cloud platform of the security control being mapped in this file. |
| tags | String | List of Strings | no | Will enable the mapping tool to produce visualizations (e.g. ATT&CK Navigator) by aggregating security controls by these tag values. <br /> Ex:  Produce an ATT&CK Navigator layer for all security controls tagged with "Azure AD". |
| description | String | yes | The description of the security control |
| techniques | List of Technique objects <br /> List Size:  [1-*] | yes |List of technique objects that describe the ATT&CK techniques that the control is able to offer protection. |
| comments | String | no | Use it to document any assumptions or comments on the mapping. |
| references | List of Strings | no	| A description of any useful references for understanding the data contained in this mapping. <br /> Ex:  A link to the documentation for the security control |




### Technique Object Fields

A technique object describes an ATT&CK technique that the security control provides protection against.
 
| Name | Type | Required | Description |
|------|------|----------|-------------|
|id | String | yes | The ID of the ATT&CK technique. |
| name | String | yes |The name of the ATT&CK technique. |
| technique-scores | List of Score objects <br /> List Size: [1-3] | no* | This optional field is a list of Score objects that enables assessing the effectiveness of the prevent, detect, and/or respond protections provided by the security control for this ATT&CK technique. |
| sub-techniques-scores	| List of Sub-techniqueScore objects <br /> List Size:  [1-*] | no* | This optional field is a list of Sub-techniqueScore objects that describe the specific sub-techniques of this technique that this control provides protection against. |


**\*A technique object must either have a technique-scores field or a sub-technique-scores field or both.**




### SubTechniquesScore Object Fields
 
A score object describes the assessment (score) of the effectiveness of the prevent, detect, and/or response protections provided by the security control for this ATT&CK sub-technique.
 
| Name | Type | Required | Description |
|------|-------|---------|-------------|
| sub-techniques | List of sub-technique ID and name tuples. | yes | The list of sub-techniques, identified by their ID and Name that the score objects apply to.  The length of this list should be at least 1.  This field supports providing a score for a group of sub-techniques rather than having to provide it for each sub-technique individually. |
| scores | List of Score objects <br /> List Size: [1-3] | yes | The list of score objects that describe the type of protection provided by this control to the specified sub-techniques. |




### Score Object Fields
A score object describes the assessment (score) of the effectiveness of the prevent, detect, and/or response protections provided by the security control for this ATT&CK technique.
 
| Name | Type | Required | Description |
|------|------|----------|-------------|
| category | String | yes | The control category. <br /> Valid values:  [Prevent, Detect, Respond] |
| value | String | yes | The score <br /> (Ex: Minimal, Partial, Full, etc.) |
| comment | String | no | A description of the justification for the assessed score or any related comments. |




## Example Mapping 

```
version: 1.0
ATT&CK version: 8.1
creation date: 1/21/2021
name: Azure Active Directory Password Protection
author: 
contact: ctid@mitre-engenuity.org
organization: Center for Threat Informed Defense (CTID)
platform: Azure
tags: 
  - Identity
  - Azure Active Directory
  - Passwords
  - Credentials
description: > 
  Azure AD Password Protection provides a global banned password lists are
  automatically applied to all users in an Azure AD tenant.  The Azure AD
  Identity Protection team constantly analyzes Azure AD security telemetry data
  looking for commonly used weak or compromised passwords.  When weak terms are
  found, they're added to the global banned password list. To support your own
  business and security needs, you can define entries in a custom banned 
  password list. When users change or reset their passwords, these banned 
  password lists are checked to enforce the use of strong passwords.
techniques:
  - id: T1110
    name: Brute Force
    technique-scores:
      - category: Prevent
        value: Partial
    sub-techniques-scores:
      - sub-techniques:
        - id: T1110.001
          name: Password Guessing
        - id: T1110.002
          name: Password Cracking
        - id: T1110.003
          name: Password Spraying
        - id: T1110.004
          name: Credential Stuffing
        scores:
          - category: Prevent
            value: Partial
comments: >
  All scores have been assessed as Partial because this control increases the
  strength of user passwords thereby reducing the likelihood of a successful
  brute force attack.  Due to the fact that a user's password is not checked 
  against the banned list of passwords unless the user changes or resets their 
  password (which is an infrequent event), there is still ample opportunity 
  for attackers to utilize this technique to gain access. This is what prevented
  the score from being elevated to Significant.
references:
  - https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-password-ban-bad
```
