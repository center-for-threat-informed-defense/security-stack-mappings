# Mapping Methodology

This document describes the methodology used to map security controls native to a technology platform to MITRE ATT&CK&copy; and aims to provide the community a reusable method of using ATT&CK to determine the capabilities of a platform's security offerings.

MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base represents adversary goals as tactics and the specific behaviors employed by adversaries to achieve those goals (how) as techniques and sub-techniques.   The methodology described below, utilizes the information in the ATT&CK knowledge base and its underlying data model to understand, assess and record the real-world threats that security controls native to a technology platform are able to mitigate.

The methodology consists of the following steps:
1. **Identify Platform Security Controls** - Identify the *native* security controls available on the platform.
1. **Security Control Review** - For each identified control, understand the security capabilities it provides.
1. **Identify Mappable ATT&CK Techniques & Sub-techniques** - Identify the ATT&CK techniques and sub-techniques mappable to the control.
1. **Score Assessment** - Assess the effectiveness of the type of protection the control provides for the identified ATT&CK techniques and sub-techniques.
1. **Create a Mapping** - Creating a mapping based on the information gathered from the previous steps. 

<img src="/images/MappingMethodologyDiagram.png" width="900px">

## Step 1:  Identify Platform Security Controls
Cyber security has emerged as an essential component of technology platforms, and consequently vendors tend to offer a variety of documentation on the security capabilities of their platform.  Peruse the platform documentation (e.g. security reference architectures, security benchmarks, security documentation of various services, etc.) to identify the security controls offered by the platform for protecting workloads on the platform.  Keep the following in mind while selecting controls:
- The scope of the controls mapped by this project are the technical control types and do not include administrative or physical control types.
- The selected controls should be native to the platform, i.e. produced by the vendor themselves or third-party controls branded by the vendor.  For example, thirty-party security controls offered in cloud marketplaces are considered out of scope.
- The security controls selected to be mapped as part of this project tend to be controls that are marketed as standalone security products available on the platform.  The intent is not to provide a mapping for all settings/features of individual platform services that are security related.  This is a non-trivial undertaking that may be explored at a later time.

## Step 2:  Security Control Review
For each identified security control, consult the available documentation to understand its capabilities.  Gather the following facts about the security control that will later help in mapping the control to the set of ATT&CK techniques and sub-techniques it is able to mitigate:
- Category of security function provided by the control:
    - Protect:  reduces the likelihood of the occurrence of a cybersecurity event.
    - Detect:   identifies the occurrence of a cybersecurity event.
    - Respond:  reduces or remediates the impact of a cybersecurity event.
- The resource type(s) protected by the control (e.g. identity, storage, network, etc.).
- If applicable, the list of operating systems supported by the control.
- Temporal nature of the control's operation:
    - Does the control operate in real-time?
    - Does the control operate periodically (hourly, daily, weekly, etc.)?
    - Is the control event triggered? How often do these events occur?
- Specific threats cited in documentation that the control mitigates.

## Step 3:  Identify Mappable ATT&CK Techniques & Sub-techniques
After understanding the capabilities of the security control and gathering the basic facts about its operation, as identified in the previous step, review the ATT&CK matrix and identify the techniques and sub-techniques the control is able to mitigate.

The following may help with this process:

#### Identify ATT&CK Tactics in Scope
- The resource type(s) protected by the control, as identified in the previous step, can help narrow down the ATT&CK tactics which are in scope for this control.
    - Example:  A control that protects identity related resources can help you focus your attention on ATT&CK tactics relevant to identity, such as:  Privilege Escalation and Credential Access.
- [ATT&CK's mitigations](https://attack.mitre.org/mitigations/enterprise/) which describe the configurations, tools or process that can prevent the successful execution of a set of (sub-)techniques, can also be used to identify the ATT&CK tactics that should be reviewed.  
    - Identify the ATT&CK mitigations that provide similar capabilities as the security control.  Each mitigation comes with the list of ATT&CK (sub-)techniques that it is able to prevent its successful execution.  The ATT&CK tactics associated with these (sub-)techniques should be reviewed.
- Use any examples of threats cited in the control documentation to also narrow down the ATT&CK tactics to review.

#### Identify ATT&CK Techniques & Sub-techniques in Scope
- Review the description of each ATT&CK technique to determine if the control is able to mitigate the adversary behavior described in the technique.
- If the technique contains sub-techniques:
    - For each sub-technique, review its description and procedure examples to determine if the control is able to mitigate the behavior described.
    - Ensure the control supports the sub-technique platforms.
    - If this control is a protective control, the sub-technique Mitigations section can be especially useful in determining if this sub-technique would be prevented by this control.
    - If this control is a detective control, the sub-technique Detections section can be especially useful in determining if this sub-technique would be detected by this control.
- ATT&CK currently does not provide guidance on how to respond to (sub-)techniques.  Utilize the (sub-)technique description and
procedure examples to determine if it should be in scope.


## Step 4:  Score Assessments
After identifying the techniques and sub-techniques that are mappable to the control, use the [scoring rubric](./scoring.md) to score the effectiveness of the security function (protect, detect, respond) provided by the control in mitigating the behavior described by the ATT&CK entity.

## Step 5:  Create A Mapping
The previous steps enabled you to gather the information required to create a mapping file for a control according to the [mapping data format](./mapping_format.md).  Use the following guidelines to help you in the process of creating a mapping:
- The mapping format promotes producing mappings that are self-contained, enabling a reader of the mapping file to understand the basic functionality provided by the control and also the rational for selecting the ATT&CK techniques and sub-techniques it maps.  Use the various comment and description fields to communicate this information to readers.
- Populate the tags field with tags that will enable you to categorize the control in different ways, for example, by the resource(s) protected by the control.  The tags field can then be utilized to visualize multiple controls with the same tag.
    - Do not include ATT&CK information in the tag field.  This information is already present in the techniques field of the YAML mapping file and the visualization tools also support grouping controls by ATT&CK (sub-)techniques and therefore there is no need to duplicate the information in the tags field.
    - The list of valid tags is maintained in the valid_tags.txt file contained in the mappings folder for each platform.  (e.g. mappings/Azure/valid_tags.txt) file.  Consult this file first and reuse existing tags where it makes sense.  If you introduce a new tag, add it to this file.
- When scoring a control's effectiveness at mitigating a technique or sub-technique, you are encouraged to include a comment along with the score that explains your assessment.  Comments can be provided at multiple levels: top level, per technique or per group of sub-techniques.  Choose the level that makes the most sense for a control, for example:
    - If the score and rational applies to most techniques in scope of the mapping, rather than repeating the comment for each technique, add a comment using the top-level comment field of the mapping file.
    - If the score and rational applies to multiple groups of sub-techniques for a technique, provide a comment along with the score at the technique level.
    - If the score and rational is specific to a group of sub-techniques, provide a comment along with the score at the sub-techniques level.
- Use the [Mapping CLI](../tools/README.md) to validate and produce ATT&CK Navigator layers for the mappings that you produce.  The tool can be applied to an individual mapping file or a directory of mapping files.
