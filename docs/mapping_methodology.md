# Mapping Methodology

This document describes the methodology used to map security controls native to a cloud platform to MITRE ATT&CK&copy; and aims to provide the community a reusable method of using ATT&CK to determine the capabilities of cloud security offerings.

MITRE ATT&CK is a globally-accessible knowledge base of the tactics and techniques utilized my malicious cyber actors (MCA) based on real-world observations. The ATT&CK knowledge base represents MCA goals as tactics and the specific behaviors employed by MCAs to achieve those goals (how) as techniques and sub-techniques.   The methodology described below, utilizes the information in the ATT&CK knowledge base and its underlying data model to understand, assess and record the real-world threats that security controls native to a cloud platform are able to mitigate.

The methodology consists of the following steps:
1. **Identify Platform Security Controls** - Identify the *native* security controls available on a cloud platform.
1. **Security Control Review** - For each identified control, understand the security capabilities it provides.
1. **Identify Mappable ATT&CK Techniques & Sub-techniques** - Identify the ATT&CK techniques and sub-techniques mappable to the control.
1. **Score Assessment** - Assess the effectiveness of the type of protection the control provides for the identified ATT&CK techniques and sub-techniques.
1. **Create a Mapping** - Creating a mapping based on the information gathered from the previous steps. 

## Step 1:  Identify Platform Security Controls
Cyber security has emerged as an essential component of cloud platforms, and consequently cloud providers tend to offer a variety of documentation on the security capabilities of their platform.  Peruse the cloud platform documentation (e.g. security reference architectures, security benchmarks, security documentation of various cloud services, etc.) to identify the security controls offered by the platform for protecting workloads on the platform.  Keep the following in mind while selecting controls:
- The scope of the controls mapped by this project are the technical control types and do not include administrative or physical control types.
- The selected controls should be native to the platform, i.e. produced by the cloud vendor themselves or third-party controls branded by the cloud provider.  Thirty-party security controls offered in cloud marketplaces are considered out of scope.
- Cloud services often provide individual The scope of controls mapped tend to be stand-alone

## Step 2:  Security Control Review
For each identified security control, consult the documentation for the control made available by the cloud provider to understand its capabilities.  Gather the following facts about the security control that will later help in mapping the control to the set of ATT&CK techniques and sub-techniques it is able to mitigate:
- Category of security function provided by the control:
    - Prevent:  reduces the likelihood of the occurrence of a cybersecurity event.
    - Detect:   identifies the occurrence of a cybersecurity event.
    - Respond:  mitigates the impact of a cybersecurity event.
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
    - If this control is a preventative control, the sub-technique Mitigations section can be especially useful in determining if this sub-technique would be prevented by this control.
    - If this control is a detective control, the sub-technique Detections section can be especially useful in determining if this sub-technique would be detected by this control.


## Step 4:  Score Assessments
After identifying the techniques and sub-techniques that are mappable to the control, use the [scoring rubric](docs/scoring.md) to score the effectiveness of the security function (prevent, detect, respond) provided by the control in mitigating the behavior described by the ATT&CK entity.
-  For a given technique, start with scoring each sub-technique that is mappable to the control.  
    - Typically the control's effectiveness at mitigating the behavior described by a sub-technique is scored as Partial or Significant.  If you are inclined to score a control's effectiveness at mitigating the behavior described by a sub-technique as Minimal, carefully consider whether this control would actually be a practical means of mitigating the sub-technique.  Often times, technically the control can mitigate the sub-technique but in the real-world it wouldn't be used for that purpose.  In that case, rather than including it in the mapping with a minimal score, the recommendation is to exclude it.
- After scoring each sub-technique for the technique, proceed to provide a score for the overall technique, considering the following:
    - The technique's score should reflect not only the control's ability to mitigate its sub-techniques but also the overall real-world manifestations of the technique as described by the technique's procedure examples.
    - The Minimal score can and is often used to score at the technique level; a control can provide, for example, significant protection against a sub-technique of the technique while not providing protection for a majority of its remaining sub-techniques.  In this case, it is appropriate for the technique to be scored as Minimal.
    - Sub-techniques of a technique that are specific to an operating system not supported by the platform should not adversely impact the score of the technique.
        - Example:  When scoring controls for the Azure platform, a majority of the sub-techniques for a particular technique are specific to the MacOS operating system.  The control being mapped does not support the MacOS operating system.  In that case, since the MacOS operating system has minimal support on the Azure platform, these sub-techniques should be excluded from consideration when assessing the effectiveness of the control.


## Step 5:  Create A Mapping
The previous steps enabled you to gather the information required to create a mapping file for a control according to the [mapping data format](docs/mapping_format.md).  Use the following guidelines to help you in the process of create a mapping:
- Populate the tags field with tags that will enable you to categorize the control in different ways, for example, by the resource(s) protected by the control.  The tags field can then be utilized to visualize multiple controls with the same tag.
    - Do not include ATT&CK information in the tag field.  This information is already present in the techniques field of the YAML mapping file and the visualization tools also support grouping controls by ATT&CK (sub-)techniques and therefore there is no need to duplicate the information in the tags field.
    - The list of valid tags is maintained in the [valid_tags.txt](tools/config/valid_tags.txt) file.  If you introduce a new tag, add it to this file.

- Validate the mapping file using the ...