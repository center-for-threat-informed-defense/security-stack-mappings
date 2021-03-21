# Scoring Rubric

This project provides three different categories: protect, detect and respond, for scoring the effectiveness of a security control's ability to mitigate the threats described in the [MITRE ATT&CK Enterprise matrix](https://attack.mitre.org/matrices/enterprise/).

Both techniques and (groups of) sub-techniques are scored (consult the [mapping format](mapping_format.md) for how this is represented) with the following guidelines for scoring a technique:
- If a technique does not support sub-techniques, its score should reflect the control's ability to mitigate the behavior described in the technique's description.  The technique's _Procedure Examples_ section should also be reviewed to better understand how adversaries have utilized this technique to ensure that score assessments are grounded in real-world occurrences of the technique.
- If a technique does support sub-techniques, the aggregate score of its sub-techniques should be included in the technique's score. 
    - For example, if the control provides Significant protection for most of the technique's sub-techniques along with its procedure examples, it should be scored as Significant.
    - If it only provides Significant protection for a minority of a technique's sub-techniques, then this should adversely affect the score of the technique, irrespective of how well it mitigates the technique's procedure examples.  The degree to which the technique's score is affected is left to the discretion of the assessor.

The following guidelines are for scoring sub-techniques:
- Typically the control's effectiveness at mitigating the behavior described by a sub-technique is scored as Partial or Significant.  If you are inclined to score a control's effectiveness at mitigating the behavior described by a sub-technique as Minimal, carefully consider whether this control would actually be a practical means of mitigating the sub-technique.  Often times, technically the control can mitigate the sub-technique but in the real-world it wouldn't be used for that purpose.  In that case, rather than including it in the mapping with a minimal score, the recommendation is to exclude it.
    - Note:  the Minimal score can and is often used to score at the technique level; a control can provide, for example, significant protection against a sub-technique of the technique while not providing protection for a majority of its remaining sub-techniques.  In this case, it is appropriate for the technique to be scored as Minimal.
- Sub-techniques of a technique that are specific to an operating system not supported by the platform should not adversely impact the score of the technique.
    - Example:  When scoring controls for the Azure platform, a majority of the sub-techniques for a particular technique are specific to the MacOS operating system.  The control being mapped does not support the MacOS operating system.  In that case, since the MacOS operating system has minimal support on the Azure platform, these sub-techniques should be excluded from consideration when assessing the effectiveness of the control.


The scoring rubric provides the following score values:
- **Minimal**:  The control provides minimum mitigation of the ATT&CK (sub-)technique.
- **Partial**:  The control provides partial mitigation of the ATT&CK (sub-)technique.
- **Significant**:  The control provides significant mitigation of the ATT&CK (sub-)technique.

In order to promote consistent assessments, the following scoring factors should be considered when assessing a control's mitigation capability.  This list of factors is only intended to illustrate some of the most common factors considered when scoring and is by no means exhaustive, contributions are welcome:
- **Coverage**
    - Assesses the control's ability to mitigate the behavior described in the description of the (sub-)technique while also considering the (sub-)technique's _Procedure Examples_ section to ensure the score assessment is grounded in real-world occurrences of the (sub-)technique. 
    - Coverage is a critical factor, typically if a control provides minimal coverage, its score is assessed as Minimal irrespective of other score factors.
- **Temporal**
    - Assesses how frequently the control operates.
        - Is it real-time?
        - Is it periodical? What's the period (minutes, hours, days)?
        - Is it triggered by an external event?  How often does the event occur?
- **Accuracy**
    - For detect controls, assesses the fidelity of the controls detection capability i.e. false positive/false negative rates.
    - A control may achieve a high accuracy score either from built-in intelligence that enables it to provide a low false-positive rate or the artifacts/behaviors that it detects do not appear frequently in the system and therefore naturally result in a low false-positive rate.



## Protect Scoring

The scoring rubric used to assess a security control's ability to prevent or minimize the impact of the execution of an ATT&CK (sub-)technique is presented below:  

| Score | Description | 
|------|------|
| **Minimal** | Low protect coverage factor irrespective of other score factors |
| **Partial** | Medium - high protect coverage factor <br />Temporal factor of hours/days |
| **Significant** | High protect coverage factor <br />Real-time, or near real-time (seconds, low minutes) temporal factor |

## Detect Scoring

The scoring rubric used to assess a security control's ability to detect the execution of an ATT&CK (sub-)technique is presented below:  

| Score | Description | 
|------|------|
| **Minimal** | Low detection coverage factor irrespective of other score factors | 
| **Partial** | Medium - high detection coverage factor <br />Suboptimal accuracy and/or temporal score |
| **Significant** | High detection coverage factor <br /> Low false-positive/false-negative rates <br />Real-time, or near real-time (seconds, low minutes) temporal factor |

## Respond Scoring

Respond scoring assesses a security control's ability to respond to the execution of an ATT&CK (sub-)technique.  The unique nature of this capability requires a different set of factors to consider when assessing its effectiveness:

- **Detection**:  An important factor in scoring the respond capability of a control is how well it is able to detect the behavior that it responds to.  Consequently, a low detection score for a control also adversely impacts any response capability it provides.
- **Type of response**: type of technical response provided by the control:
    - Data Enrichment/Forensics
        - Control provides more than basic alerting (basic alerting is considered default functionality of a detect control), typically enriching the data contained in an alert to provide the analyst improved situational awareness.
        <br/>Example:  Aggregates forensic data from third-party tools
    - Containment of an incident
        - Containment involves keeping the threat from growing or impacting other systems.
        - Minimizes the impact of an incident but requires additional mitigation action to be performed to completely mitigate the threat.
        <br/>Examples:  Quarantine file, Account Disable
    - Eradication
        - Mitigates the threat by removing it.
        <br/>Examples:  Force Account Password Change, Remove malware from storage, Terminate process and delete executable.
- **Integration**:  Supports integration with 3rd-party security tools to enrich the control's response capability.
- **Automation**:  Supports APIs that enable automating and scaling the response capability.


| Response Type | Minimal | Partial | Significant |
|------|------|------|------|
| Data Enrichment/Forensics | - Minimal detection score, irrespective of other score factors <br/> or <br/> - Partial detection score and minimal support for integrations and automation. |-  Partial/Significant detection score and <br/> - Significant 3rd-party integrations <br/> - Automation/API support | N/A, Data Enrichment/Forensics response type doesn't actually mitigate the threat so its maximum score is Partial.|
| Containment | - Minimal detection score, irrespective of other factors.| - Partial or Significant detection score and <br/> - Minimum/Partial support for 3rd party integrations <br/> - or No/Minimal Automation/API support | - Partial or Significant detection score and <br />- Provides significant support for platform and 3rd-party integrations and/or <br />-Supports automation/API |
| Eradication | - Minimal detection score, irrespective of other factors. | - Partial detection score and <br />- Minimal/Partial support for 3rd-party integrations and/or No/Minimal automation/API support |- Significant detection irrespective of other factors. <br />- Partial detection score and </br> - Provides significant support for platform and 3rd-party integrations <br /> - Supports automation/API|
