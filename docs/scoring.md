# Scoring Rubric

This project provides three different categories: prevent, detect and respond, for scoring the effectiveness of a security control's ability to mitigate the threats described in the [MITRE ATT&CK Enterprise matrix](https://attack.mitre.org/matrices/enterprise/).

Both techniques and (groups of) sub-techniques are scored (consult the [mapping format](mapping_format.md) for how this is represented) with the following guidelines for scoring a technique:
  - If a technique does not support sub-techniques, its score should reflect the technique's ability mitigate the behavior described in the _Procedure Examples_ section of the technique's description.  This ensures that score assessments are grounded in real-world occurrences of the technique.
  - If a technique does support sub-techniques, then the aggregate score of its sub-techniques should be considered when assessing the technique's score. 
    - For example, if the control provides Significant protection for most of the technique's sub-techniques along with its procedure examples, it should be scored as Significant.
    - If it only provides a Significant protection for a small number of a technique's sub-techniques, then this should adversely affect the score of the technique, irrespective of how well it mitigates the technique's procedure examples.  The degree to which the technique's score is affected is left to the discretion of the assessor.

The scoring rubric provides the following score values:
- **Minimal**:  The control provides minimum protection for the ATT&CK (sub-)technique.
- **Partial**:  The control provides partial protection for the ATT&CK (sub-)technique.
- **Significant**:  The control provides significant protection for the ATT&CK (sub-)technique.

In order to promote consistent assessments, the following scoring factors should be considered when assessing a control's mitigation capability.  This list of factors is only intended to illustrate some of the most common factors considered when scoring and is by no means exhaustive, contributions are welcome:
- **Coverage**
    - Assesses the control's ability to mitigate the behavior described in the (sub-)technique with respect to the variations in its execution as described in its _Procedure Examples_ section of its ATT&CK page.
    - Coverage is a critical factor, typically a control provides minimal coverage, its score is assessed as Minimal irrespective of other score factors.
- **Temporal**
    - Assesses how frequently the control operates.
        - Is it real-time?
        - Is it periodical? What's the period (minutes, hours, days)?
        - Is it triggered by an external event?  How often does the event occur?
- **Accuracy**
    - For detect controls, assesses the fidelity of the controls detection capability i.e. false positive/false negative rates.
    - A control may achieve a high accuracy score either from built-in intelligence that enables it to provide a low false-positive rate or the artifacts/behaviors that it detects do not appear frequently in the system and therefore naturally result in a low false-positive rate.



## Prevent Scoring

The scoring rubric used to assess a security control's ability to prevent the execution of an ATT&CK (sub-)technique is presented below.  

| Score | Description | 
|------|------|
| **Minimal** | Low prevent coverage factor irrespective of other score factors | 
| **Partial** | Medium - high prevent coverage factor <br />Temporal factor of hours/days | 
| **Significant** | High prevent coverage factor <br />Real-time, or near real-time (seconds, low minutes) temporal factor |

## Detect Scoring

The scoring rubric used to assess a security control's ability to detect the execution of an ATT&CK (sub-)technique is presented below.  

| Score | Description | 
|------|------|
| **Minimal** | Low detection coverage factor irrespective of other score factors | 
| **Partial** | Medium - high detection coverage factor <br />Suboptimal accuracy and/or temporal score |
| **Significant** | High detection coverage factor <br /> Low false-positive/false-negative rates <br />Real-time, or near real-time (seconds, low minutes) temporal factor |

## Respond Scoring

The unique nature of response controls requires a different set of factors to consider when assessing its effectiveness:

- **Detection**:  An important factor in scoring the respond capability of a control is how well it is able to detect the behavior that it responds to.  Consequently, a low detection score for a control also adversely impacts any response capability adversely impacts its response score.
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
- **Integration**:  Supports the integration with 3rd-party security tools to enrich the control's response capability.
- **Automation**:  Supports scaling the response capability to many (compromised) resources via automation.


| Response Type | Minimal | Partial | Significant |
|------|------|------|------|
| Data Enrichment/Forensics | - Minimal detection score, irrespective of other score factors <br/> or <br/> - Partial detection score and minimal support for integrations and automation. |-  Partial/Significant detection score and <br/> - Significant 3rd-party integrations <br/> - Automation/API support | N/A, Data Enrichment/Forensics response type doesn't actually mitigate the threat so its maximum score is Partial.|
| Containment | - Minimal detection score, irrespective of other factors.| - Partial or Significant detection score and <br/> - Minimum/Partial support for 3rd party integrations <br/> - and/or No/Minimal Automation/API support | - Partial or Significant detection score and <br />- Provides significant support for platform and 3rd-party integrations and/or <br />-Supports automation/API |
| Eradication | - Minimal detection score, irrespective of other factors. | - Partial detection score and <br />- Minimal/Partial support for 3rd-party integrations and/or No/Minimal automation/API support |- Significant detection irrespective of other factors. <br />- Partial detection score and </br> - Provides significant support for platform and 3rd-party integrations <br /> - Supports automation/API|
