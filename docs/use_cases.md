# Use Cases

This document describes basic use cases for Security Stack Mappings to ATT&CK. These use cases are expressed as user stories, and a short exploration of how a user story may be achieved follows each story.

## Use Cases — as a user of the Security Stack Mappings to ATT&CK...

### 1. I want to determine the (sub-)technique coverage of a control or set of controls

With control mappings implemented at a (sub-)technique level, this is as simple as following the mappings from the control(s) to the associated (sub-)techniques. Additionally, ATT&CK Navigator integration will easily support visualizations of such coverage.

In the context of this project, a mapping from a control to a (sub-)technique includes a score that communicates the effectiveness of the control in mitigating the (sub-)technique.  Additionally, most scores include comments describing the rational for assigning a particular score that should allow you to tailor the score to your environment.

For example, a particular control that detects threats to a database-as-a-service (DBaaS) offering may be scored as Minimal detection because its detection does not detect threats to databases installed on infrastructure-as-a-service (IaaS) components.  But in your environment, you may only be using the DBaaS offering; in that case you may want to consider adjusting the score of the control from Minimal to Partial or Significant to reflect the improved coverage with respect to your environment.

### 2. I want to know what security controls to select/implement in order to mitigate a specific set of (sub-)techniques

This is essentially the reverse direction of [use case 1](##1-i-want-to-determine-the-sub-technique-coverage-of-a-control-or-set-of-controls). 
This project produces an ATT&CK Navigator layer per platform, located in the `layers\platform.json` file, that aggregates the ATT&CK coverage of all the controls mapped for the platform into a single layer.  These layer files provide the reverse mapping of the information contained in a mapping file; rather than mapping a control to the set of (sub-)techniques that it mitigates, it provides a mapping for each (sub-technique) to the set of controls that mitigate it.  Use this layer file to search for the set of (sub-)techniques and the corresponding controls that provide a mitigation.

Additionally, this information can be visualized via the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).  Use your mouse to hover over a (sub-)technique in the tool and the list of controls that mitigate the (sub-technique) will be provided in the tooltip.

Because (sub-)techniques can map to multiple controls, it is likely that there will be multiple combinations of controls which could mitigate the (sub-)techniques. Given a way of ranking the possible solutions (e.g. minimize the number of controls, maximize the baseline-impact of controls) a dynamic programming algorithm can be implemented to determine the optimal set of controls required to mitigate the (sub-)techniques. 

### 3. I want to determine what security controls I can use to defend against a given group or software.

Groups and Software in ATT&CK are mapped to techniques. Therefore, this use case can be achieved by reviewing the set of (sub-)techniques that are associated with the group or software of interest and then exploring the set of security controls that mitigate those techniques. This then resolves to an extension of [use case 2](#2-i-want-to-know-what-security-controls-to-selectimplement-in-order-to-mitigate-a-specific-set-of-sub-techniques), where the set of (sub-)techniques is those associated with the software or group of interest. 

Additionally, this information can be visualized via the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/). Load the Navigator layer for the control mappings of interest and then filter the layer by the group or software of interest to see just the (sub-)techniques of interest and their security control mappings. 

## Additional Use Cases
Do you have additional use cases that we haven't thought of?  We'd love to hear about them, please share your ideas by submitting an issue or contacting ctid@mitre-engenuity.org.
