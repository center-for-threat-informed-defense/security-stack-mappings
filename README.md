# Security Stack Mappings

## What is the Security Stack Mappings project?

The aim of this project is to help organizations better understand what _native_ security controls are available on technology platforms to prevent, detect and respond to common threats to workloads running on the platform.  It achieves this by mapping security capabilities that are available as part of these platforms to the [ATT&CK techniques](https://attack.mitre.org/matrices/enterprise/) that they can prevent, detect, or respond to. This will allow organizations that adopt these platforms to make threat-informed decisions when selecting which native security capabilities to use to protect their workloads.  

This project provides the following:
- **[Mapping data format](docs/mapping_format.md)** - The specification of a YAML file that captures the mapping of a security control native to a technology platform to the set of ATT&CK techniques that it mitigates.
- **[Scoring Rubric](docs/scoring.md)** - A scoring rubric that enables assessing the effectiveness of a security control native to a technology platform in mitigating the set of ATT&CK techniques that it has been mapped to.  This scoring rubric enables providing a score for each (sub-)technique included in a security control's mapping file.
- **[Methodology](docs/mapping_methodology.md)** – A methodology for using the mapping data format and scoring rubric to produce mapping files for security controls native to a technology platform.  By providing a methodology, we hope to encourage a consistent, best-practice approach to performing mappings that will make mappings more comparable to each other. It also encourages community mappings to be developed – including, potentially, by security vendors themselves.
- **[Mapping Tool](tools/)** – A Python-based tool that enables validating and producing [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layers for mapping files.

We envision that the community can use the functionality produced by this project to produce mappings for various technology platforms.  To encourage this endeavor, this project has produced mapping files for the following technology platforms:
- [Microsoft Azure](mappings/Azure/)

## Getting Involved

There are several ways that you can get involved with this project and help advance threat-informed defense.

First, review the mappings, use them, and tell us what you think. We welcome your review and feedback on the Azure cloud mappings, our methodology, and resources.

Second, we are interested in applying our methodology to other technology platforms. Let us know what platforms you would like to see mapped to ATT&CK. Your input will help us prioritize how we expand our mappings.

Finally, we are interested developing additional tools and resources to help the community understand and make threat-informed decisions in their risk management programs. Share your ideas and we will consider them as we explore additional research projects.

## Questions and Feedback
Please submit issues for any technical questions/concerns or contact ctid@mitre-engenuity.org directly for more general inquiries.

Also see the guidance for contributors if are you interested in contributing or simply reporting issues.

## Notice
Copyright 2021 MITRE Engenuity. Approved for public release. Document number XXXXX

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

This project makes use of ATT&CK®

[ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/)