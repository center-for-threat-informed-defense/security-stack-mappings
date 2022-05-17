# Security Stack Mappings

This repository contains a collection of _native_ security controls mapped to MITRE ATT&CK® based on a common methodology and tool set. We aim to empower organizations with independent data on which _native_ security controls are most useful in defending against the adversary TTPs that they care about and establish a foundation for systematically mapping product security controls to ATT&CK. These mappings will allow organizations to make threat-informed decisions when selecting which native security capabilities to use.

## Get the Mappings

This project has produced mapping files for the following technology platforms, with more on the roadmap:

### Microsoft Azure

| [HTML Summary](https://center-for-threat-informed-defense.github.io/security-stack-mappings/Azure/README.html) | [YAML Mappings](mappings/Azure) | [ATT&CK Navigator Layers](mappings/Azure/layers) |
| -------------------------------------------------------------------------------------------------------------- | ------------------------------- | ------------------------------------------------ |

Released on June 29, 2021, these mappings cover the native security controls of Microsoft Azure Infrastructure as a Services for version 8.2 of MITRE ATT&CK. The following scoping decisions influenced the Azure mappings:
- ATT&CK Scope: This work is focused on ATT&CK (sub-)techniques included in the Enterprise domain v8; Mobile techniques are not covered. There is a follow-on project that will update the mappings to ATT&CK v9.
- Native Security Controls: This work focused on mapping the security controls produced by Microsoft or branded as Microsoft products. Third-party security controls available on the platform were excluded from analysis.
- Azure Security Benchmark: Most of the controls included in scope were derived from [Microsoft’s Azure Security Benchmark v2](https://docs.microsoft.com/en-us/security/benchmark/azure/overview) and our review of [Azure security documentation](https://docs.microsoft.com/en-us/azure/security/).
- Azure Defender for servers: This control was excluded from analysis due to its complexity and its inclusion within recent [MITRE ATT&CK Evaluations](https://attackevals.mitre-engenuity.org/enterprise/participants/microsoft/?adversary=carbanak_fin7).

### Amazon Web Services

| [HTML Summary](https://center-for-threat-informed-defense.github.io/security-stack-mappings/AWS/README.html) | [YAML Mappings](mappings/AWS) | [ATT&CK Navigator Layers](mappings/AWS/layers) |
| ------------------------------------------------------------------------------------------------------------ | ----------------------------- | ---------------------------------------------- |


Released on September 21, 2021, these mappings cover the native security controls of Amazon Web Services for version 9.0 of MITRE ATT&CK. The following scoping decisions influenced the AWS mappings:
- ATT&CK Scope: This work is focused on ATT&CK techniques and sub-techniques included in ATT&CK for Enterprise v9; Mobile techniques are not covered.
- Native Security Controls: This work focused on mapping the security controls produced by AWS or branded as AWS products. Third-party security controls available on the platform were excluded from analysis.
- The [AWS Security, Identity, & Compliance products](https://aws.amazon.com/products/security/?nc=sn&loc=2) page was used to source the list of controls included within scope of this mapping.
- Driven by Center participant interest, this effort also included mappings of security features of select, non-security services such as VPC, RDS, and S3.

### Google Cloud Platform

| [HTML Summary](https://center-for-threat-informed-defense.github.io/security-stack-mappings/GCP/README.html) | [YAML Mappings](mappings/GCP) | [ATT&CK Navigator Layers](mappings/GCP/layers) |
| ------------------------------------------------------------------------------------------------------------ | ----------------------------- | ---------------------------------------------- |

Released on June 28, 2022, these mappings cover the native security controls of Google Cloud Platform (GCP) for version 10 of MITRE ATT&CK. The following scoping decisions influenced the GCP mappings:
- ATT&CK Scope: This work is focused on ATT&CK (sub-)techniques included in the Enterprise domain v10; mobile techniques are not covered.
- Native Security Controls: This work focused on mapping the security controls produced by Google or offered as Google products. The selected controls are considered native to the platform, i.e., produced by the vendor themselves or third-party controls branded or acquired by the vendor. Third-party security controls offered in cloud marketplaces are considered out of scope and were excluded from analysis.
- Google Cloud Security: Most of the controls included in scope were derived from [Google Cloud Security Solutions]( https://cloud.google.com/solutions/security) and our review of [GCP security documentation]( https://cloud.google.com/docs/security).

## Supporting Resources

This project provides the following supporting resources:
- **[Use Cases](docs/use_cases.md)** - There are several use cases for applying the mapping files to advance the state-of-the-art and the state-of-the-practice in threat-informed defense.
- **[Methodology](docs/mapping_methodology.md)** – A methodology for using the mapping data format and scoring rubric to produce mapping files for security controls native to a technology platform.  By providing a methodology, we hope to encourage a consistent, best-practice approach to performing mappings that will make mappings more comparable to each other. It also encourages community mappings to be developed – including, potentially, by security vendors themselves.
- **[Scoring Rubric](docs/scoring.md)** - A scoring rubric that enables assessing the effectiveness of a security control native to a technology platform in mitigating the set of ATT&CK techniques that it has been mapped to.  This scoring rubric enables providing a score for each (sub-)technique included in a security control's mapping file.
- **[Mapping data format](docs/mapping_format.md)** - The specification of a YAML file that captures the mapping of a security control native to a technology platform to the set of ATT&CK techniques that it mitigates.
- **[Mapping Tool](tools/)** – A Python-based tool that enables validating and producing [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layers for mapping files.
- **[Releases](https://github.com/center-for-threat-informed-defense/security-stack-mappings/releases)** - A list of updates to this repository.

## Getting Involved

There are several ways that you can get involved with this project and help advance threat-informed defense:
- **Review the mappings, use them, and tell us what you think.**  We welcome your review and feedback on the mappings, our methodology, and resources.
- **Apply the methodology and share your security capability mappings.** We encourage organizations to apply our methodology to map the security capabilities of their products and we welcome mapping contributions.
- **Help us prioritize additional platforms to map.** Let us know what platforms you would like to see mapped to ATT&CK. Your input will help us prioritize how we expand our mappings.
- **Share your ideas.** We are interested in developing additional tools and resources to help the community understand and make threat-informed decisions in their risk management programs. If you have ideas or suggestions, we consider them as explore additional research projects.

## Questions and Feedback
Please submit issues for any technical questions/concerns or contact ctid@mitre-engenuity.org directly for more general inquiries.

## Notice
Copyright 2021 MITRE Engenuity. Approved for public release. Document number CT0019

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

This project makes use of ATT&CK®

[ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/)
