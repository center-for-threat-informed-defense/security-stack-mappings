# Cloud Security Stack Mappings

## What is the Cloud Security Stack Mappings project?

The aim of this project is to help organizations better understand what native security controls are available on cloud platforms to prevent, detect and mitigate common cloud threats to their cloud workloads.  It achieves this by mapping security capabilities that are available as part of these platforms to the [ATT&CK techniques](https://attack.mitre.org/matrices/enterprise/) that they can prevent, detect, or respond to. This will allow organizations that adopt cloud platforms for their workloads to make threat-informed decisions when selecting which native security capabilities to use to protect their workloads. 

This project provides the following:
- **[Mapping data format](docs/mapping_format.md)** - The specification of a YAML file that captures the mapping of a security control native to a cloud platform to the set of ATT&CK techniques that it offers protection.
- **[Scoring Rubric](docs/scoring.md)** - A scoring rubric that enables assessing how effective a security control native to a cloud platform protects against the set of ATT&CK techniques that it is mapped to.  This scoring rubric enables providing a score for each technique that the security control is mapped to.
- **[Methodology](docs/mapping_methodology.md)** – A methodolgy for using the mapping data format and scoring rubric to produce mapping files for security controls native to a cloud platform.  By providing a methodology, we hope to encourage a consistent, best-practice approach to performing mappings that will make mappings more comparable to each other. It also encourages community mappings to be developed – including, potentially, by security vendors themselves.
- **[Visualization Tool](tools/)** – A Python-based visualization tool that enables producing a visualization of a mapping file as ATT&CK Navigator layers.

We envision that the community can use the functionality produced by this project to produce mapping files for various cloud platforms or even other security stacks.  To encourage this endeavor, this project has produced mapping files for the following cloud platforms:
- [Microsoft Azure](mappings/Azure/)

## Background

As the usage of cloud infrastructure has exploded and, consequently, draw the attention of malicious cyber actors, cloud providers have worked diligently to build security into their cloud platforms by providing numerous security capabilities native to their platforms that prevent, detect or respond to attacks. While laudable, this is very similar to the state that the on-prem security space was in as endpoint and post-compromise detection exploded -- there are many exciting security capabilities, but also uncertainty about what specific tools do and do not help address.

Luckily, with the development of the ATT&CK cloud platforms, we’re already ahead of the game.  [ATT&CK Cloud](https://attack.mitre.org/matrices/enterprise/cloud/)  provides a well-formed categorization of the TTPs that adversaries use to attack cloud infrastructures, and can be utilized to understand what cloud security capabilities do, just like what has been accomplished with endpoint.

This project leverages the advancements made in codifying attacker behavior, provided by the ATT&CK knowledge base, to produce artificats the help organizations better understand what security capabilities are available natively on cloud platforms and what each of those capabilities can provide. That can be used to inform configuration decisions, determine which capabilities to purchase, or help understand gaps in defenses.
