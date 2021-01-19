# Cloud Security Stack Mappings

## What is the Cloud Security Stack Mappings project?

The aim of this project is to advance the state of the practice in securing cloud workloads by helping organizations better understand how to prevent, detect and mitigate common cloud threats using the security controls native to cloud platforms.

This project maps security capabilities available as part of cloud platforms to the ATT&CK cloud techniques that they can detect, protect, or respond to. This will allow end users of cloud platforms to make threat-informed decisions about which capabilities to use and how to use. The principal objectives of this project are:
- **Prototype a methodology to map cloud security offerings into ATT&CK** – Prototyping and publishing this methodology will provide the community with a reusable way to use ATT&CK to determine the capabilities of cloud security offerings.
- **Map Microsoft Azure security offerings into ATT&CK** – These mappings will provide an example of how to use the prototyped methodology to map cloud security offerings into ATT&CK and valuable information on the ability of these offerings to protect, detect, and respond to cloud techniques in ATT&CK.

## Background

As the usage of cloud infrastructure has exploded and, correspondingly, attackers start to target that infrastructure, cloud providers have worked to build security in by providing numerous security capabilities in the cloud offerings to prevent or detect attacks. While laudable, this is very similar to the state that the on-prem security space was in as endpoint and post-compromise detection exploded -- there are many exciting security capabilities, but also uncertainty about what specific tools do and do not help address.

Luckily, with the development of the ATT&CK cloud platforms, we’re already ahead of the game.  [ATT&CK Cloud](https://attack.mitre.org/matrices/enterprise/cloud/)  provides a well-formed categorization of the TTPs that adversaries use to attack cloud infrastructures, and can utilized to understand what cloud security capabilities do, just like what has been accomplished with endpoint.

The most immediate impact of this project will be on end users of Microsoft Azure (the prototype platform). Those users will have a better understanding of what security capabilities are available to them and what each of those capabilities can provide. That can be used to inform configuration decisions, determine which capabilities to purchase, or help understand gaps in defenses.

Longer-term, by publishing the methodology used to perform the mappings, other cloud platforms or even other security stacks can be mapped using the same approach. Providing a consistent, best-practice approach to perform mappings will make mappings more comparable to each other. Providing an approach also encourages community mappings to be developed – including, potentially, by security vendors themselves.
