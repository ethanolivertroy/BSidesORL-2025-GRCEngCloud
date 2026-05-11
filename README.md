# GRC Engineering in the Cloud: BSides Orlando 2025

Talk artifacts from *GRC Engineering in the Cloud*, presented at BSides Orlando 2025.

## Contents

- **[`GRC-Engineering-in-the-Cloud.pdf`](GRC-Engineering-in-the-Cloud.pdf)**: slide deck from the talk.
- **[`gcp-fedramp-collector/`](gcp-fedramp-collector/)**: the demo tool. A read-only Python collector and analyzer that pulls GCP configuration and checks it against a FedRAMP 20x pilot-era KSI snapshot. I demoed it as an auditor workflow, then made the point that the same idea can run as an internal GRC function.

## FedRAMP 20x pilot-era caveat

This repo is a talk artifact, not current FedRAMP 20x guidance. I wrote the collector during the FedRAMP 20x pilot period, around **September 26, 2025**, against the public material available then. FedRAMP is a GSA program. This demo uses FedRAMP 20x because that was the cloud compliance change happening during the talk window.

FedRAMP's public docs continued changing after that point. There is no exact September 26 commit in the visible [`FedRAMP/docs`](https://github.com/FedRAMP/docs) history; useful anchors around that date include the September 11, 2025 pilot/VDR regeneration commit [`34a080e`](https://github.com/FedRAMP/docs/commit/34a080e), the October 7, 2025 impact-level/generator update [`ff2a9b3`](https://github.com/FedRAMP/docs/commit/ff2a9b3), and the November 5, 2025 Phase Two KSI draft commit [`b79d0a9`](https://github.com/FedRAMP/docs/commit/b79d0a9).

Do not treat the KSI mappings, scoring, or findings here as accurate for current FedRAMP 20x work without checking them against current FedRAMP material. The point that still matters is simpler: pull cloud configuration from APIs, map it to the control question, and produce output someone can inspect.

## Talk premise

GRC engineering is engineering-mindset problem-solving applied to governance, risk, compliance, assessment, and assurance work. It is not a job title to argue about, and it is not a vendor category. It is what you end up doing when you stop asking *"what screenshot does the auditor want?"* and start asking *"what API can prove this control is actually working?"*

#AbolishScreenshots. Most of what an auditor manually collects is one command.

The collector is one version of that idea. It runs read-only against a GCP project, maps configuration to a pilot-era FedRAMP 20x KSI snapshot, and emits a report you can inspect. That last part matters. If a GRC platform is going to test controls for you, someone still has to test the GRC automation. Someone has to be able to read the code.

## FedRAMP 20x and RMF Changes

The talk changed in its final week because two separate things landed at about the same time.

The first was FedRAMP 20x, a GSA/FedRAMP effort to rethink cloud authorization around key security indicators, automation, and evidence that can be tested directly. That is why the demo maps GCP configuration to a FedRAMP 20x pilot-era KSI snapshot.

The second was the Department of War's [Cybersecurity Risk Management Construct](https://dodcio.defense.gov/In-the-News/Article/4367432/department-of-war-announces-new-cybersecurity-risk-management-construct/), which is a separate defense cyber risk/RMF modernization effort. It is not part of FedRAMP and it is not governed by GSA. It mattered to the talk because it reinforced the same broader pressure: static checklists and manual process are giving way to automation, critical controls, DevSecOps, and evidence that can be continuously produced.

Those two changes are not technically related programs. They just pointed at the same GRC engineering lesson from different sides of government: stop treating compliance as screenshot collection. Treat it as an evidence pipeline. FedRAMP 20x is the example in this repo, not the only framework worth automating against. Fork this, gut it, rewrite it for whatever framework you actually live in.

If you came to the talk: thanks for being there.

## License

[MIT](LICENSE). Do whatever you want with it.
