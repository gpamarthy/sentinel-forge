# Security policy

## Supported versions

Pre-1.0, only the latest tagged release receives security fixes.

## Reporting a vulnerability

**Do not file public issues for security problems.**

Email a description and reproduction to the maintainer. Expect an acknowledgement within 72 hours and a fix or mitigation plan within 14 days for issues that can be reproduced.

If no response in 14 days, you are free to disclose publicly.

## Scope

In scope:

- Vulnerabilities in sentinel-forge itself (RCE in rule evaluator, injection in report rendering, path traversal in output)
- Rule misfires that disclose data they should not (e.g. unredacted secrets in a manager summary)
- Mishandling of AWS source credentials when fetching findings

Out of scope:

- Vulnerabilities or misconfigurations in the AWS account whose findings are being analyzed. Those are the findings the tool is built to surface.
- Vulnerabilities in `pydantic`, `rich`, `boto3`, or other upstream dependencies. Report to the respective project.
- False positives or false negatives in detection rules. Open a feature request to tune the rule rather than a security report.

## Operator note

`sentinel-forge` is a defensive, read-only tool. It does not modify AWS resources or attempt remediation. The bundled sample corpus is safe to explore offline.
