# Compliance-as-Code Pipeline

![Compliance Check](https://github.com/zainabthaa/compliance-as-code-pipeline/actions/workflows/compliance.yml/badge.svg)

A GitHub Actions pipeline that automatically checks Terraform infrastructure against real [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services) controls **before** it can be merged — blocking the pull request if a control is violated, and generating a human-readable compliance report and dashboard.

> **Note on the badge above:** it shows **failing**, on purpose. The `main` branch intentionally includes non-compliant demo infrastructure (a public S3 bucket, an SSH port open to the internet, a hardcoded database password, etc.) so the pipeline has something real to catch. The red badge is proof the enforcement actually works — see [Live Demo](#live-demo) below for a real pull request this pipeline blocked.

## The Problem

Compliance checks in most organizations happen too late — a security team manually reviews infrastructure changes after the fact, or a scanner runs periodically and finds issues after they're already deployed. This project takes the opposite approach: compliance rules are written **as code**, evaluated **automatically**, and enforced **before** infrastructure can ever be merged or deployed.

## How It Works

Terraform (.tf)
→ terraform plan
→ JSON plan output
→ Conftest evaluates Rego policies against the plan
→ Python generates a Markdown report + HTML dashboard
→ GitHub Actions fails the check if any control is violated
→ Branch protection blocks the merge


Every step runs automatically in GitHub Actions on every pull request, using **OIDC federation** to authenticate to AWS — no long-lived AWS credentials are stored anywhere in this repository or in GitHub Secrets for the AWS role itself.

## Controls Checked

| Control ID | Title | Severity |
|---|---|---|
| 2.1.1 | S3 Bucket Server-Side Encryption | High |
| 2.1.2 | S3 Bucket Versioning | Medium |
| 2.1.5.1 | S3 Block Public Access | Critical |
| 2.3 | RDS Publicly Accessible | Critical |
| 2.3.3 | RDS Storage Encryption | High |
| 5.2 | SSH Open to the Internet | Critical |
| 5.3 | RDP Open to the Internet | Critical |
| EBS-1 | EBS Volume Encryption | High |
| IAM-1 | IAM Wildcard Policy (`Action: "*"`, `Resource: "*"`) | High |
| SECRET-1 | Hardcoded Credentials in Terraform Source | Critical |

Controls prefixed with a number (e.g. `2.1.1`, `5.2`) map directly to the CIS AWS Foundations Benchmark. `EBS-1`, `IAM-1`, and `SECRET-1` are additional security best-practice checks not tied to a specific CIS control number.

Each `terraform/main.tf` resource has a matching **compliant** and **insecure** version, so the pipeline has real, concrete violations to catch — this isn't a toy example, every check runs against a real (though intentionally imperfect) `terraform plan`.

## Live Demo

A real pull request, blocked by this pipeline because required checks failed:

![Blocked PR](docs/blocked-pr.png)

The generated compliance dashboard for the current state of `main`:

![Dashboard](docs/dashboard.png)

## Tech Stack

| Purpose | Tool |
|---|---|
| Infrastructure as Code | Terraform |
| Policy engine | Open Policy Agent (OPA) + Rego |
| CI enforcement | Conftest + GitHub Actions |
| AWS authentication | OIDC federation (no stored credentials) |
| Framework reference | CIS AWS Foundations Benchmark |
| Reporting | Python (Markdown report + static HTML dashboard) |

## Repository Structure

compliance-as-code-pipeline/
├── terraform/ # Demo infrastructure (compliant + intentionally insecure)
├── policy/cis-aws/ # Rego policies, one file per AWS resource area
├── scripts/
│ ├── compliance_data.py # Shared logic: runs Conftest, parses results
│ ├── generate_report.py # Builds the Markdown report, sets CI pass/fail
│ └── generate_dashboard.py # Builds the static HTML dashboard
└── .github/workflows/
└── compliance.yml # The CI pipeline itself


## Running Locally

Requires: [Terraform](https://developer.hashicorp.com/terraform/install), [OPA](https://www.openpolicyagent.org/docs/latest/#running-opa), [Conftest](https://www.conftest.dev/install/), Python 3, and AWS credentials with S3/RDS/IAM/EBS read access (or your own AWS account, per the free-tier setup this project was built against).

```bash
cd terraform
terraform init
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json
cd ..

conftest test terraform/tfplan.json --policy policy/cis-aws

python3 scripts/generate_report.py       # creates compliance-report.md
python3 scripts/generate_dashboard.py    # creates dashboard.html
```

## What's Next

- IAM password policy, CloudTrail logging, EC2 unnecessary public IPs, KMS key rotation — additional CIS controls planned
- OSCAL-formatted output (NIST's machine-readable compliance standard)
- Multi-cloud policies (Azure/GCP) to demonstrate cross-cloud policy design

## Why This Project

Real compliance and security review in most organizations is manual, slow, and inconsistent. This project demonstrates translating actual regulatory/security requirements (CIS AWS Foundations Benchmark) into automated, enforceable code — and wiring that enforcement directly into the deployment pipeline itself, using the same OIDC-based, credential-free authentication pattern used in production CI/CD systems.