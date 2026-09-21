# Compliance-as-Code Pipeline

![Compliance Check](https://github.com/zainabthaa/compliance-as-code-pipeline/actions/workflows/compliance.yml/badge.svg)

A GitHub Actions pipeline that automatically checks Terraform infrastructure against real [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services) controls **before** it can be merged — blocking the pull request if a control is violated, and generating a human-readable compliance report and interactive dashboard.

> **Note on the badge above:** it shows **failing**, on purpose. The `main` branch intentionally includes both compliant and non-compliant demo infrastructure (a public S3 bucket next to a private one, an SSH port open to the internet next to a locked-down one, a hardcoded database password next to a securely-sourced one) so the pipeline has real, concrete violations to catch. The red badge is proof the enforcement actually works — see [Live Demo](#live-demo) below for a real pull request this pipeline blocked.

## The Problem

Compliance checks in most organizations happen too late — a security team manually reviews infrastructure changes after the fact, or a scanner runs periodically and finds issues after they're already deployed. This project takes the opposite approach: compliance rules are written **as code**, evaluated **automatically**, and enforced **before** infrastructure can ever be merged or deployed.

## How It Works

```mermaid
flowchart LR
    A["Pull request / push to main"] --> B["GitHub Actions starts"]
    B --> C["Log in to AWS<br/>(OIDC, no stored keys)"]
    C --> D["terraform plan<br/>(nothing is deployed)"]
    D --> E["Plan saved as JSON"]
    E --> F{"Conftest checks the plan<br/>against the Rego policies"}
    F --> G["Python builds<br/>report + dashboard"]
    G --> H{"Any violation?"}
    H -- "No" --> I["Check passes<br/>merge allowed"]
    H -- "Yes" --> J["Check fails<br/>merge blocked"]
    G --> K["Report + dashboard<br/>saved as artifacts"]
```

In words: the pipeline turns your Terraform into a plan, checks that plan against the rules, writes a report, and fails the check if any rule is broken. Branch protection then blocks the merge.

Every step runs automatically in GitHub Actions on every pull request, using **OIDC federation** to authenticate to AWS — no long-lived AWS credentials are stored anywhere in this repository or in GitHub Secrets for the AWS role itself.

Each control is checked against **every applicable resource in the plan**, not just reported as a single pass/fail — so a control can show, for example, one failing resource and one passing resource side by side, with the specific reason and remediation for the one that failed.

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
| IAM-1 | IAM Wildcard Policy (`Action` of `"*"` or `"service:*"` with `Resource: "*"`, for `Allow` statements) | High |
| SECRET-1 | Hardcoded Credentials in Terraform Source | Critical |

Controls prefixed with a number (e.g. `2.1.1`, `5.2`) map directly to the CIS AWS Foundations Benchmark. `EBS-1`, `IAM-1`, and `SECRET-1` are additional security best-practice checks not tied to a specific CIS control number.

Every `terraform/main.tf` resource has a matching **compliant** and **insecure** version, so the pipeline has real, concrete violations to catch — this isn't a toy example, every check runs against a real (though intentionally imperfect) `terraform plan`.

## Live Demo

A real pull request, blocked by this pipeline because a required check failed:

![Blocked PR](docs/blocked-pr.png)

The interactive compliance dashboard for the current state of `main` — click any control to see exactly which resource failed, why, and how to fix it:

![Dashboard](docs/dashboard.png)

## Setup

To run the pipeline on your own fork you need to configure three things.

**1. Repository variable `AWS_ROLE_ARN`**

The role the pipeline assumes, kept out of the code. In GitHub: **Settings → Secrets and variables → Actions → Variables → New repository variable**, name `AWS_ROLE_ARN`, value = your role's ARN.

**2. Repository secret `TF_VAR_compliant_db_password`**

The demo database password, under **Secrets** on the same page.

**3. Lock the role's trust policy to this repository**

Without this, another repository could assume your role. The role's trust policy should only allow your repo:

```json
{
  "Effect": "Allow",
  "Principal": { "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
    "StringLike":   { "token.actions.githubusercontent.com:sub": "repo:zainabthaa/compliance-as-code-pipeline:*" }
  }
}
```

## Tech Stack

| Purpose | Tool |
|---|---|
| Infrastructure as Code | Terraform |
| Policy engine | Open Policy Agent (OPA) + Rego |
| CI enforcement | Conftest + GitHub Actions |
| AWS authentication | OIDC federation (no stored credentials) |
| Framework reference | CIS AWS Foundations Benchmark |
| Reporting | Python (Markdown report + interactive HTML dashboard) |

## Repository Structure
```
compliance-as-code-pipeline/
├── terraform/                  # Demo infrastructure (compliant + intentionally insecure)
├── policy/cis-aws/             # Rego policies, one file per AWS resource area
├── scripts/
│   ├── compliance_data.py      # Shared logic: runs Conftest, reads the plan, builds pass/fail data
│   ├── generate_report.py      # Builds the Markdown report, sets CI pass/fail
│   └── generate_dashboard.py   # Builds the interactive HTML dashboard
├── .github/workflows/
│   └── compliance.yml          # The CI pipeline itself
├── Makefile                    # Shortcuts: make plan / check / all / clean
└── LICENSE                     # MIT
```

## Running Locally

Requires: [Terraform](https://developer.hashicorp.com/terraform/install), [OPA](https://www.openpolicyagent.org/docs/latest/#running-opa), [Conftest](https://www.conftest.dev/install/), Python 3, and AWS credentials with S3/RDS/IAM/EBS read access.

The [Makefile](Makefile) wraps every step, so you don't have to remember the commands:

```bash
make plan        # terraform plan -> terraform/tfplan.json (needs AWS login)
make check       # check the plan against the policies (Conftest)
make all         # write compliance-report.md and dashboard.html
open dashboard.html
```

| Command | What it does |
|---|---|
| `make help` | List all commands |
| `make plan` | Run Terraform and save the plan as JSON |
| `make check` | Run the policies on the plan and list failures |
| `make report` | Write `compliance-report.md` (exits with an error if any violation is found) |
| `make dashboard` | Write `dashboard.html` |
| `make all` | Report + dashboard (the dashboard is built even when violations are found) |
| `make clean` | Delete the generated files |

On the demo infrastructure, `make check` and `make report` finish with an error. That is expected: the insecure demo resources violate the controls, which is exactly what makes the CI check fail.

## What's Next

- **Expanding resources** — IAM password policy, CloudTrail logging, EC2 unnecessary public IPs, KMS key rotation — additional CIS controls planned
- OSCAL-formatted output (NIST's machine-readable compliance standard)
- Multi-cloud policies (Azure/GCP) to demonstrate cross-cloud policy design

## Why This Project

Real compliance and security review in most organizations is manual, slow, and inconsistent. This project demonstrates translating actual regulatory/security requirements (CIS AWS Foundations Benchmark) into automated, enforceable code — and wiring that enforcement directly into the deployment pipeline itself, using the same OIDC-based, credential-free authentication pattern used in production CI/CD systems.