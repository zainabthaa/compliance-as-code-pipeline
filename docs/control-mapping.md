# Control mapping

Generated from `controls/controls.json` by `scripts/generate_mapping_doc.py`. Do not edit by hand.

How to read this:

- **Control ID:** a numeric ID (like 2.2.3) is a real CIS AWS Foundations Benchmark v5.0.0 recommendation number, used only when this check is a direct match for it. An ID like S3-ENC-1 is a project ID for a check with no equivalent CIS recommendation (or only a related one).
- **CIS AWS** is the closest recommendation in the CIS AWS Foundations Benchmark v5.0.0, taken from the benchmark document. *direct* means the same requirement, *related* means overlapping but not identical, *none* means the benchmark has no such recommendation.
- **NIST 800-53** is Rev 5. Where AWS Security Hub documents an equivalent control, its related requirements were used (base controls only, enhancements omitted). Otherwise the mapping is author-assigned and says so.
- **ISO 27001** is 2022 Annex A. These are author-assigned by control intent and indicative only. The ISO standard itself is paywalled and no official crosswalk was used.
- A mapping shows which requirement a check *supports*. It is not a claim that passing the check makes you compliant.

## Summary

| Control | Title | CIS AWS v5.0.0 | NIST 800-53 Rev 5 | ISO 27001:2022 |
|---|---|---|---|---|
| S3-ENC-1 | S3 Bucket Server-Side Encryption | no matching recommendation | SC-13, SC-28 | A.8.24 |
| S3-VER-1 | S3 Bucket Versioning | no matching recommendation | CP-6, CP-9, CP-10 | A.8.13 |
| 2.1.4 | S3 Block Public Access | 2.1.4 | AC-3, AC-4, AC-6, SC-7 | A.5.15, A.8.3 |
| 2.2.1 | RDS Storage Encryption | 2.2.1 | SC-13, SC-28 | A.8.24 |
| 2.2.3 | RDS Publicly Accessible | 2.2.3 | AC-4, SC-7 | A.8.20, A.8.22 |
| 5.3 | Admin Ports (SSH/RDP) Open to the Internet - IPv4 | 5.3 | AC-4, CM-7, SC-7 | A.8.20, A.8.22 |
| 5.4 | Admin Ports (SSH/RDP) Open to the Internet - IPv6 | 5.4 | AC-4, CM-7, SC-7 | A.8.20, A.8.22 |
| EBS-1 | EBS Volume Encryption | 5.1.1 (related match) | SC-13, SC-28 | A.8.24 |
| IAM-1 | IAM Wildcard Policy | 1.15 (related match) | AC-2, AC-3, AC-5, AC-6 | A.5.15, A.8.2 |
| SECRET-1 | Hardcoded Credentials | no matching recommendation | IA-5, IA-5(7) | A.5.17, A.8.4 |

## Detail and basis

### S3-ENC-1 — S3 Bucket Server-Side Encryption

- **CIS:** none
  - S3 encryption at rest is not a recommendation in v5.0.0.
- **NIST 800-53 Rev 5:** SC-13 Cryptographic Protection; SC-28 Protection of Information at Rest
  - Basis: AWS Security Hub control S3.17 (related requirements); base controls only, enhancements omitted; S3.17 is the KMS variant, so this is a related mapping
- **ISO 27001:2022:** A.8.24 Use of cryptography
  - Basis: Author-assigned by control intent; indicative only (no official crosswalk used)

### S3-VER-1 — S3 Bucket Versioning

- **CIS:** none
  - S3 versioning is not a recommendation in v5.0.0 (2.1.2 there is MFA Delete).
- **NIST 800-53 Rev 5:** CP-6 Alternate Storage Site; CP-9 System Backup; CP-10 System Recovery and Reconstitution
  - Basis: AWS Security Hub control S3.14 (related requirements); base controls only, enhancements omitted
- **ISO 27001:2022:** A.8.13 Information backup
  - Basis: Author-assigned by control intent; indicative only (no official crosswalk used)

### 2.1.4 — S3 Block Public Access

- **CIS 2.1.4** (direct): Ensure that S3 is configured with 'Block Public Access' enabled
- **NIST 800-53 Rev 5:** AC-3 Access Enforcement; AC-4 Information Flow Enforcement; AC-6 Least Privilege; SC-7 Boundary Protection
  - Basis: AWS Security Hub control S3.8 (related requirements); base controls only, enhancements omitted
- **ISO 27001:2022:** A.5.15 Access control; A.8.3 Information access restriction
  - Basis: Author-assigned by control intent; indicative only (no official crosswalk used)

### 2.2.1 — RDS Storage Encryption

- **CIS 2.2.1** (direct): Ensure that encryption-at-rest is enabled for RDS instances
- **NIST 800-53 Rev 5:** SC-13 Cryptographic Protection; SC-28 Protection of Information at Rest
  - Basis: AWS Security Hub control RDS.3 (related requirements); base controls only, enhancements omitted
- **ISO 27001:2022:** A.8.24 Use of cryptography
  - Basis: Author-assigned by control intent; indicative only (no official crosswalk used)

### 2.2.3 — RDS Publicly Accessible

- **CIS 2.2.3** (direct): Ensure that RDS instances are not publicly accessible
- **NIST 800-53 Rev 5:** AC-4 Information Flow Enforcement; SC-7 Boundary Protection
  - Basis: AWS Security Hub control RDS.2 (related requirements); base controls only, enhancements omitted
- **ISO 27001:2022:** A.8.20 Networks security; A.8.22 Segregation of networks
  - Basis: Author-assigned by control intent; indicative only (no official crosswalk used)

### 5.3 — Admin Ports (SSH/RDP) Open to the Internet - IPv4

- **CIS 5.3** (direct): Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports
  - Covers the IPv4 range 0.0.0.0/0. The benchmark's administration ports include SSH (22) and RDP (3389).
- **NIST 800-53 Rev 5:** AC-4 Information Flow Enforcement; CM-7 Least Functionality; SC-7 Boundary Protection
  - Basis: AWS Security Hub EC2.13 (port 22) related requirements, base controls only; applied to RDP (3389) by analogy because the Security Hub page for EC2.14 lists no NIST mapping
- **ISO 27001:2022:** A.8.20 Networks security; A.8.22 Segregation of networks
  - Basis: Author-assigned by control intent; indicative only (no official crosswalk used)

### 5.4 — Admin Ports (SSH/RDP) Open to the Internet - IPv6

- **CIS 5.4** (direct): Ensure no security groups allow ingress from ::/0 to remote server administration ports
  - Covers the IPv6 range ::/0. The benchmark's administration ports include SSH (22) and RDP (3389).
- **NIST 800-53 Rev 5:** AC-4 Information Flow Enforcement; CM-7 Least Functionality; SC-7 Boundary Protection
  - Basis: Same mapping as 5.3 (IPv6 variant of the same requirement)
- **ISO 27001:2022:** A.8.20 Networks security; A.8.22 Segregation of networks
  - Basis: Author-assigned by control intent; indicative only (no official crosswalk used)

### EBS-1 — EBS Volume Encryption

- **CIS 5.1.1** (related): Ensure EBS volume encryption is enabled in all regions
  - CIS 5.1.1 is the account-level default-encryption setting; this control checks each volume.
- **NIST 800-53 Rev 5:** SC-13 Cryptographic Protection; SC-28 Protection of Information at Rest
  - Basis: AWS Security Hub control EC2.3 (related requirements); base controls only, enhancements omitted
- **ISO 27001:2022:** A.8.24 Use of cryptography
  - Basis: Author-assigned by control intent; indicative only (no official crosswalk used)

### IAM-1 — IAM Wildcard Policy

- **CIS 1.15** (related): Ensure IAM policies that allow full '*:*' administrative privileges are not attached
  - CIS 1.15 checks policies that are attached; this control checks policy definitions in Terraform, so it catches the problem before anything is attached.
- **NIST 800-53 Rev 5:** AC-2 Account Management; AC-3 Access Enforcement; AC-5 Separation of Duties; AC-6 Least Privilege
  - Basis: AWS Security Hub control IAM.1 (related requirements); base controls only, enhancements omitted
- **ISO 27001:2022:** A.5.15 Access control; A.8.2 Privileged access rights
  - Basis: Author-assigned by control intent; indicative only (no official crosswalk used)

### SECRET-1 — Hardcoded Credentials

- **CIS:** none
  - No CIS AWS recommendation covers secrets in Terraform source.
- **NIST 800-53 Rev 5:** IA-5 Authenticator Management; IA-5(7) No Embedded Unencrypted Static Authenticators
  - Basis: Author-assigned: AWS Security Hub has no equivalent control. IA-5(7) is 'No Embedded Unencrypted Static Authenticators'
- **ISO 27001:2022:** A.5.17 Authentication information; A.8.4 Access to source code
  - Basis: Author-assigned by control intent; indicative only (no official crosswalk used)

## Sources

- CIS Amazon Web Services Foundations Benchmark v5.0.0 (recommendation numbers and titles)
- AWS Security Hub controls reference: S3, RDS, EC2 and IAM controls, 'Related requirements' (NIST 800-53 Rev 5)
- NIST SP 800-53 Rev 5 (control titles)
- ISO/IEC 27001:2022 Annex A (control titles)
