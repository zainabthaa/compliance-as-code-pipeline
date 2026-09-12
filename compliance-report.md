# Compliance Report

Generated: 2026-09-12 10:49 UTC

**Total violations found: 10**

| Severity | Control | Resource | Issue |
|---|---|---|---|
| CRITICAL | 2.1.5.1 | `aws_s3_bucket_public_access_block.insecure_bucket_access` | aws_s3_bucket_public_access_block.insecure_bucket_access has block_public_acls = false. S3 buckets must block public access. |
| CRITICAL | 2.3 | `aws_db_instance.insecure_db` | aws_db_instance.insecure_db is a publicly accessible RDS instance. |
| CRITICAL | 5.2 | `aws_security_group.insecure_sg` | aws_security_group.insecure_sg allows SSH (port 22) ingress from 0.0.0.0/0 (entire internet). |
| CRITICAL | 5.3 | `aws_security_group.insecure_sg_rdp` | aws_security_group.insecure_sg_rdp allows RDP (port 3389) ingress from 0.0.0.0/0 (entire internet). |
| CRITICAL | SECRET-1 | `aws_db_instance.insecure_db` | aws_db_instance.insecure_db has a hardcoded plaintext password in source code. |
| HIGH | 2.1.1 | `aws_s3_bucket.insecure_bucket` | aws_s3_bucket.insecure_bucket has no server-side encryption configured. |
| HIGH | 2.3.3 | `aws_db_instance.insecure_db` | aws_db_instance.insecure_db has unencrypted RDS storage. |
| HIGH | EBS-1 | `aws_ebs_volume.insecure_volume` | aws_ebs_volume.insecure_volume is an unencrypted EBS volume. |
| HIGH | IAM-1 | `aws_iam_policy.insecure_policy` | aws_iam_policy.insecure_policy grants wildcard Action=* and Resource=* (full admin access). |
| MEDIUM | 2.1.2 | `aws_s3_bucket.insecure_bucket` | aws_s3_bucket.insecure_bucket has no versioning configuration enabled. |

## Details & Remediation

### 2.1.5.1 — S3 Block Public Access
- **Severity:** CRITICAL
- **Resource:** `aws_s3_bucket_public_access_block.insecure_bucket_access`
- **Issue:** aws_s3_bucket_public_access_block.insecure_bucket_access has block_public_acls = false. S3 buckets must block public access.
- **Remediation:** Set block_public_acls, block_public_policy, ignore_public_acls, and restrict_public_buckets to true.

### 2.3 — RDS Publicly Accessible
- **Severity:** CRITICAL
- **Resource:** `aws_db_instance.insecure_db`
- **Issue:** aws_db_instance.insecure_db is a publicly accessible RDS instance.
- **Remediation:** Set publicly_accessible = false on the RDS instance, and access it via a bastion host or VPN instead.

### 5.2 — SSH Open to the Internet
- **Severity:** CRITICAL
- **Resource:** `aws_security_group.insecure_sg`
- **Issue:** aws_security_group.insecure_sg allows SSH (port 22) ingress from 0.0.0.0/0 (entire internet).
- **Remediation:** Restrict the security group's ingress CIDR block for port 22 to a specific internal range, not 0.0.0.0/0.

### 5.3 — RDP Open to the Internet
- **Severity:** CRITICAL
- **Resource:** `aws_security_group.insecure_sg_rdp`
- **Issue:** aws_security_group.insecure_sg_rdp allows RDP (port 3389) ingress from 0.0.0.0/0 (entire internet).
- **Remediation:** Restrict the security group's ingress CIDR block for port 3389 to a specific internal range, not 0.0.0.0/0.

### SECRET-1 — Hardcoded Credentials
- **Severity:** CRITICAL
- **Resource:** `aws_db_instance.insecure_db`
- **Issue:** aws_db_instance.insecure_db has a hardcoded plaintext password in source code.
- **Remediation:** Move the password into a Terraform variable marked sensitive = true, supplied via .tfvars (gitignored) or a secrets manager.

### 2.1.1 — S3 Bucket Server-Side Encryption
- **Severity:** HIGH
- **Resource:** `aws_s3_bucket.insecure_bucket`
- **Issue:** aws_s3_bucket.insecure_bucket has no server-side encryption configured.
- **Remediation:** Add an aws_s3_bucket_server_side_encryption_configuration resource for this bucket with sse_algorithm = "AES256".

### 2.3.3 — RDS Storage Encryption
- **Severity:** HIGH
- **Resource:** `aws_db_instance.insecure_db`
- **Issue:** aws_db_instance.insecure_db has unencrypted RDS storage.
- **Remediation:** Set storage_encrypted = true on the RDS instance.

### EBS-1 — EBS Volume Encryption
- **Severity:** HIGH
- **Resource:** `aws_ebs_volume.insecure_volume`
- **Issue:** aws_ebs_volume.insecure_volume is an unencrypted EBS volume.
- **Remediation:** Set encrypted = true on the EBS volume.

### IAM-1 — IAM Wildcard Policy
- **Severity:** HIGH
- **Resource:** `aws_iam_policy.insecure_policy`
- **Issue:** aws_iam_policy.insecure_policy grants wildcard Action=* and Resource=* (full admin access).
- **Remediation:** Scope the policy's Action and Resource fields to only the specific permissions needed, instead of "*".

### 2.1.2 — S3 Bucket Versioning
- **Severity:** MEDIUM
- **Resource:** `aws_s3_bucket.insecure_bucket`
- **Issue:** aws_s3_bucket.insecure_bucket has no versioning configuration enabled.
- **Remediation:** Add an aws_s3_bucket_versioning resource for this bucket with status = "Enabled".
