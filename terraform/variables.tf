variable "compliant_db_password" { # declare password
  description = "Password for the compliant demo RDS instance"
  type        = string
  sensitive   = true # will redact this value anywhere found - output, JSON
}