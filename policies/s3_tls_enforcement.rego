package policies.s3_tls_enforcement

import rego.v1

metadata := {
    "id":          "SOC2-CC6.7-S3-TLS",
    "framework":   "SOC 2",
    "control":     "CC6.7",
    "severity":    "HIGH",
    "remediation": "Add a bucket policy denying requests where aws:SecureTransport is false",
}

# Only deny NEW S3 buckets being created without a TLS policy
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    resource.change.actions == ["create"]
    not s3_has_tls_policy
    msg := sprintf(
        "[%s] %s: S3 bucket '%s' must enforce TLS-only requests (SOC 2 CC6.7 — GAP-03)",
        [metadata.severity, metadata.control, resource.address]
    )
}

s3_has_tls_policy if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_policy"
    resource.change.actions[_] in ["create", "update"]
    policy := json.unmarshal(resource.change.after.policy)
    some statement in policy.Statement
    statement.Effect == "Deny"
    statement.Condition.Bool["aws:SecureTransport"] == "false"
}
