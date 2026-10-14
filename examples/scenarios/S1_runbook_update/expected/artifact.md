# Cache Timeout Remediation

1. Confirm timeout alerts are active.
2. Restart the affected payment API workers.
3. Run cache warmup validation and confirm timeout count is decreasing.
4. Return the service to normal traffic.
