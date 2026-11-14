
# Log Processing Rule Matrix

## 1. Required Fields

The following fields must be preserved because they are required by Module C detection rules.

| Log Source | Required Fields |
|---|---|
| Linux Authentication | timestamp, source_ip, username, outcome, process |
| Web Access | timestamp, source_ip, http_method, url_path, status_code |
| Firewall | timestamp, source_ip, destination_ip, destination_port, action |

## 2. Sensitive Data Masking

| Field | Processing Rule | Expected Result |
|---|---|---|
| password_sample | Mask full value | [REDACTED] |
| url_query token value | Mask token value | token=[REDACTED] |

Example:

Before:
password_sample = Secret123!

After:
password_sample = [REDACTED]

Before:
url_query = token=xyz123secret

After:
url_query = token=[REDACTED]

## 3. Fields That Must Not Be Dropped

- outcome=failure
- status_code=401
- action=BLOCK

These values are necessary for detection scenarios.

## 4. Candidate Fields for Filtering

The following fields are identified as candidates for removal:

- debug_info
- message
- user_agent
- response_bytes
- raw_message
- rule
- protocol

Before removing them, their relevance to future analysis must be reviewed.

## 5. Processing Principle

No field required by Module C detection rules may be removed or modified in a way that changes detection results.
