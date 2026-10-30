
# Log Field Mapping

## 1. Linux Authentication Logs

| Field | Description |
|---|---|
| timestamp | Event timestamp |
| source_ip | IP address of the source |
| username | Account name |
| outcome | Authentication result |
| process | Process responsible for authentication |
| password_sample | Synthetic sensitive test value |

Required detection fields:
timestamp, source_ip, username, outcome, process

## 2. Web Access Logs

| Field | Description |
|---|---|
| timestamp | Request timestamp |
| source_ip | Client IP address |
| http_method | HTTP request method |
| url_path | Requested URL path |
| url_query | URL query parameters |
| status_code | HTTP response status code |

Required detection fields:
timestamp, source_ip, http_method, url_path, status_code

## 3. Firewall Logs

| Field | Description |
|---|---|
| timestamp | Firewall event timestamp |
| source_ip | Source IP address |
| destination_ip | Destination IP address |
| destination_port | Destination port |
| action | Firewall decision |

Required detection fields:
timestamp, source_ip, destination_ip, destination_port, action

## 4. Standardization

The field source_ip must be used consistently across all three log sources.

The web log source name must be standardized as web_access.
