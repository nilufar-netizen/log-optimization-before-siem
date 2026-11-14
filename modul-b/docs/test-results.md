
# Module B Test Results

## 1. Test Objectives

The purpose of testing is to verify that log processing does not remove information required for security detection.

## 2. Test Checklist

| Test ID | Test Description | Status |
|---|---|---|
| T01 | Validate JSONL input format | Not Tested |
| T02 | Verify required fields are preserved | Not Tested |
| T03 | Verify password masking | Not Tested |
| T04 | Verify URL token masking | Not Tested |
| T05 | Verify failure events are preserved | Not Tested |
| T06 | Verify HTTP 401 events are preserved | Not Tested |
| T07 | Verify firewall BLOCK events are preserved | Not Tested |
| T08 | Verify processed logs reach OpenSearch | Not Tested |
| T09 | Compare raw and processed detection results | Not Tested |

## 3. Validation Criteria

- JSONL records must be valid.
- Required fields must remain available.
- Sensitive values must be masked.
- Detection-relevant events must be preserved.
- Detection results must be compared before and after processing.

## 4. Test Evidence

Screenshots, test outputs and validation evidence will be added after execution.

## 5. Final Status

Testing has not yet been completed.
