# DynamoDB Schema Documentation

This document describes the single-table design for the Quorum metrics storage.

## Table Overview

**Table Name**: `quorum-metrics-{environment}`
**Billing Mode**: PAY_PER_REQUEST (on-demand)
**TTL Attribute**: `ttl`

## Primary Key Structure

| Attribute | Type | Description |
|-----------|------|-------------|
| `PK` | String | Partition Key - Generic, overloaded by entity type |
| `SK` | String | Sort Key - Generic, overloaded by entity type |

## Entity Types

The table stores multiple entity types using key prefixes:

| Entity | Description |
|--------|-------------|
| `REVIEW` | A complete review session for a PR |
| `MODEL_RESPONSE` | Individual model's response to a review |
| `FINDING` | Specific issue identified by a model |
| `CONSENSUS` | Agreement between 2+ models on an issue |
| `COST_METRIC` | Cost tracking per model/PR |

---

## Access Patterns & Indexes

### Base Table (PK/SK)

#### Pattern: Get all reviews for a repository

```text
PK: REPO#{owner}#{repo}
SK: REVIEW#{ISO-timestamp}#{pr_number}
```

**Query Example**:

```python
response = table.query(
    KeyConditionExpression="PK = :pk AND begins_with(SK, :sk_prefix)",
    ExpressionAttributeValues={
        ":pk": "REPO#owner#repo",
        ":sk_prefix": "REVIEW#"
    },
    ScanIndexForward=False  # Most recent first
)
```

#### Pattern: Get all model responses for a PR

```text
PK: REVIEW#{owner}#{repo}#{pr_number}#{review_id}
SK: MODEL#{model_id}
```

**Query Example**:

```python
response = table.query(
    KeyConditionExpression="PK = :pk AND begins_with(SK, :sk_prefix)",
    ExpressionAttributeValues={
        ":pk": "REVIEW#owner#repo#123#uuid-v4",
        ":sk_prefix": "MODEL#"
    }
)
```

#### Pattern: Get all findings for a review

```text
PK: REVIEW#{owner}#{repo}#{pr_number}#{review_id}
SK: FINDING#{model_id}#{finding_id}
```

#### Pattern: Get consensus items for a review

```text
PK: REVIEW#{owner}#{repo}#{pr_number}#{review_id}
SK: CONSENSUS#{consensus_id}
```

---

### GSI1: Model Performance & Date Queries

**Purpose**: Compare model performance across all reviews, query by date.

| Attribute | Key Type |
|-----------|----------|
| `GSI1PK` | Partition Key |
| `GSI1SK` | Sort Key |

#### Pattern: Model performance comparison

```text
GSI1PK: MODEL#{model_id}
GSI1SK: REVIEW#{ISO-timestamp}#{owner}#{repo}#{pr_number}
```

**Query Example** - Get all reviews for Claude:

```python
response = table.query(
    IndexName="GSI1",
    KeyConditionExpression="GSI1PK = :pk",
    ExpressionAttributeValues={
        ":pk": "MODEL#anthropic.claude-3-sonnet"
    },
    ScanIndexForward=False
)

# Aggregate metrics
total_findings = sum(item['findings_count'] for item in response['Items'])
avg_latency = statistics.mean(item['latency_ms'] for item in response['Items'])
total_cost = sum(item['cost_usd'] for item in response['Items'])
```

**Query Example** - Compare models in time range:

```python
for model_id in ["claude-3-sonnet", "gpt-4", "llama-70b"]:
    response = table.query(
        IndexName="GSI1",
        KeyConditionExpression="GSI1PK = :pk AND GSI1SK BETWEEN :start AND :end",
        ExpressionAttributeValues={
            ":pk": f"MODEL#{model_id}",
            ":start": "REVIEW#2025-01-01T00:00:00Z",
            ":end": "REVIEW#2025-01-31T23:59:59Z"
        }
    )
```

#### Pattern: All reviews on a specific date

```text
GSI1PK: DATE#{YYYY-MM-DD}
GSI1SK: REVIEW#{ISO-timestamp}#{owner}#{repo}#{pr_number}
```

**Query Example**:

```python
response = table.query(
    IndexName="GSI1",
    KeyConditionExpression="GSI1PK = :pk",
    ExpressionAttributeValues={
        ":pk": "DATE#2025-01-15"
    }
)
```

---

### GSI2: Entity Type Queries

**Purpose**: Query by entity type across all repositories.

| Attribute | Key Type |
|-----------|----------|
| `GSI2PK` | Partition Key |
| `GSI2SK` | Sort Key |

#### Pattern: All reviews globally

```text
GSI2PK: TYPE#REVIEW
GSI2SK: {ISO-timestamp}#{owner}#{repo}#{pr_number}
```

**Query Example** - Recent reviews:

```python
response = table.query(
    IndexName="GSI2",
    KeyConditionExpression="GSI2PK = :pk AND GSI2SK >= :start_time",
    ExpressionAttributeValues={
        ":pk": "TYPE#REVIEW",
        ":start_time": "2025-01-08T00:00:00Z"
    }
)
```

#### Pattern: All findings by severity

```text
GSI2PK: TYPE#FINDING#{severity}
GSI2SK: {ISO-timestamp}#{category}
```

**Query Example** - High severity findings:

```python
response = table.query(
    IndexName="GSI2",
    KeyConditionExpression="GSI2PK = :pk",
    ExpressionAttributeValues={
        ":pk": "TYPE#FINDING#high"
    }
)
```

#### Pattern: All consensus items

```text
GSI2PK: TYPE#CONSENSUS
GSI2SK: {ISO-timestamp}#{severity}#{category}
```

---

### GSI3: Flexible Future Queries

**Purpose**: Category-based queries and future flexibility.

| Attribute | Key Type |
|-----------|----------|
| `GSI3PK` | Partition Key |
| `GSI3SK` | Sort Key |

#### Pattern: Query by category

```text
GSI3PK: CATEGORY#{category}
GSI3SK: {ISO-timestamp}#{severity}#{model_id}
```

**Query Example** - Security findings over time:

```python
response = table.query(
    IndexName="GSI3",
    KeyConditionExpression="GSI3PK = :pk AND GSI3SK BETWEEN :start AND :end",
    ExpressionAttributeValues={
        ":pk": "CATEGORY#security",
        ":start": "2025-01-01T00:00:00Z",
        ":end": "2025-01-31T23:59:59Z"
    }
)
```

#### Pattern: User-based queries (future multi-tenant)

```text
GSI3PK: USER#{github_username}
GSI3SK: REVIEW#{ISO-timestamp}
```

---

## Example Items

### Review Item

```json
{
  "PK": "REPO#owner#repo",
  "SK": "REVIEW#2025-01-15T10:30:00Z#123",
  "GSI1PK": "DATE#2025-01-15",
  "GSI1SK": "REVIEW#2025-01-15T10:30:00Z#owner#repo#123",
  "GSI2PK": "TYPE#REVIEW",
  "GSI2SK": "2025-01-15T10:30:00Z#owner#repo#123",

  "entity_type": "REVIEW",
  "review_id": "uuid-v4",
  "pr_number": 123,
  "pr_title": "Add new feature",
  "pr_url": "https://github.com/owner/repo/pull/123",
  "models_used": ["claude-3-sonnet", "gpt-4", "llama-70b"],
  "total_findings": 15,
  "consensus_findings": 5,
  "status": "completed",
  "total_cost_usd": 0.0234,
  "created_at": "2025-01-15T10:30:00Z",
  "ttl": 1739548200
}
```

### ModelResponse Item

```json
{
  "PK": "REVIEW#owner#repo#123#uuid-v4",
  "SK": "MODEL#claude-3-sonnet",
  "GSI1PK": "MODEL#claude-3-sonnet",
  "GSI1SK": "REVIEW#2025-01-15T10:30:00Z#owner#repo#123",
  "GSI2PK": "TYPE#MODEL_RESPONSE",
  "GSI2SK": "2025-01-15T10:30:00Z#claude-3-sonnet",

  "entity_type": "MODEL_RESPONSE",
  "model_id": "claude-3-sonnet",
  "findings_count": 7,
  "input_tokens": 15420,
  "output_tokens": 2340,
  "latency_ms": 12500,
  "cost_usd": 0.0089,
  "raw_response_s3_key": "owner/repo/123/claude-3-sonnet/2025-01-15T10:30:00Z.json",
  "status": "success",
  "created_at": "2025-01-15T10:30:00Z",
  "ttl": 1739548200
}
```

### Finding Item

```json
{
  "PK": "REVIEW#owner#repo#123#uuid-v4",
  "SK": "FINDING#claude-3-sonnet#finding-001",
  "GSI2PK": "TYPE#FINDING#high",
  "GSI2SK": "2025-01-15T10:30:00Z#security",
  "GSI3PK": "CATEGORY#security",
  "GSI3SK": "2025-01-15T10:30:00Z#high#claude-3-sonnet",

  "entity_type": "FINDING",
  "finding_id": "finding-001",
  "model_id": "claude-3-sonnet",
  "severity": "high",
  "category": "security",
  "file_path": "src/auth/login.py",
  "line_start": 45,
  "line_end": 52,
  "title": "SQL Injection Vulnerability",
  "description": "User input is directly concatenated into SQL query...",
  "suggestion": "Use parameterized queries instead of string concatenation...",
  "in_consensus": true,
  "created_at": "2025-01-15T10:30:00Z",
  "ttl": 1739548200
}
```

### Consensus Item

```json
{
  "PK": "REVIEW#owner#repo#123#uuid-v4",
  "SK": "CONSENSUS#consensus-001",
  "GSI2PK": "TYPE#CONSENSUS",
  "GSI2SK": "2025-01-15T10:30:00Z#high#security",
  "GSI3PK": "CATEGORY#security",
  "GSI3SK": "2025-01-15T10:30:00Z#high#CONSENSUS",

  "entity_type": "CONSENSUS",
  "consensus_id": "consensus-001",
  "agreeing_models": ["claude-3-sonnet", "gpt-4"],
  "agreement_count": 2,
  "severity": "high",
  "category": "security",
  "file_path": "src/auth/login.py",
  "merged_description": "Both models identified SQL injection...",
  "finding_ids": ["finding-001", "finding-gpt4-001"],
  "created_at": "2025-01-15T10:30:00Z",
  "ttl": 1739548200
}
```

---

## Access Pattern Summary

| # | Access Pattern | Index | Key Condition |
|---|----------------|-------|---------------|
| 1 | Reviews for a repository | Base | `PK = REPO#...` |
| 2 | Model responses for a PR | Base | `PK = REVIEW#... AND SK begins_with MODEL#` |
| 3 | Findings for a review | Base | `PK = REVIEW#... AND SK begins_with FINDING#` |
| 4 | Consensus for a review | Base | `PK = REVIEW#... AND SK begins_with CONSENSUS#` |
| 5 | Model performance comparison | GSI1 | `GSI1PK = MODEL#...` |
| 6 | Reviews on a date | GSI1 | `GSI1PK = DATE#...` |
| 7 | All reviews globally | GSI2 | `GSI2PK = TYPE#REVIEW` |
| 8 | Findings by severity | GSI2 | `GSI2PK = TYPE#FINDING#{severity}` |
| 9 | All consensus items | GSI2 | `GSI2PK = TYPE#CONSENSUS` |
| 10 | Findings by category | GSI3 | `GSI3PK = CATEGORY#...` |

---

## TTL Configuration

DynamoDB TTL is enabled on the table with attribute name `ttl`. The actual retention period is **defined at the application level** when writing items - not in Terraform.

**Why application-level?** Different entity types may need different retention periods:

- `REVIEW` items: 90 days (sufficient for trend analysis)
- `COST_METRIC` items: 365 days (longer for billing reconciliation)

**TTL Calculation** (implement in your application):

```python
from datetime import datetime, timedelta

def calculate_ttl(retention_days: int) -> int:
    """Calculate TTL as Unix timestamp for DynamoDB."""
    expiry = datetime.utcnow() + timedelta(days=retention_days)
    return int(expiry.timestamp())

# Example usage when writing items
item = {
    "PK": "REPO#owner#repo",
    "SK": "REVIEW#2025-01-15T10:30:00Z#123",
    # ... other attributes
    "ttl": calculate_ttl(90)  # Expires in 90 days
}
```

**Recommended retention periods**:

| Entity Type | Retention | Rationale |
|-------------|-----------|-----------|
| REVIEW | 90 days | Sufficient for trend analysis |
| MODEL_RESPONSE | 90 days | Tied to parent review |
| FINDING | 90 days | Tied to parent review |
| CONSENSUS | 90 days | Tied to parent review |
| COST_METRIC | 365 days | Longer for billing reconciliation |

---

## S3 Integration

Raw model outputs are stored in S3 with the following key structure:

```text
{repo}/{pr_number}/{model}/{timestamp}.json
```

The `raw_response_s3_key` attribute in `ModelResponse` items references the S3 object.
