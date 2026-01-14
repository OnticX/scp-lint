# SCP Linter

A command-line tool for validating AWS Service Control Policies (SCPs) to ensure correctness, security, and best practices.

## Installation

```bash
pip install scp-lint
```

Or install from source:

```bash
git clone https://github.com/OnticX/scp-lint.git
cd scp-lint
pip install -e .
```

## Usage

Lint a single SCP file:

```bash
scp-lint policy.json
```

Lint all JSON files in a directory:

```bash
scp-lint ./policies/
```

### Example Output

```
============================================================
File: ./my-scp.json
Status: PASSED with warnings
============================================================

  WARNINGS (1):
    [W042] Unknown action: 's3:GetObjet'
           Location: Statement[0].Action[0]
           Suggestion: Did you mean: s3:GetObject?

  INFO (1):
    [I031] Statement has no Sid (identifier)
           Location: Statement[0]
           Suggestion: Add a Sid for easier debugging and management

============================================================
SUMMARY
============================================================
  SCPs linted:    1
  Passed:         1
  Failed:         0
============================================================
```

## Features

- **JSON Syntax Validation**: Detects invalid JSON and file access errors
- **Policy Structure Checks**: Flags missing `Version`/`Statement` fields, unknown top-level fields, and invalid `Effect` values
- **Size Limits**: Errors for policies exceeding 5120 characters, warnings at 75% capacity
- **Statement Validation**: Ensures required fields (`Action`, `Effect`) are present, rejects unsupported fields like `Principal`
- **Action Validation**: Cross-references actions against an IAM reference database of 20,000+ actions, catching typos and providing "Did you mean?" suggestions
- **Condition Block Syntax**: Validates operator structure, detects unknown operators, and flags empty conditions
- **Condition Key Validation**: Verifies keys like `aws:SourceIp` exist, supports tag-based keys such as `aws:RequestTag/*`
- **Best Practices**: Warns on blanket denies without conditions, service-wide denies, and Allow-only SCPs

## Lint Rules

### Errors (E-codes) - Invalid policies that will not work

| Code | Description |
|------|-------------|
| E001 | File not found |
| E002 | Cannot read file |
| E003 | Invalid JSON syntax |
| E010 | Policy exceeds 5120 character limit |
| E020 | Missing Version field |
| E021 | Missing Statement field |
| E022 | Statement is not an object or array |
| E030 | Statement is not an object |
| E031 | Missing Effect field |
| E032 | Invalid Effect value (must be Allow or Deny) |
| E033 | Missing Action or NotAction field |
| E034 | Principal/NotPrincipal not allowed in SCPs |
| E040 | Action must be string or array |
| E041 | Action array item is not a string |
| E050 | Condition block must be an object |
| E051 | Condition operator value must be an object |
| E052 | Unknown condition operator |

### Warnings (W-codes) - Valid but potentially problematic

| Code | Description |
|------|-------------|
| W010 | Policy is over 75% of size limit |
| W020 | Unusual Version value |
| W021 | Unknown top-level field |
| W030 | Empty statements array |
| W031 | More than 20 statements |
| W032 | Unknown statement field |
| W040 | Action missing service prefix |
| W041 | Unknown service prefix |
| W042 | Unknown action name (with suggestions) |
| W043 | Unknown condition key |
| W044 | Empty condition block |
| W045 | Empty condition operator block |
| W046 | Empty or null condition value |
| W050 | Blanket Deny * without conditions |
| W051 | Service-wide deny without conditions |

### Info (I-codes) - Best practice suggestions

| Code | Description |
|------|-------------|
| I030 | No Resource specified (defaults to *) |
| I031 | No Sid specified |
| I050 | Policy contains only Allow statements |

## GitHub Actions Integration

Add SCP linting to your CI/CD pipeline:

```yaml
name: SCP Lint

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install scp-lint
        run: pip install scp-lint
      - name: Lint SCPs
        run: scp-lint ./policies/
```

## License

MIT - See [LICENSE](LICENSE) for details.
