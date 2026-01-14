# SCP Linter

SCP Linter is a tool for validating AWS Service Control Policies (SCPs) across multiple dimensions to help ensure correctness, security, and best practices.

## Features
- **JSON Syntax Validation**: Detects invalid JSON and file access errors.
- **Policy Structure Checks**: Flags missing `Version`/`Statement` fields, unknown top-level fields, and invalid `Effect` values.
- **Size Limits**: Errors for policies exceeding 5120 characters, warnings at 75% capacity.
- **Statement Validation**: Ensures required fields (`Action`, `Effect`) are present, rejects unsupported fields like `Principal`, and detects unknown statement fields.
- **Action Validation**: Cross-references actions against an IAM reference database of 20,000+ actions, catching typos (e.g., `s3:GetObjet`) and providing "Did you mean?" suggestions.
- **Condition Block Syntax**: Validates operator structure, detects unknown operators (e.g., `StringEquls`), and flags empty conditions.
- **Condition Key Validation**: Verifies keys like `aws:SourceIp` exist, supports tag-based keys such as `aws:RequestTag/*`.
- **Best Practices**: Warns on blanket denies without conditions, service-wide denies, and Allow-only SCPs.

## Output
- **Errors (E-codes)**: For invalid policies that will not work.
- **Warnings (W-codes)**: For potentially problematic but valid policies.
- **Informational (I-codes)**: For best practice suggestions.

## Usage
Run the linter on your SCP JSON files to receive detailed feedback and suggestions for improvement.

## License
See LICENSE for details.
