# CAS Metrics Script

This script retrieves various Prisma Cloude Application Security (CAS) metrics from an API endpoint. It performs multiple checks related to CI/CD findings, code security issues, secret exposure, and pipeline runs, and provides feedback based on predefined thresholds.

## Prerequisites

Ensure the following environment variables are set:

- `PRISMA_API_URL`: The URL for the PRISMA API.
- `PRISMA_ACCESS_KEY_ID`: The access key ID for authentication.
- `PRISMA_SECRET_KEY`: The secret key for authentication.

## Usage

1. Clone the repository.
2. Set the required environment variables.
3. Execute the script.

```bash
python cas_metrics.py
