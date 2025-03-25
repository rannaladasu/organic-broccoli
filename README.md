# CAS Metrics Script

This script retrieves various Prisma Cloud Application Security (CAS) metrics from an API endpoint. It performs multiple checks related to CI/CD findings, code security issues, secret exposure, and pipeline runs, and provides feedback based on predefined thresholds.

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
```

### Debugging

The script includes debugging functionality. You can enable different debug modes to log detailed information about the execution process.

- **Basic Debug Mode**: Use this to log important events and errors.
  - To enable it, set the environment variable `DEBUG_MODE=1` or use the `--debug` command-line argument.
  
- **Deep Debug Mode**: Provides additional detailed logging, including API request details and the actual API responses.
  - To enable Deep Debug Mode, set the environment variable `DEEP_DEBUG_MODE=1` or use the `--deep-debug` command-line argument.
  - Logs will be saved in `debug_log.txt`.

### Enabling Debug Modes

You can enable the debug modes using environment variables or command-line arguments:

#### 1. Using Environment Variables

For **Basic Debug Mode**:
```bash
export DEBUG_MODE=1
```

For **Deep Debug Mode**:
```bash
export DEEP_DEBUG_MODE=1
```

#### 2. Using Command-Line Arguments

For **Basic Debug Mode**:
```bash
python cas_metrics.py --debug
```

For **Deep Debug Mode**:
```bash
python cas_metrics.py --deep-debug
```

### Example Command

```bash
python cas_metrics.py --debug
```

If you're running the script on **Windows PowerShell**, you can set environment variables as follows:
```bash
PS C:\Users\cmartinsjr\Documents\Repositories\organic-broccoli-main\organic-broccoli-main> $env:PRISMA_API_URL="https://api2.prismacloud.io"
PS C:\Users\cmartinsjr\Documents\Repositories\organic-broccoli-main\organic-broccoli-main> $env:PRISMA_ACCESS_KEY_ID="*****************"
PS C:\Users\cmartinsjr\Documents\Repositories\organic-broccoli-main\organic-broccoli-main> $env:PRISMA_SECRET_KEY="***********************"
PS C:\Users\cmartinsjr\Documents\Repositories\organic-broccoli-main\organic-broccoli-main> python cas_metrics.py
```

You can also run it directly in Python:
```bash
PS C:\Users\cmartinsjr\Documents\Repositories\organic-broccoli-main\organic-broccoli-main> python
Python 3.12.1 (tags/v3.12.1:2305ca5, Dec  7 2023, 22:03:25) [MSC v.1937 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> os.environ['PRISMA_API_URL'] = "https://api2.prismacloud.io"
>>> os.environ['PRISMA_ACCESS_KEY_ID'] = "*******************"
>>> os.environ['PRISMA_SECRET_KEY'] = "*********************"
>>> exec(open('C:\\Users\\cmartinsjr\\Documents\\Repositories\\organic-broccoli-main\\organic-broccoli-main\\cas_metrics.py').read())
Get CAS Metrics -  v1.0 - Initiated
20 percent of Medium/High CI/CD Findings Fixed: False - 0.0%
80% of all risks are prevented in the pipeline: False - 0.0%
10% increase in Number of fixed vs opened code security issue: False - 0.0%
50% reduction of secret exposure: False - 0.0%
80% reduction of secret exposure: False - 0.0%
80% of High code issues blocked: False - 39.0%
Get CAS Metrics -  v1.0 - Completed
```

### Debug Log File

If **Deep Debug Mode** is enabled, a `debug_log.txt` file will be created. It will contain detailed logs for the following events:
- Authentication process.
- API request details (method, endpoint, payload).
- Full API response in JSON format (if available).

The log entries will be timestamped and look like this:
```
[2025-03-25 15:00:00] Making POST request to https://api.prismacloud.io/bridgecrew/api/v1/pipeline-risks/export
API Response:
{
    "status": "success",
    "data": [...],
    ...
}
```

### Examples

#### Example 1: Basic Debug Mode

```bash
python cas_metrics.py --debug
```

This will log critical events such as the start and end of the script, any missing environment variables, and basic request/response status.

#### Example 2: Deep Debug Mode

```bash
python cas_metrics.py --deep-debug
```

In this case, detailed information such as API requests, full response bodies, and timestamps will be logged in `debug_log.txt` for thorough analysis.