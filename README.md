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

## Examples
Here are some examples of how to set the environment variables and run the script.

If you are running it in windows powershell, you can also set the env variables right on the powershell command line like this:
```bash
PS C:\Users\cmartinsjr\Documents\Repositories\organic-broccoli-main\organic-broccoli-main> $env:PRISMA_API_URL="https://api2.prismacloud.io"
PS C:\Users\cmartinsjr\Documents\Repositories\organic-broccoli-main\organic-broccoli-main> $env:PRISMA_ACCESS_KEY_ID="*****************"
PS C:\Users\cmartinsjr\Documents\Repositories\organic-broccoli-main\organic-broccoli-main> $env:PRISMA_SECRET_KEY="***********************"
PS C:\Users\cmartinsjr\Documents\Repositories\organic-broccoli-main\organic-broccoli-main> python cas_metrics.py
```

You can run it directly in python like this: 
```bash
PS C:\Users\cmartinsjr\Documents\Repositories\organic-broccoli-main\organic-broccoli-main> python
Python 3.12.1 (tags/v3.12.1:2305ca5, Dec  7 2023, 22:03:25) [MSC v.1937 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> print(PRISMA_API_URL)
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
NameError: name 'PRISMA_API_URL' is not defined
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
