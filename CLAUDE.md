# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an IIS SSL certificate monitoring tool written in Python that:
- Monitors specific IIS websites for SSL certificate status
- Uses PowerShell to query IIS bindings and certificate information
- Checks SSL certificate expiry dates via direct SSL connections
- Provides console output with site status and certificate details

## Architecture

The project consists of a single Python script (`iis_monitor.py`) with three main components:

1. **IIS Integration**: Uses PowerShell's `WebAdministration` module to query IIS site bindings and certificate details from the Windows certificate store
2. **SSL Verification**: Direct SSL socket connections to validate certificates and check expiry dates
3. **Monitoring Logic**: Filters sites based on the `MONITOR_SITES` configuration list

## Key Functions

- `get_iis_sites()`: Executes PowerShell script to retrieve IIS binding and certificate information
- `extract_hostname()`: Parses IIS binding format (IP:Port:Hostname) to extract hostnames
- `check_ssl_certificate()`: Performs live SSL certificate validation and expiry checking

## Configuration

- **MONITOR_SITES**: List of IIS site names to monitor (line 8 in `iis_monitor.py`)
- The tool currently monitors `["qr.novax-intl.com"]` by default

## Runtime Requirements

- Windows environment with IIS installed
- PowerShell with `WebAdministration` module
- Python with standard library modules (no external dependencies)
- Administrative privileges may be required to access IIS configuration

## Running the Tool

```bash
python iis_monitor.py
```

The script runs once and outputs:
- Site binding information
- SSL certificate status and expiry details
- Days remaining until certificate expiration
- SNI (Server Name Indication) configuration status

## Platform-Specific Notes

This tool is Windows-specific due to:
- PowerShell integration for IIS management
- Windows certificate store access
- IIS-specific binding format and SSL configuration