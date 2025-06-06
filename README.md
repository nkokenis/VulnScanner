# Project: Vulnerability Scanner

## Goal

To build a lightweight, extensible tool that scans for basic vulnerabilities on web servers or hosts, a simplified version of **Nmap, Nikto, and CVE checker**.

## Project Requirements

### 1. Overview

A command-line tool that:
- Scans IP addresses or domains  
- Checks for:
  - Open ports  
  - Web technologies in use (e.g., Apache, Nginx, PHP)  
  - Common misconfigurations  
  - Known vulnerabilities using CVE lookup (via APIs like [cve.circl.lu](https://cve.circl.lu))  

### 2. Core Features

| **Feature**                  | **Description**                                                    |
|-----------------------------|--------------------------------------------------------------------|
| Port Scanner                | TCP scanning on common ports (80, 443, 22, 21, etc.)               |
| HTTP Fingerprinting         | Check server headers, identify technologies                        |
| CVE Checker                 | Look up CVEs based on server banners (e.g., Apache 2.4.49)         |
| Directory Brute-forcing *(optional)* | Try known endpoints (e.g., `/admin`, `/config`)                  |
| Report Generation           | JSON/Markdown output of findings                                   |

### 3. Tech Stack

- **Language:** Python (easy to integrate with `socket`, `requests`, `nmap`, etc.)
- **Libraries:**
  - `socket`, `requests`
  - `python-nmap` (wrapper for Nmap)
  - `beautifulsoup4` *(optional for scraping)*
  - `rich` *(for CLI formatting)*
  - `argparse` *(for CLI)*

### 4. Stretch Goals

- CVSS scoring integration  
- HTML report output  
- Plugin system for custom checks  
- Docker support