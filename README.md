# SCANNER-DF 
# Web Security Scanner Tool

A comprehensive tool to scan websites for various security vulnerabilities, including:

- **Vulnerability Scan**: Checks for common vulnerabilities like SQL injection, XSS, SSRF, etc.
- **Port Scan**: Scans for open ports on the target server.
- **SSL/TLS Scan**: Verifies the SSL/TLS certificate and its validity.
- **DNS Security**: Checks DNS records for security concerns.
- **HTTP Security Headers**: Ensures important security headers like HSTS and XSS protection are present.
- **DDoS Vulnerability Scan**: Detects potential DDoS vulnerabilities based on HTTP 503/429 responses.
- **Rate Limiting Check**: Tests for rate limiting to prevent brute force attacks.
- **Email Leakage Scan**: Identifies if any emails are exposed on the website (requires API integration).

## Features

- Simple and easy-to-use command-line interface (CLI).
- Supports both **Linux** and **macOS** environments.
- Works with **curl** and **nmap** for scanning and checks.
- Customizable for additional security checks and vulnerability assessments.

## Installation

### Requirements

- **curl**
- **nmap**
- **openssl** (for SSL/TLS scanning)
- **dig** (for DNS queries)

To install dependencies, run the following command (supports both Ubuntu/Debian and macOS):

```bash
git clone https://github.com/MohamedAbuAl-Saud/SCANNER-DF
cd SCANNER-DF.sh
bash SCANNER-DF.sh
