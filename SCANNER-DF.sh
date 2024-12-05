#!/bin/bash
#MYCODE-@A_Y_TR
#آلقيـــــــــــــــآدهہ‌‏ آلزعيـــم
# Install required libraries
function install_dependencies() {
    echo -e "\e[33m[*] Installing required libraries...\e[0m"
    if [[ "$(uname -s)" == "Linux" ]]; then
        if command -v apt >/dev/null; then
            sudo apt update && sudo apt install -y curl nmap
        elif command -v yum >/dev/null; then
            sudo yum install -y curl nmap
        else
            echo -e "\e[31m[!] Package manager not supported!\e[0m"
            exit 1
        fi
    elif [[ "$(uname -s)" == "Darwin" ]]; then
        if command -v brew >/dev/null; then
            brew install curl nmap
        else
            echo -e "\e[31m[!] You need to install Homebrew to install dependencies.\e[0m"
            exit 1
        fi
    else
        echo -e "\e[31m[!] Unsupported OS for installing libraries.\e[0m"
        exit 1
    fi
    echo -e "\e[32m[+] Libraries installed successfully.\e[0m"
}

# Check environment
function check_environment() {
    os_name=$(uname -s)
    if [[ "$os_name" == "Linux" || "$os_name" == "Darwin" || "$os_name" == "CYGWIN" ]]; then
        echo -e "\e[32m[*] Supported environment!\e[0m"
    else
        echo -e "\e[33m[!] Environment may not be fully supported.\e[0m"
    fi
}

# Print banner
function print_banner() {
    echo -e "\e[36m
    ##############################################
    #               SCANNER-DF                  #
    ##############################################
    #           Designed by @A_Y_TR             #
    ##############################################
    \e[0m"
}

# Print menu
function print_menu() {
    echo -e "\e[33m
    Choose the scan option:
    1. Full scan (Vulnerabilities + Ports)
    2. Vulnerabilities scan only
    3. Ports scan only
    4. DDoS scan
    5. SSL/TLS scan
    6. DNS Security scan
    7. HTTP Security Headers scan
    9. Rate Limiting scan
    0. Exit
    \e[0m"
}

# Vulnerability scan
function check_vulnerabilities() {
    local url="$1"
    echo -e "\e[34m[+] Scanning vulnerabilities for: $url...\e[0m"

    declare -A vulnerabilities=(
        ["SQL Injection"]="sql"
        ["XSS"]="<script>alert('XSS')</script>"
        ["Open Redirect"]="http://example.com"
        ["LFI"]="../../../../etc/passwd"
        ["SSRF"]="http://localhost"
        ["Command Injection"]="; ls"
        ["Path Disclosure"]="/etc/passwd"
        ["XXE"]='<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    )

    for vuln in "${!vulnerabilities[@]}"; do
        echo -n "[*] Checking for $vuln... "
        response=$(curl -s -G --data-urlencode "q=${vulnerabilities[$vuln]}" "$url")
        if [[ "$response" =~ .*"${vulnerabilities[$vuln]}".* ]]; then
            echo -e "\e[32mFound!\e[0m"
        else
            echo -e "\e[31mNot found.\e[0m"
        fi
    done
}

# Port scan
function check_ports() {
    local url="$1"
    domain=$(echo "$url" | sed -e 's|https\?://||' -e 's|/.*||')
    echo -e "\e[34m[+] Scanning ports for: $domain...\e[0m"
    open_ports=$(nmap -p- --open "$domain" | grep "open" | awk '{print $1}')
    if [[ -z "$open_ports" ]]; then
        echo -e "\e[31mNo open ports found.\e[0m"
    else
        echo -e "\e[32mOpen ports:\e[0m"
        echo "$open_ports"
    fi
}

# SSL/TLS scan
function check_ssl() {
    local url="$1"
    echo -e "\e[34m[+] Checking SSL/TLS for: $url...\e[0m"
    ssl_info=$(echo | openssl s_client -connect "$url:443" 2>/dev/null | openssl x509 -noout -dates)
    if [[ -z "$ssl_info" ]]; then
        echo -e "\e[31mNo valid SSL/TLS certificate found!\e[0m"
    else
        echo -e "\e[32mValid SSL/TLS certificate found!\e[0m"
        echo "$ssl_info"
    fi
}

# DNS Security scan
function check_dns() {
    local domain="$1"
    echo -e "\e[34m[+] Checking DNS records for: $domain...\e[0m"
    dns_info=$(dig +short "$domain")
    if [[ -z "$dns_info" ]]; then
        echo -e "\e[31mNo DNS records found for $domain!\e[0m"
    else
        echo -e "\e[32mDNS records for $domain:\e[0m"
        echo "$dns_info"
    fi
}

# HTTP Security Headers scan
function check_http_headers() {
    local url="$1"
    echo -e "\e[34m[+] Checking HTTP headers for: $url...\e[0m"
    headers=$(curl -s -I "$url" | grep -i "Strict-Transport-Security\|X-Content-Type-Options\|X-XSS-Protection")
    if [[ -z "$headers" ]]; then
        echo -e "\e[31mMissing important HTTP security headers!\e[0m"
    else
        echo -e "\e[32mFound security headers:\e[0m"
        echo "$headers"
    fi
}

# Rate Limiting scan
function check_rate_limiting() {
    local url="$1"
    echo -e "\e[34m[+] Testing rate limiting on: $url...\e[0m"
    response=$(curl -s -w "%{http_code}" -o /dev/null "$url")
    if [[ "$response" == "429" ]]; then
        echo -e "\e[32mRate limiting is in place (HTTP 429).\e[0m"
    else
        echo -e "\e[31mNo rate limiting detected.\e[0m"
    fi
}

# DDoS scan
function check_ddos() {
    local url="$1"
    echo -e "\e[34m[+] Checking potential DDoS vulnerability for: $url...\e[0m"
    # This check depends on sending numerous rapid requests to the site
    response=$(curl -s -w "%{http_code}" -o /dev/null "$url")
    if [[ "$response" == "503" || "$response" == "429" ]]; then
        echo -e "\e[32mPotential DDoS vulnerability detected (HTTP 503/429).\e[0m"
    else
        echo -e "\e[31mNo DDoS vulnerability detected.\e[0m"
    fi
}

# Main function
function main() {
    check_environment
    print_banner

    while true; do
        print_menu
        read -rp $'\e[32m[?] Choose the desired option: \e[0m' choice

        case $choice in
            1)
                read -rp $'\e[32m[?] Enter the website URL: \e[0m' url
                check_vulnerabilities "$url"
                check_ports "$url"
                check_ssl "$url"
                check_dns "$url"
                check_http_headers "$url"
                check_rate_limiting "$url"
                check_ddos "$url"
                ;;
            2)
                read -rp $'\e[32m[?] Enter the website URL: \e[0m' url
                check_vulnerabilities "$url"
                ;;
            3)
                read -rp $'\e[32m[?] Enter the website URL: \e[0m' url
                check_ports "$url"
                ;;
            4)
                read -rp $'\e[32m[?] Enter the website URL: \e[0m' url
                check_ddos "$url"
                ;;
            5)
                read -rp $'\e[32m[?] Enter the website URL: \e[0m' url
                check_ssl "$url"
                ;;
            6)
                read -rp $'\e[32m[?] Enter the website URL: \e[0m' url
                check_dns "$url"
                ;;
            7)
                read -rp $'\e[32m[?] Enter the website URL: \e[0m' url
                check_http_headers "$url"
                ;;
            9)
                read -rp $'\e[32m[?] Enter the website URL: \e[0m' url
                check_rate_limiting "$url"
                ;;
            0)
                echo -e "\e[32m[+] Exiting...\e[0m"
                exit 0
                ;;
            *)
                echo -e "\e[31m[!] Invalid option. Please try again.\e[0m"
                ;;
        esac
    done
}

# Install dependencies if necessary
if ! command -v curl >/dev/null || ! command -v nmap >/dev/null; then
    install_dependencies
fi

# Run the main function
main
