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

# Print banner
function print_banner() {
    echo -e "\e[36m
    ##############################################
    #               SCANNER DF                  #
    ##############################################
    #           Designed by @A_Y_TR             #
    ##############################################
    \e[0m"
}

# Function to print a separator line
function print_separator() {
    echo -e "\e[36m----------------------------------------\e[0m"
}

# Function to print table headers
function print_table_headers() {
    printf "\e[33m%-40s %-15s\e[0m\n" "Test Name" "Result"
    print_separator
}

# Main menu
function print_menu() {
    echo -e "\e[33m
    Choose an option:
    1. Vulnerability Scan (All)
    2. Nmap Port Scan
    3. File Permission Check
    4. Fetch Website IP and Server Info
    0. Exit
    \e[0m"
}

# Vulnerability Scan (All)
function vulnerability_scan() {
    local url="$1"
    echo -e "\e[34m[+] Starting Vulnerability Scan for: $url\e[0m"
    print_separator

    declare -A tests=(
        ["SQL Injection"]="q=' OR '1'='1"
        ["Cross-Site Scripting (XSS)"]="q=<script>alert('XSS')</script>"
        ["Cross-Site Request Forgery (CSRF)"]="q=csrf_test"
        ["Remote Code Execution (RCE)"]="q=;ls"
        ["Buffer Overflow"]="q=AAAAAAAAAAAAAAAAAAAAAAAAAA"
        ["Directory Traversal"]="q=../../../../etc/passwd"
        ["Privilege Escalation"]="q=sudo_test"
        ["Man-in-the-Middle (MITM)"]="q=mitm_test"
        ["Broken Authentication"]="q=login_test"
        ["Sensitive Data Exposure"]="q=sensitive_data_test"
        ["XML External Entity (XXE) Injection"]="q=<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
        ["Insecure Deserialization"]="q=deserialize_test"
        ["Denial of Service (DoS)"]="q=dos_test"
        ["Server-Side Request Forgery (SSRF)"]="q=http://localhost"
        ["Clickjacking"]="q=clickjack_test"
    )

    print_table_headers
    for vuln in "${!tests[@]}"; do
        echo -n "[*] Testing $vuln... "
        response=$(curl -s -G --data-urlencode "${tests[$vuln]}" "$url")
        if [[ "$response" =~ .*"${tests[$vuln]}".* ]]; then
            printf "\e[32m%-40s %-15s\e[0m\n" "$vuln" "Found"
        else
            printf "\e[31m%-40s %-15s\e[0m\n" "$vuln" "Not Found"
        fi
    done
    print_separator
}

# Nmap Port Scan
function port_scan() {
    local ip="$1"
    echo -e "\e[34m[+] Scanning Ports for: $ip\e[0m"
    print_separator
    open_ports=$(nmap -p- --open "$ip" | grep "open" | awk '{print $1 " " $2}')
    printf "\e[33m%-15s %-20s\e[0m\n" "Port" "Service"
    print_separator
    if [[ -z "$open_ports" ]]; then
        echo -e "\e[31mNo open ports found.\e[0m"
    else
        echo "$open_ports" | while read -r line; do
            printf "\e[32m%-15s %-20s\e[0m\n" "$line"
        done
    fi
    print_separator
}

# File Permission Check
function file_permission_check() {
    echo -e "\e[34m[+] Checking File Permissions...\e[0m"
    print_separator
    echo -e "\e[33mWarning: Files with 777 permissions:\e[0m"
    printf "\e[33m%-50s\e[0m\n" "File"
    print_separator
    find / -type f -perm 0777 2>/dev/null | while read -r file; do
        printf "\e[32m%-50s\e[0m\n" "$file"
    done
    print_separator
}

# Fetch IP and Server Info
function fetch_ip_server() {
    local url="$1"
    echo -e "\e[34m[+] Fetching IP and Server Information for: $url\e[0m"
    print_separator
    ip=$(ping -c 1 "$url" | grep -oP '(?<=).*?(?=)' | head -n 1)
    server=$(curl -sI "$url" | grep -i "Server" | awk '{print $2}')
    printf "\e[33m%-20s %-30s\e[0m\n" "Info" "Details"
    print_separator
    printf "\e[32m%-20s %-30s\e[0m\n" "IP Address:" "$ip"
    printf "\e[32m%-20s %-30s\e[0m\n" "Server Type:" "${server:-Unknown}"
    print_separator
}

# Main logic
function main() {
    print_banner
    install_dependencies
    while true; do
        print_menu
        read -p "Enter your choice: " choice
        case $choice in
            1)
                read -p "Enter URL (e.g., http://example.com): " url
                vulnerability_scan "$url"
                ;;
            2)
                read -p "Enter IP Address: " ip
                port_scan "$ip"
                ;;
            3)
                file_permission_check
                ;;
            4)
                read -p "Enter Domain (e.g., example.com): " domain
                fetch_ip_server "$domain"
                ;;
            0)
                echo -e "\e[32mExiting. Goodbye!\e[0m"
                exit 0
                ;;
            *)
                echo -e "\e[31mInvalid choice, please try again.\e[0m"
                ;;
        esac
    done
}

main
