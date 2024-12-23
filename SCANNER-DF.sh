#!/bin/bash
#MYCODE-@A_Y_TR
#آلقيـــــــــــــــآدهہ‌‏ آلزعيـــم


function print_banner() {
    echo -e "\e[36m
    ##############################################
    #               SCANNER DF                  #
    ##############################################
    #           Designed by @A_Y_TR             #
    ##############################################
    \e[0m"
}


function print_separator() {
    echo -e "\e[36m----------------------------------------\e[0m"
}


function print_table_headers() {
    printf "\e[33m%-40s %-15s\e[0m\n" "Vulnerability" "Status"
    print_separator
}


function print_menu() {
    echo -e "\e[33m
    Choose an option:
    1. Vulnerability Scan (All)
    2. Nmap Port Scan
    3. Website File Check
    4. Website Analysis
    0. Exit
    \e[0m"
}


function vulnerability_scan() {
    local url="$1"
    echo -e "\e[34m[+] Starting Vulnerability Scan for: $url\e[0m"
    print_separator

    declare -A tests=(
        ["SQL Injection"]="q=' OR '1'='1"
        ["Cross-Site Scripting (XSS)"]="q=<script>alert('XSS')</script>"
        ["Cross-Site Request Forgery (CSRF)"]="q=csrf_test"
        ["Remote Code Execution (RCE)"]="q=;ls"
        ["Buffer Overflow"]="q=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ["Directory Traversal"]="q=../../../../etc/passwd"
        ["Privilege Escalation"]="q=whoami"
        ["Man-in-the-Middle (MITM) Attack"]="q=mitm"
        ["Broken Authentication"]="q=broken_auth"
        ["Sensitive Data Exposure"]="q=password123"
        ["XML External Entity (XXE) Injection"]="q='<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>'"
        ["Insecure Deserialization"]="q=O:11:\"TestClass\":1:{s:4:\"name\";s:4:\"test\";}"
        ["Denial of Service (DoS)"]="q=load-test"
        ["Server-Side Request Forgery (SSRF)"]="q=http://localhost"
        ["Clickjacking"]="q=<iframe src=\"http://example.com\"></iframe>"
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


function website_file_check() {
    local url="$1"
    echo -e "\e[34m[+] Checking Website Files for: $url\e[0m"
    print_separator

    
    declare -a files=(
        "index.html" "robots.txt" "sitemap.xml" "admin.php" "config.php"
        "wp-login.php" "wp-config.php" "login.php" "db.php" "backup.zip"
        ".env" "README.md" "LICENSE.txt" "install.php" "error_log"
        "web.config" ".htaccess" ".git/config" "phpinfo.php" "debug.log"
    )

    print_table_headers

    
    for file in "${files[@]}"; do
        response=$(curl -s -o /dev/null -w "%{http_code}" "$url/$file")
        if [[ "$response" -eq 200 ]]; then
            printf "\e[32m%-40s %-15s\e[0m\n" "$file" "Found"
        else
            printf "\e[31m%-40s %-15s\e[0m\n" "$file" "Not Found"
        fi
    done

    print_separator
}


function website_analysis() {
    local url="$1"
    echo -e "\e[34m[+] Analyzing Website: $url\e[0m"
    print_separator
    
    response_time=$(curl -o /dev/null -s -w "%{time_total}" "$url")
    
    links=$(curl -s "$url" | grep -o "<a " | wc -l)
    internal_links=$(curl -s "$url" | grep -o "<a href=\"/$url" | wc -l)
    external_links=$((links - internal_links))

    printf "\e[33m%-25s %-20s\e[0m\n" "Metric" "Value"
    print_separator
    printf "\e[32m%-25s %-20s\e[0m\n" "Response Time (s):" "$response_time"
    printf "\e[32m%-25s %-20s\e[0m\n" "Total Links:" "$links"
    printf "\e[32m%-25s %-20s\e[0m\n" "Internal Links:" "$internal_links"
    printf "\e[32m%-25s %-20s\e[0m\n" "External Links:" "$external_links"
    print_separator
}


function main() {
    print_banner
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
                read -p "Enter Website URL (e.g., http://example.com): " url
                website_file_check "$url"
                ;;
            4)
                read -p "Enter Website URL (e.g., http://example.com): " url
                website_analysis "$url"
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
