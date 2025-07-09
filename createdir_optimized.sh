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

# Placeholder functions for file creation (to be defined separately)
_create_external_files() { local -n failed_ref=$1; }
_create_internal_files() { local -n failed_ref=$1; }
_create_webapp_files() { local -n failed_ref=$1; }
_create_assessment_readme() { local type=$1; }
