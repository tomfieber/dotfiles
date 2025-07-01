# Install Tools Script Improvements

## Summary of Changes

The `install-tools.sh` script has been significantly improved for better efficiency, robustness, and user experience.

## Key Improvements

### 1. **Enhanced Error Handling**
- **Graceful failures**: Script continues even if individual installations fail
- **Better error tracking**: Maintains lists of successful, failed, and skipped installations
- **Comprehensive logging**: All operations logged with timestamps

### 2. **Dependency Checking**
- **Prerequisite validation**: Checks for essential tools before starting
- **Package manager detection**: Automatically skips tools if package managers are unavailable
- **Already installed checks**: Prevents duplicate installations

### 3. **Architecture & OS Detection**
- **Smart architecture mapping**: Automatically detects and maps system architecture
- **Cross-platform support**: Works on different architectures (x86_64, arm64, etc.)
- **OS-specific downloads**: Uses correct binaries for the detected system

### 4. **Performance Optimizations**
- **Shallow git clones**: Uses `--depth 1` for faster repository cloning
- **Parallel-ready**: Functions designed to support parallel execution
- **Reduced redundancy**: Eliminated duplicate installations

### 5. **Better User Experience**
- **Installation summary**: Shows counts and lists of successful/failed/skipped installations
- **Progress indicators**: Clear visual feedback during installations
- **Colored output**: Green for success, red for errors, yellow for warnings

### 6. **Robustness Features**
- **Duplicate removal**: Eliminated duplicate entries in pipx installations
- **Path management**: Better handling of binary paths and symlinks
- **Tool availability checks**: Verifies tools are available before attempting installation

## New Functions

### `check_prerequisites()`
Validates that essential tools are available before starting installations.

### `is_installed()`
Checks if a package is already installed for different package managers.

### `command_exists()`
Simple utility to check if a command is available in PATH.

### `create_directories()`
Safely creates required directories with proper error handling.

### `print_summary()`
Displays a comprehensive summary of all installation results.

## Installation Flow

1. **Setup & Validation**
   - Check prerequisites
   - Detect system architecture
   - Create necessary directories

2. **Conditional Installations**
   - Only install if package manager is available
   - Skip if already installed
   - Continue on individual failures

3. **Summary & Cleanup**
   - Display installation results
   - Show log file location
   - Provide failure details

## Usage

```bash
# Make script executable
chmod +x install-tools.sh

# Run the script (installs core tools only)
./install-tools.sh

# Run with GitHub tools included
./install-tools.sh --github-tools

# Show help
./install-tools.sh --help

# Check the log file for details
tail -f ~/.local/logging/install-tools-*.log
```

## Command Line Options

### `--github-tools`
- **Purpose**: Install GitHub-based security tools that are cloned to `/opt/tools`
- **Default**: Disabled (tools are skipped by default)
- **Includes**: ~30 security tools like Responder, BloodHound.py components, enumeration tools, etc.
- **Why optional**: These tools require significant disk space and may not be needed in all environments

### `--help` or `-h`
- Shows usage information and available options

## Dry Run Testing

A dry-run version is available for testing:

```bash
chmod +x install-tools-dry-run.sh
./install-tools-dry-run.sh
```

## Log Files

All operations are logged to `~/.local/logging/install-tools-YYYYMMDDHHMMSS.log` with:
- Timestamps for all operations
- Error details for troubleshooting
- Success confirmations

## Error Recovery

The script now:
- Continues execution even if individual tools fail
- Provides clear feedback on what failed and why
- Maintains a summary of all operations
- Suggests checking log files for details

## Architecture Support

Automatically detects and supports:
- x86_64 / amd64
- aarch64 / arm64  
- armv7l
- Fallback to amd64 for unknown architectures

This makes the script more reliable across different systems and reduces manual intervention requirements.
