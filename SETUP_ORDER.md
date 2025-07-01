# Setup Order and Dependencies

This document outlines the proper order of execution for the setup scripts to ensure all dependencies are met.

## Execution Order

### 1. Initial System Setup
**Script:** `initial_setup.sh`

**What it does:**
- Installs system packages from `requirements.txt`
- Sets up logging directories
- Installs Go, Rust, and pyenv
- **NEW: Installs Oh My Zsh (if using zsh shell)**
- **NEW: Installs zsh plugins (zsh-autosuggestions, zsh-syntax-highlighting)**
- Sets up environment variables
- Updates shell profile

**Dependencies:** None (this is the first script to run)

**Note:** This script now includes Oh My Zsh installation to ensure it's available before any configuration files that depend on it are copied.

### 2. Configuration Files Deployment
**Script:** `configuration_files.sh`

**What it does:**
- Copies configuration files to appropriate locations
- Copies zsh theme to `~/.oh-my-zsh/themes/` (now checks if Oh My Zsh exists first)
- Sets up aliases and shortcuts
- Copies tmux configuration

**Dependencies:** 
- `initial_setup.sh` must be run first (for Oh My Zsh installation)
- Oh My Zsh must be installed for theme copying

### 3. Additional Tools Installation
**Script:** `install-tools.sh`

**What it does:**
- Installs various security and development tools
- **UPDATED: Now checks if zsh plugins are already installed from initial setup**
- Installs tools via Go, cargo, pip, etc.
- Optionally installs GitHub-based tools (with `--github-tools` flag)

**Dependencies:**
- `initial_setup.sh` (for Go, Rust, pyenv)
- Optionally `configuration_files.sh` if you want configurations in place

## Recommended Execution Sequence

```bash
# 1. Run initial setup (includes Oh My Zsh and plugins)
./initial_setup.sh

# 2. Deploy configuration files
./configuration_files.sh

# 3. Install additional tools
./install-tools.sh --github-tools  # include --github-tools if desired

# 4. Restart shell or source profile
source ~/.zshrc  # or source ~/.bashrc if using bash
```

## Key Improvements Made

### 1. Oh My Zsh Installation Integration
- **Before:** Oh My Zsh installation was scattered across different scripts
- **After:** Centralized in `initial_setup.sh` with proper error handling and dependency checks

### 2. Plugin Installation Order
- **Before:** Plugins were installed in `install-tools.sh` without ensuring Oh My Zsh was available
- **After:** Plugins are installed right after Oh My Zsh in `initial_setup.sh`, with fallback checking in `install-tools.sh`

### 3. Theme Deployment Safety
- **Before:** `configuration_files.sh` blindly tried to copy theme to Oh My Zsh directory
- **After:** Script checks if Oh My Zsh exists before attempting theme copy

### 4. Better Error Messages
- Added informative error messages that guide users to run `initial_setup.sh` first
- Improved logging throughout the process

## Alternative: Unified Setup Script

If you prefer a single script approach, consider using `setup.sh` which appears to combine functionality from multiple scripts. However, the modular approach allows for more flexibility and easier debugging.

## Troubleshooting

### Oh My Zsh Not Found
If you see "Oh My Zsh not found" errors:
1. Ensure you're using zsh as your shell: `echo $SHELL`
2. Run `initial_setup.sh` which will install Oh My Zsh
3. If installation fails, check internet connectivity
4. Look at the log file for detailed error messages

### Theme Not Loading
If the custom theme doesn't load:
1. Ensure Oh My Zsh is installed: `ls -la ~/.oh-my-zsh`
2. Check if theme file exists: `ls -la ~/.oh-my-zsh/themes/th0m12.zsh-theme`
3. Run `configuration_files.sh` to copy the theme file
4. Restart your shell or run `source ~/.zshrc`

### Plugins Not Working
If zsh plugins aren't working:
1. Check if plugins are installed: `ls -la ~/.oh-my-zsh/custom/plugins/`
2. Verify plugins are listed in `~/.zshrc` plugins array
3. Run `initial_setup.sh` to install missing plugins
4. Restart your shell
