# ==============================================================================
# EXPERT ZSH CONFIGURATION
# ==============================================================================

# ------------------------------------------------------------------------------
# SECTION 4: MASTERING HISTORY
# ------------------------------------------------------------------------------
# Set the path to the history file and increase its size dramatically.
export HISTFILE=${ZDOTDIR:-~}/.zsh_history
export HISTSIZE=1000000
export SAVEHIST=1000000

# Set history options for a robust, shared, and de-duplicated history.
setopt SHARE_HISTORY         # Share history instantly across all sessions.
setopt EXTENDED_HISTORY      # Save timestamp and command duration.
setopt HIST_IGNORE_ALL_DUPS  # Remove older duplicate entries from history.
setopt HIST_SAVE_NO_DUPS     # Don't save duplicate entries in the history file.
setopt HIST_IGNORE_SPACE     # Don't save commands that start with a space.
setopt HIST_VERIFY           # Don't execute history expansions immediately.

# ------------------------------------------------------------------------------
# SECTION 6: FINE-TUNING THE ENGINE (ADVANCED SETOPT)
# ------------------------------------------------------------------------------
# Set shell options for an improved interactive experience.
setopt AUTOCD              # If a command is a directory, cd into it.
setopt EXTENDED_GLOB       # Enable more powerful globbing features.
setopt NOCLOBBER           # Prevent > from overwriting existing files.
setopt AUTO_MENU           # Show completion menu on second tab press.
setopt COMPLETE_IN_WORD    # Allow completion from anywhere in a word.
setopt ALWAYS_TO_END       # Move cursor to end of word on completion.

# ------------------------------------------------------------------------------
# SECTION 5: THE ART OF THE ALIAS
# ------------------------------------------------------------------------------
# Source the separate aliases file for better organization.
 && source "${ZDOTDIR:-~}/zsh_aliases"

# ------------------------------------------------------------------------------
# SECTION 3: THE COMMAND CENTER (PROMPT)
# ------------------------------------------------------------------------------
# Load the high-performance gitstatus prompt system.
# Ensure 'gitstatus' is cloned to ~/gitstatus or update the path.
if [ -f ~/gitstatus/gitstatus.prompt.zsh ]; then
  source ~/gitstatus/gitstatus.prompt.zsh
fi

# Configure the prompt.
# Left prompt: Shows the last part of the current directory path in cyan,
# followed by a '$' for normal users or a '#' for root.
PROMPT='%F{cyan}%1~%f ${GITSTATUS_PROMPT} %(!.#.$) '

# Right prompt: Populated by gitstatus.
RPROMPT='${GITSTATUS_PROMPT}'

# ------------------------------------------------------------------------------
# SECTION 2 & 4: CORE ENHANCEMENTS (PLUGINS)
# ------------------------------------------------------------------------------
# Initialize the completion system
autoload -Uz compinit && compinit

# --- zsh-autosuggestions ---
# Must be sourced before zsh-syntax-highlighting.
# Customize the suggestion color to be a light grey.
ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=8'
# Source the plugin (path for Homebrew).
if [ -f "$(brew --prefix)/share/zsh-autosuggestions/zsh-autosuggestions.zsh" ]; then
  source "$(brew --prefix)/share/zsh-autosuggestions/zsh-autosuggestions.zsh"
# Source the plugin (path for standard Linux package managers).
elif [ -f /usr/share/zsh-autosuggestions/zsh-autosuggestions.zsh ]; then
  source /usr/share/zsh-autosuggestions/zsh-autosuggestions.zsh
fi

# --- zsh-history-substring-search ---
# Source the plugin and bind keys.
if [ -f "$(brew --prefix)/share/zsh-history-substring-search/zsh-history-substring-search.zsh" ]; then
  source "$(brew --prefix)/share/zsh-history-substring-search/zsh-history-substring-search.zsh"
elif [ -f /usr/share/zsh-history-substring-search/zsh-history-substring-search.zsh ]; then
  source /usr/share/zsh-history-substring-search/zsh-history-substring-search.zsh
fi
# Bind the arrow keys to search history based on what's already typed.
bindkey '^; then
  source "$(brew --prefix)/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh"
# Source the plugin (path for standard Linux package managers).
elif [ -f /usr/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh ]; then
  source /usr/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh
fi