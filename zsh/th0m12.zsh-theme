# This is a Zsh configuration file that sets up various options, keybindings,
# and prompt styles for a personalized shell experience.
# Set the theme for the terminal (optimized for readability and information density)
PROMPT=$'%F{%(?.green.red)}• %B%F{#e95420}%1~ %B%F{magenta}➜  %b%f'

setopt autocd              # change directory just by typing its name
#setopt correct            # auto correct mistakes
setopt interactivecomments # allow comments in interactive mode
setopt magicequalsubst     # enable filename expansion for arguments of the form ‘anything=expression’
setopt nonomatch           # hide error message if there is no match for the pattern
setopt notify              # report the status of background jobs immediately
setopt numericglobsort     # sort filenames numerically when it makes sense
setopt promptsubst         # enable command substitution in prompt

WORDCHARS=${WORDCHARS//\/} # Don't consider certain characters part of the word

# Hide EOL sign ('%') for cleaner prompt
PROMPT_EOL_MARK=""

# Configure keybindings for improved navigation and editing
bindkey -e                                        # emacs key bindings
bindkey ' ' magic-space                           # do history expansion on space
bindkey '^U' backward-kill-line                   # ctrl + U
bindkey '^[[3;5~' kill-word                       # ctrl + Supr
bindkey '^[[3~' delete-char                       # delete
bindkey '^[[1;5C' forward-word                    # ctrl + right arrow
bindkey '^[[1;5D' backward-word                   # ctrl + left arrow
bindkey '^[[5~' beginning-of-buffer-or-history    # page up
bindkey '^[[6~' end-of-buffer-or-history          # page down
bindkey '^[[H' beginning-of-line                  # home
bindkey '^[[F' end-of-line                        # end
bindkey '^[[Z' undo                               # shift + tab undo last action

# enable completion features
autoload -Uz compinit # Load completion system
compinit -d ~/.cache/zcompdump
zstyle ':completion:*:*:*:*:*' menu select
zstyle ':completion:*' auto-description 'specify: %d'
zstyle ':completion:*' completer _expand _complete
zstyle ':completion:*' format 'Completing %d'
zstyle ':completion:*' group-name ''
zstyle ':completion:*' list-colors ''
zstyle ':completion:*' list-prompt %SAt %p: Hit TAB for more, or the character to insert%s
zstyle ':completion:*' matcher-list 'm:{a-zA-Z}={A-Za-z}'
zstyle ':completion:*' rehash true
zstyle ':completion:*' select-prompt %SScrolling active: current selection at %p%s
zstyle ':completion:*' use-compctl false
zstyle ':completion:*' verbose true
zstyle ':completion:*:kill:*' command 'ps -u $USER -o pid,%cpu,tty,cputime,cmd' # Show more info for kill completion

NEWLINE_BEFORE_PROMPT=yes
precmd() {
    # Print the previously configured terminal title, if any
    if [[ -n "$TERM_TITLE" ]]; then
        print -Pnr -- "$TERM_TITLE"
    fi

    # Print a new line before the prompt, but only if it's not the very first prompt
    if [ "$NEWLINE_BEFORE_PROMPT" = yes ]; then
        if [[ -n "$_NEW_LINE_BEFORE_PROMPT_FLAG" ]]; then
            print ""
        fi
    fi
}

# Set autosuggestions color
ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=5'
