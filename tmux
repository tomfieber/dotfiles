# History
set -g history-limit 50000

set -g default-terminal "screen-256color"

#set -g status-bg orange
#set -g status-fg black

# Rebind prefix key
# remap prefix from 'C-b' to 'C-a'
#unbind C-b
#set-option -g prefix C-a
#bind-key C-a send-prefix

unbind %
bind v split-window -h

unbind '"'
bind h split-window -v

unbind r
bind r source-file ~/.tmux.conf


bind -r m resize-pane -Z

set -g mouse on

unbind -T copy-mode-vi MouseDragEnd1Pane # don't exit copy mode when dragging with mouse

set-window-option -g mode-keys vi

# Shift arrow to switch windows
bind -n S-Left  previous-window
bind -n S-Right next-window

# Use Alt-arrow keys without prefix key to switch panes
bind -n M-Left select-pane -L
bind -n M-Right select-pane -R
bind -n M-Up select-pane -U
bind -n M-Down select-pane -D

# Copy
#for copying to sys clipboard
bind-key -T copy-mode-vi 'v' send -X begin-selection # start selecting text with "v"
bind-key -T copy-mode-vi 'y' send -X copy-selection # copy text with "y"
bind -T copy-mode-vi Enter send-keys -X copy-pipe-and-cancel "xclip -i -f -selection primary | xclip -i -selection clipboard"
bind -T copy-mode-vi MouseDragEnd1Pane send-keys -X copy-pipe-and-cancel "xclip -i -f -selection primary | xclip -i -selection clipboard"
#bind -T copy-mode-vi C-j send-keys -X copy-pipe-and-cancel "xclip -i -f -selection primary | xclip -i -selection clipboard"

# List of plugins

set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
set -g @plugin 'tmux-plugins/tmux-logging'
set -g @plugin 'tmux-plugins/tmux-resurrect' # persist tmux sessions after computer restart
set -g @plugin 'tmux-plugins/tmux-continuum' # automatically saves sessions for you every 15 minutes

# Logging path
set -g @logging-path "$PWD/.tmuxlogging"

# VPN Config
set -g status-right "#( /opt/tools/vpnpanel.sh ) #H %H:%M %d.%m.%Y "

# Initialize TMUX plugin manager (keep at bottom)
run '~/.tmux/plugins/tpm/tpm'
