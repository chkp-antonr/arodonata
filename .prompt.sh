#!/bin/bash
# Project-specific bash prompt
# Source this file from your project directory: source .prompt.sh

if [ -f ".venv/bin/activate" ]; then
    # shellcheck source=.venv/bin/activate
    . ".venv/bin/activate"
fi

# Store original PS1 for restoration if not already saved
if [ -z "$_ORIGINAL_PS1" ]; then
    export _ORIGINAL_PS1="$PS1"
fi

# Set project root (directory where this script lives)
export PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PROJECT_NAME="$(basename "$PROJECT_ROOT")"

# Source git-prompt if __git_ps1 is not already available
if ! declare -f __git_ps1 &>/dev/null; then
    candidate_files=(
        "$HOME/.git-prompt.sh"
        "/Library/Developer/CommandLineTools/usr/share/git-core/git-prompt.sh"
        "/Applications/Xcode.app/Contents/Developer/usr/share/git-core/git-prompt.sh"
        "/usr/share/git/completion/git-prompt.sh"
        "/usr/share/git-core/contrib/completion/git-prompt.sh"
        "/usr/lib/git-core/git-sh-prompt"
        "/etc/bash_completion.d/git-prompt"
        "/usr/share/bash-completion/completions/git-prompt.sh"
        "/opt/homebrew/share/git-core/contrib/completion/git-prompt.sh"
        "/opt/homebrew/etc/bash_completion.d/git-prompt.sh"
        "/usr/local/share/git-core/contrib/completion/git-prompt.sh"
        "/usr/local/etc/bash_completion.d/git-prompt.sh"
    )
    if command -v brew &>/dev/null; then
        brew_prefix="$(brew --prefix 2>/dev/null)"
        if [ -n "$brew_prefix" ]; then
            candidate_files+=(
                "$brew_prefix/share/git-core/contrib/completion/git-prompt.sh"
                "$brew_prefix/etc/bash_completion.d/git-prompt.sh"
            )
        fi
    fi

    for file in "${candidate_files[@]}"; do
        if [ -f "$file" ]; then
            # shellcheck disable=SC1090
            source "$file" && break
        fi
    done
fi

# Fallback implementation of __git_ps1 if git-prompt is not installed
if ! declare -f __git_ps1 &>/dev/null; then
    __git_ps1() {
        local format="${1:- (%s)}"
        local branch
        branch=$(git symbolic-ref --short HEAD 2>/dev/null || git rev-parse --short HEAD 2>/dev/null)
        if [ -n "$branch" ]; then
            # shellcheck disable=SC2059
            printf "$format" "$branch"
        fi
    }
fi

# Enable git status indicators
export GIT_PS1_SHOWDIRTYSTATE=1
export GIT_PS1_SHOWUNTRACKEDFILES=1

# Function to show relative path from project root
parse_relative_path() {
    local cwd="$(pwd)"
    if [[ "$cwd" == "$PROJECT_ROOT"* ]]; then
        local relative="${cwd#$PROJECT_ROOT}"
        if [ -z "$relative" ]; then
            echo ""
        else
            echo "/${relative#/}"
        fi
    else
        echo "/...$cwd"
    fi
}

# Function to show project name from venv
parse_project_name() {
    if [ -n "$VIRTUAL_ENV" ]; then
        echo "($(basename "$(dirname "$VIRTUAL_ENV")"))"
    else
        echo "($PROJECT_NAME)"
    fi
}

# Set the custom prompt
# Format: [git-branch] (project-name)/relative-path/$
export PS1='\[\e]0;\u@\h: \w\a\]\[\033[01;33m\]$(__git_ps1 "[%s] ")\[\033[01;36m\]$(parse_project_name)\[\033[00m\]$(parse_relative_path)\[\033[01;32m\]\$\[\033[00m\] '

echo "✓ Custom prompt loaded for this session"
echo "  Project: $PROJECT_NAME"
echo "  Root: $PROJECT_ROOT"
echo "  To restore original: source .prompt.restore.sh"
