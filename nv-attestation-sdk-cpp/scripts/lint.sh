#!/bin/bash
# Lint the SDK with clang-tidy.
# This script can be run from any directory.
# By default, it only lints changed files compared to origin/main.
# Use --all to lint all files.

set -euo pipefail

readonly SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
readonly PROJECT_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"
readonly BUILD_DIR="$PROJECT_DIR/build"
readonly COMPILE_COMMANDS_FILE="$BUILD_DIR/compile_commands.json"

# Function to get changed files
get_changed_files() {
    local changed_files=""
    
    # Check if running in GitLab CI
    if [ -n "${CI:-}" ] && [ -n "${GITLAB_CI:-}" ]; then
        echo "Running in GitLab CI" >&2
        
        local target_branch="origin/main"
        
        # In GitLab CI, use merge request target branch if available
        if [ -n "${CI_MERGE_REQUEST_TARGET_BRANCH_NAME:-}" ]; then
            target_branch="origin/${CI_MERGE_REQUEST_TARGET_BRANCH_NAME}"
        fi
        
        echo "Comparing against: $target_branch" >&2
        
        # Get changed .cpp files in src directory
        changed_files=$(git diff --name-only --diff-filter=ACMR --relative "$target_branch"...HEAD | grep -E '^src/.*\.cpp$' || true)
    else
        echo "Running on host machine" >&2
        
        # Get committed changes between HEAD and origin/main
        local committed_files=$(git diff --name-only --diff-filter=ACMR --relative origin/main...HEAD | grep -E '^src/.*\.cpp$' || true)
        
        # Get uncommitted changes
        local uncommitted_files=$(git diff --name-only --diff-filter=ACMR --relative HEAD | grep -E '^src/.*\.cpp$' || true)
        
        # Combine both sets of files and remove duplicates
        changed_files=$(echo -e "$committed_files\n$uncommitted_files" | sort -u | grep -v '^$' || true)
        
        echo "Committed changes (HEAD...origin/main): $committed_files" >&2
        echo "Uncommitted changes: $uncommitted_files" >&2
    fi
    
    echo "$changed_files"
}

echo "--- Linting SDK ---"
cd "$PROJECT_DIR"

if [ ! -f "$COMPILE_COMMANDS_FILE" ]; then
   echo "$COMPILE_COMMANDS_FILE not found. Build the SDK first."
   exit 1
fi

# Check if --all flag is provided
if [ "${1:-}" = "--all" ]; then
    echo "Running on all files"
    source_files=$(find src -name '*.cpp')
    echo "Source files found: $source_files"
else
    # Default: only lint changed files
    echo "Running on changed files only (use --all to lint all files)"
    changed_files=$(get_changed_files)
    
    if [ -z "$changed_files" ]; then
        echo "No .cpp files changed in src directory. Skipping clang-tidy."
        exit 0
    fi
    
    echo "Changed .cpp files found:"
    echo "$changed_files"
    source_files="$changed_files"
fi

# Run clang-tidy on the determined files
if [ -n "$source_files" ]; then
    echo "Running clang-tidy on files..."
    clang-tidy -p="$COMPILE_COMMANDS_FILE" --quiet $source_files
    echo "Linting completed successfully"
else
    echo "No source files to lint"
fi