#!/usr/bin/env bash

# Exit if any command fails
set -e

# Fetch the source remote
git fetch fork

# Checkout source main with detached head
git checkout fork/incorporate-go@{0}

# Reset to main branch with unstaged changes
git reset --soft debian

# Make sure debian specific files are not deleted
git checkout debian -- update.sh debian

# Commit changes for new source
git commit -m "Update source"

# Rename the branch to the main one
git checkout -b temp
git branch -M debian

# push
git push fork
