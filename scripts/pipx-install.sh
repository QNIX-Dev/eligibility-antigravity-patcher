#!/usr/bin/env bash

set -e

while IFS= read -r package || [[ -n "$package" ]]; do
    # Skip empty lines and comments
    [[ -z "$package" || "$package" =~ ^[[:space:]]*# ]] && continue

    echo "Installing: $package"
    pipx install "$package"

done < requirements.txt
