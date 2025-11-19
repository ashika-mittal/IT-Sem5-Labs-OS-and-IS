#!/bin/bash

# Check if a filename is given
if [ $# -ne 1 ]; then
    echo "Usage: $0 filename"
    exit 1
fi

file="$1"

# Delete even-numbered lines using sed
sed -i 'n;d' "$file"

echo "Even-numbered lines deleted from $file"

