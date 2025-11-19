#!/bin/bash

if [ $# -lt 2 ]; then
    echo "Usage: $0 inputfile pattern1 [pattern2 ...]"
    exit 1
fi

file="$1"
shift
patterns=("$@")

while true; do
    echo "Menu:"
    echo "1. Search patterns in file"
    echo "2. Delete all occurrences of patterns in file"
    echo "3. Exit"
    read -p "Enter choice: " choice

    case $choice in
        1)
            for pattern in "${patterns[@]}"; do
                echo "Lines containing '$pattern':"
                grep "$pattern" "$file"
            done
            ;;
        2)
            for pattern in "${patterns[@]}"; do
                sed -i "s/$pattern//g" "$file"
                echo "Removed occurrences of '$pattern'"
            done
            ;;
        3)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid choice"
            ;;
    esac
done

