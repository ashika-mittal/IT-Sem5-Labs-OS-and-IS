#!/bin/bash

# User-defined bubble sort
sort_strings() {
    n=$#                # number of arguments
    args=("$@")         # store arguments in array

    for ((i=0; i<n; i++)); do
        for ((j=i+1; j<n; j++)); do
            if [[ "${args[i]}" > "${args[j]}" ]]; then
                temp=${args[i]}
                args[i]=${args[j]}
                args[j]=$temp
            fi
        done
    done

    echo "Sorted strings:"
    for str in "${args[@]}"; do
        echo "$str"
    done
}

# Call the function with all command line args
sort_strings "$@"

