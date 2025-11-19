#!/bin/bash

if [ $# -ne 2 ]; then
    echo "Usage: $0 {-linecount|-wordcount|-charcount} filename"
    exit 1
fi

case $1 in
    -linecount)
        wc -l < "$2"
        ;;
    -wordcount)
        wc -w < "$2"
        ;;
    -charcount)
        wc -m < "$2"
        ;;
    *)
        echo "Invalid option. Use -linecount, -wordcount, or -charcount"
        ;;
esac

