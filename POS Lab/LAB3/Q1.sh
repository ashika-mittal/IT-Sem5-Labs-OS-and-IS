#!/bin/bash

echo "Enter File Name : "
read file

if [ -d "$file" ]; then
	echo "$file is a directory."
elif [ -f "$file" ]; then
	echo "$file is a regular file."
else
	echo "$file does not exist."
fi
