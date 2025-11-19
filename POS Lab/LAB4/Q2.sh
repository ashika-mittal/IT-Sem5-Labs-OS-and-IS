#!/bin/bash
if [ $# -eq 0 ]; then
	echo "Usage: $0 file1 file2 ..."
	exit 1
fi

for file in "$@"; do
	if [ -f "$file" ]; then
		echo "Do you want to delete $file? (y/n)"
		read ans
		if [ "$ans" = "y" ]; then
			rm "$file"
			echo "$file deleted"
		else
			echo "$file skipped"
		fi
	else
		echo "$file does not exist"
	fi
done	
