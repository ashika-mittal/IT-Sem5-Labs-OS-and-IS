#!/bin/bash
find . -type f -name "*.text" | while read file; do
	newname=$(echo "$file" | sed 's/\.text$/.txt/')
	mv "$file" "$newname"
done    
