#!/bin/bash

for file in *.txt;do
	sed -i -E 's/^ex:/Example: /g; s/\.ex:/\.Example:/g' "$file"
done
