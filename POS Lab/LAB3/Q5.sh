#!/bin/bash

echo "Enter file extention :"
read ext

echo "Enter target foldef name :"
read target

mkdir -p "$target"

for file in *."$ext";do
	[ -f "$file" ] && cp "$file" "$target/"
done
