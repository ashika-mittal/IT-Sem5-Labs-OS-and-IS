#!/bin/bash


echo "Enter Pattern : "
read pattern

find . -maxdepth 1 -type f -name "*$pattern*" -exec basename {} \;

