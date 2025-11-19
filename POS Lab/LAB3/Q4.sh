#!/bin/bash

echo "Enter basic : "
read basic

echo "Enter TA :"
read ta

gs=$(echo "$basic + $ta + 0.1*$basic" | bc -l)
echo "Gross Salary : $gs" 
