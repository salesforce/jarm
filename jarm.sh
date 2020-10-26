#!/bin/bash

if [ ! $# -eq 2 ]
    then
    echo "Two arguments required: (1) a list of IPs/domains in a"
    echo "file, separated by line and (2) an output file name."
    echo "Example: ./jarm.sh alexa500.txt jarm_alexa_500.csv"
    exit 1
 fi

input=$1
while IFS= read -r line
do
  python3 jarm.py $line -v -o $2 &
done < "$input"

wait
