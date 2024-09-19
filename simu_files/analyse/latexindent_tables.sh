#!/bin/bash

# Set the directory where your .tex files are located
directory="table_1/"

# Loop through all .tex files in the directory
for file in "$directory"*.tex; do
  # Apply latexindent to each file
  latexindent "$file" -w
done
