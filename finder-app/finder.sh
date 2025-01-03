#!/bin/bash 

# set -ex for shell debugging
set -e

exit_fail() {
  echo "$1: retcode $?"
  exit 1
}

if [ "$#" -ne 2 ]; then
  echo -e "$(basename $0) is intended to find a string in files in a directory
Usage:
\t$0 <directory_to_search> <search_string>
\t<search_string> is a grep-compatible regular expression"
  exit 1
fi

directory_to_search=$1
grep_mask=$2

if [ ! -d "$directory_to_search" ]; then
  exit_fail "$directory_to_search is not a directory"
fi

files="$(find "$directory_to_search" | wc -l)"
lines="$(grep -r "$grep_mask" "$directory_to_search" | wc -l)"

echo "The number of files are $files and the number of matching lines are $lines"