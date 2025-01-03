#!/bin/bash 

# set -ex for shell debugging
set -e

exit_fail() {
  echo "$1: retcode $?"
  exit 1
}

if [ "$#" -ne 2 ]; then
  echo -e "$(basename $0) is intended to write a string to a file
Usage:
\t$0 <full_path_to_file> <content_to_write>"
  exit 1
fi

# mkdir -p is smart enough to return 0 (non-error) exit code if directory already exists
mkdir -p $(dirname $1) || exit_fail "Failed to create directory $(dirname $1)"
echo "$2" > "$1" || exit_fail "Failed to write to file $1"
