#!/bin/bash

node=$(which node)
test_path="${BASH_SOURCE[0]}"
solution_path="$(realpath .)"
tmp_dir=$(mktemp -d -t lab1-XXXXXXXXXX)

cd $tmp_dir

rm -rf *
cp $solution_path/*.js .
result=$($"node" lab0.js) ; ret=$?
if [ $ret -ne 0 ] ; then
  echo "[!] Failed"
  exit 1
else
  if [[ $result != "Hello world!" ]]; then
    echo "[!] Failed"
    exit 1
  else
    echo "[V] Pass"
  fi
fi

rm -rf $tmp_dir

exit 0

# vim: set fenc=utf8 ff=unix et sw=2 ts=2 sts=2: