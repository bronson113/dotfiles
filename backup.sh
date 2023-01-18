#!/bin/bash

# Check to see is git command line installed in this machine
IS_GIT_AVAILABLE=`git --version`
if [[ $IS_GIT_AVAILABLE == *"version"* ]]; then
  echo "Git is Available"
else
  echo "Git is not installed"
  exit 1
fi

function dotconfig {
    /usr/bin/git --git-dir=$HOME/.cfg/ --work-tree=$HOME $@
}

# Check git status
gs="$(dotconfig status | grep -i "modified")"


# If there is a new change
if [[ $gs == *"modified"* ]]; then
  echo "push"
fi


# push to Github
dotconfig commit -am "Backup `date +'%Y-%m-%d %H:%M:%S'`";
dotconfig push
