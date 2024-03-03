#!/bin/bash

# Check to see is git command line installed in this machine
IS_GIT_AVAILABLE=`git --version`
if [[ $IS_GIT_AVAILABLE == *"version"* ]]; then
    echo "git is Available"
else
    echo "git is not installed"
    exit 1
fi

function dotconfig {
    /usr/bin/git --git-dir=$HOME/.cfg/ --work-tree=$HOME "$@"
}


# Check git status
gs="$(dotconfig status | grep -i "modified")"


# If there is a new change
if [[ $gs == *"modified"* ]]; then
    echo "push"
else
    echo "no change detected"
    exit 1
fi



# push to Github
UPDATE_COMMENT_UNIQUE_SUFFIX_OWO="Backup_`date +'%Y-%m-%d_%H:%M:%S'` $*"

dotconfig add -u
dotconfig commit -m "${UPDATE_COMMENT_UNIQUE_SUFFIX_OWO}"
dotconfig push
