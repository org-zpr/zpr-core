#!/bin/sh

HOOKS="pre-commit"
PATH_TO_HOOKS=../.git/hooks
PATH_TO_SCRIPT=$(cd "$(dirname "$0")"; pwd -P)

cd "$PATH_TO_SCRIPT"

for hook in $HOOKS; do
    # Checks if there is an existing hook with the same name, archives it
    if [ -f $PATH_TO_HOOKS/$hook -a -x $PATH_TO_HOOKS/$hook ]
    then 
        mv $PATH_TO_HOOKS/$hook $PATH_TO_HOOKS/$hook.old
    fi 

    #ln -s -f $hook $PATH_TO_HOOKS/$hook TODO not sure if symlink is better
    cp $hook $PATH_TO_HOOKS

done