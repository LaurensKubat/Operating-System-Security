#!/bin/bash

FILE="/tmp/communication.txt"
if test -f "$FILE"; then
    echo "$FILE exists."
fi