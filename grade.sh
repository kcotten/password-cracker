#!/bin/bash

# Copyright (C) 2018 David C. Harrison - All Rights Reserved.
# You may not use, distribute, or modify this code without 
# the written permission of the copyright holder.

total=0;

check()
{
    TAG=$1
    NAME=$2
    MARKS=$3

    grep $TAG check.out > /dev/null
    if [ $? -eq 0 ]
    then
        printf "%10s:" $NAME
        set `grep $TAG check.out`
        if [ "$2" == "PASS" ]
        then
            total=$(( total + $MARKS ))
            printf "%4s/%3s\n" $MARKS $MARKS
        else
            printf "%4s/%3s\n" "0" $MARKS
        fi
    else
        printf "%10s:   0/%3s\n" $NAME $MARKS
    fi
}

printf "\n%s\n\n" "CMPS122 Winter 2019 Lab 1"

check 'CrackSingle: '   'Basic'    50
check 'CrackMultiple: ' 'Advanced' 30
check 'CrackSpeedy: '   'Stretch'  10
check 'CrackStealthy: ' 'Extreme'  10

printf "\n%10s: %3s/100\n\n" "Total" $total 

