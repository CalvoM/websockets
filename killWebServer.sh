#!/bin/bash
PORT=$1
PID=`sudo netstat -ntlp | grep -e ":$PORT" | awk '{print $7}'|awk 'BEGIN{FS="/";}{print $1}'`
if [ "$PID" == "" ];then
    echo "Port not open, please confirm"
    exit 1
fi
kill -9 $PID
