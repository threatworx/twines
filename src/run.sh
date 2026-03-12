#!/bin/bash

echo "Starting zeek in the background"
/opt/zeek/bin/zeek -B all -i $LISTEN_ON -C /usr/share/twines/twines.zeek &

echo "Starting twines loop"
while true; do
  python /usr/share/twines/twines.py run --log-dir /opt/zeek/logs
  sleep 5
done
