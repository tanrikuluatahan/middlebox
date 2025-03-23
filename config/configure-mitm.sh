#!/bin/bash

echo "$INSECURENET_HOST_IP insec" >> /etc/hosts
echo "$SECURENET_HOST_IP sec" >> /etc/hosts

echo 'Printing environment'
echo "Route net is ${SECURE_NET}"
echo "Route gateway is ${SECURENET_GATEWAY}"

sysctl -w net.ipv4.ip_forward=0
sysctl -p

# This following pings adds the MAC addresses to the ARP table
ping sec -c 1
ping insec -c 1


make clean
make

$(./switch >& /proc/1/fd/1)

while true; 
    do sleep 0.01;
    done
