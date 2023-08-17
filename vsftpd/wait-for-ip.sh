#! /bin/bash
default_interface="$(ip route | awk '/default/ { print $5 }' | grep -v "vmbr")"
while ! ip -4 addr show dev "$default_interface" | grep -q "inet "; do
    sleep 1
done 
echo "IP discovered on $default_interface!"
