#!/bin/bash

ip tuntap add name tun9 mode tun multi_queue
ip addr add fd5a:5052:1::8080/16 dev tun9
ip link set tun9 up

