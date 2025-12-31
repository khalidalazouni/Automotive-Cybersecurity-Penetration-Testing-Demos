#!/bin/bash
# ========================================================
# Network Namespace Lab Setup Script
# 4 namespaces (node1–node4) connected via bridge br0
# node1/node2 -> IPv4
# node3/node4 -> IPv6
# ========================================================

set -e

echo " Cleaning old setup (if any)..."
# Clean up if rerun
for ns in node1 node2 node3 node4; do
    ip netns del $ns 2>/dev/null || true
done
ip link del br0 2>/dev/null || true
ip link del veth1-br 2>/dev/null || true
ip link del veth2-br 2>/dev/null || true
ip link del veth3-br 2>/dev/null || true
ip link del veth4-br 2>/dev/null || true

echo " Creating network namespaces..."
ip netns add node1
ip netns add node2
ip netns add node3
ip netns add node4

echo " Creating bridge br0..."
ip link add br0 type bridge
ip link set br0 up

echo " Creating veth pairs..."
ip link add veth1 type veth peer name veth1-br
ip link add veth2 type veth peer name veth2-br
ip link add veth3 type veth peer name veth3-br
ip link add veth4 type veth peer name veth4-br

echo " Connecting veth ends to namespaces..."
ip link set veth1 netns node1
ip link set veth2 netns node2
ip link set veth3 netns node3
ip link set veth4 netns node4

echo " Attaching bridge-side veth ends to br0..."
ip link set veth1-br master br0
ip link set veth2-br master br0
ip link set veth3-br master br0
ip link set veth4-br master br0

echo " Bringing up bridge-side interfaces..."
ip link set veth1-br up
ip link set veth2-br up
ip link set veth3-br up
ip link set veth4-br up

echo " Assigning IP addresses..."
# IPv4 for node1 and node2
ip netns exec node1 ip addr add 10.0.0.1/24 dev veth1
ip netns exec node2 ip addr add 10.0.0.2/24 dev veth2

# IPv6 for node3 and node4
ip netns exec node3 ip addr add fd00:1::1/64 dev veth3
ip netns exec node4 ip addr add fd00:1::2/64 dev veth4

echo " Bringing up interfaces inside namespaces..."
for ns in node1 node2 node3 node4; do
    ip netns exec $ns ip link set lo up
done

ip netns exec node1 ip link set veth1 up
ip netns exec node2 ip link set veth2 up
ip netns exec node3 ip link set veth3 up
ip netns exec node4 ip link set veth4 up

echo " Setup complete!"
echo
echo " Verifying namespaces and interfaces..."
ip netns list
echo
ip netns exec node1 ip -br addr
ip netns exec node2 ip -br addr
ip netns exec node3 ip -br addr
ip netns exec node4 ip -br addr

echo
echo " Testing connectivity..."
echo "IPv4 test: node1 -> node2"
ip netns exec node1 ping -c 3 10.0.0.2 || true

echo
echo "IPv6 test: node3 -> node4"
ip netns exec node3 ping -c 3 fd00:1::2 || true

echo
echo " Tip: Run 'sudo wireshark &' and capture on br0 to see ARP (IPv4) and NDP (IPv6) traffic."
echo "Done!"
