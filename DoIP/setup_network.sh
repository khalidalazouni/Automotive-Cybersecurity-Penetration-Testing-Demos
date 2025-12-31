#!/bin/bash
set -e

# Cleanup previous run
echo "[*] Cleaning up..."
ip netns del NodeA 2>/dev/null || true
ip netns del NodeC 2>/dev/null || true # Gear (called NodeC in python ip map)
ip netns del NodeD 2>/dev/null || true # Tester
ip link del doip_br 2>/dev/null || true

# 1. Create Bridge
echo "[*] Creating Bridge..."
ip link add name doip_br type bridge
ip link set doip_br type bridge mcast_snooping 0
ip link set doip_br up

# 2. Create Namespaces
ip netns add NodeA
ip netns add NodeC
ip netns add NodeD

# 3. Create veth pairs and link to bridge
create_veth() {
    NS=$1
    IF=$2
    
    ip link add $IF type veth peer name ${IF}_br
    ip link set ${IF}_br master doip_br
    ip link set ${IF}_br up
    ip link set $IF netns $NS
}

create_veth NodeA vethA
create_veth NodeC vethC
create_veth NodeD vethD

# 4. Configure Interfaces inside Namespaces
echo "[*] Configuring IPs..."

# ... (inside section 4) ...

# Node A (Mirror) -> 10.0.0.1
ip netns exec NodeA ip addr add 10.0.0.1/24 dev vethA
ip netns exec NodeA ip link set vethA up
ip netns exec NodeA ip link set lo up
ip netns exec NodeA ip route add 224.0.0.0/4 dev vethA
# ADD THIS: Ensure broadcast is sent out the veth interface
ip netns exec NodeA ip route add broadcast 255.255.255.255 dev vethA

# Node C (Gear) -> 10.0.0.2
ip netns exec NodeC ip addr add 10.0.0.2/24 dev vethC
ip netns exec NodeC ip link set vethC up
ip netns exec NodeC ip link set lo up
ip netns exec NodeC ip route add 224.0.0.0/4 dev vethC
ip netns exec NodeC ip route add broadcast 255.255.255.255 dev vethC

# Node D (Tester) -> 10.0.0.3
ip netns exec NodeD ip addr add 10.0.0.3/24 dev vethD
ip netns exec NodeD ip link set vethD up
ip netns exec NodeD ip link set lo up
ip netns exec NodeD ip route add 224.0.0.0/4 dev vethD
# ADD THIS: This is the most important one for the Tester!
ip netns exec NodeD ip route add broadcast 255.255.255.255 dev vethD


# Inside setup.sh in the Node D (Tester) configuration section
ip netns exec NodeD ip route add 255.255.255.255 dev vethD

echo "✅ Network Ready."
echo "-----------------------------------------------"
echo "Terminal 1: sudo ip netns exec NodeA python3 node_a_mirror.py"
echo "Terminal 2: sudo ip netns exec NodeC python3 node_b_gear.py"
echo "Terminal 3: sudo ip netns exec NodeD python3 node_c_tester.py"
