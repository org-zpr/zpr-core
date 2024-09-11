#!/usr/bin/bash
set -euo pipefail

PH_BIN=$(realpath "$(dirname $0)/../target/debug/ph")

source "$(dirname $0)/common_funcs.sh"

ZPR_USER=$USER

NODE_SUBSTRATE_ADDR_A=10.0.0.1
NODE_SUBSTRATE_ADDR_B=10.0.1.1
A_SUBSTRATE_ADDR=10.0.0.2
B_SUBSTRATE_ADDR=10.0.1.2

A_ZPR_ADDR=192.168.1.1
B_ZPR_ADDR=192.168.1.2
NODE_ZPR_ADDR=192.168.2.1

A_ZPR_ADDR6=fd00:1:1::1
B_ZPR_ADDR6=fd00:1:2::1
NODE_ZPR_ADDR6=fd00:1:1::2

ADAPTER1_SOCK=adapter1.sock
ADAPTER2_SOCK=adapter2.sock
NODE_SOCK=node.sock

#
# Set up automatic cleanup
#

CHILDREN=()

trap cleanup EXIT

TMPDIR=$(mktemp -d)
pushd "$TMPDIR" > /dev/null

echo "Setting up network"

#
# Prepare for test
#

destroy_network

create_network

create_ca_key_and_cert ca
create_agent_key_and_cert ca adapter1
create_agent_key_and_cert ca adapter2
create_agent_key_and_cert ca node

echo "Launching DUTs"

#
# Launch PHs
#
sudo -E ip netns exec zpr-node sudo -E -u "$ZPR_USER" "$PH_BIN" \
     --name "zpr-node" --control-path "$NODE_SOCK" \
     --self-addr 0.0.0.0:12345 --peer-addr1 "$A_SUBSTRATE_ADDR":12345 \
     --peer-addr2 "$B_SUBSTRATE_ADDR":12345 \
     --ca-file ca.crt --certificate-file node.crt --private-key-file node.key \
     --tun-if tun0 &
CHILDREN=(${CHILDREN[@]} "$!")


sudo -E ip netns exec zpr-a sudo -E -u "$ZPR_USER" "$PH_BIN" \
  --name "zpr-a" --control-path "$ADAPTER1_SOCK" \
  --self-addr "$A_SUBSTRATE_ADDR":12345 --peer-addr1 "$NODE_SUBSTRATE_ADDR_A":12345 \
  --ca-file ca.crt --certificate-file adapter1.crt --private-key-file adapter1.key \
  --tun-if tun0 &
CHILDREN=(${CHILDREN[@]} "$!")


sudo -E ip netns exec zpr-b sudo -E -u "$ZPR_USER" "$PH_BIN" \
  --name "zpr-b" --control-path "$ADAPTER2_SOCK" \
  --self-addr "$B_SUBSTRATE_ADDR":12345 --peer-addr1 "$NODE_SUBSTRATE_ADDR_B":12345 \
  --ca-file ca.crt --certificate-file adapter2.crt --private-key-file adapter2.key \
  --tun-if tun0 &
CHILDREN=(${CHILDREN[@]} "$!")



#
# Wait for connectivity
#

echo "Wait for TUN carrier..."
wait_for 5 check_carrier zpr-a tun0 || { echo "FAILURE"; exit 1; }
wait_for 5 check_carrier zpr-b tun0 || { echo "FAILURE"; exit 1; }
wait_for 5 check_carrier zpr-node tun0 || { echo "FAILURE"; exit 1; }
echo "Carrier has arrived."

stty sane || true


echo "=========================================================="
echo "=========================================================="
echo "=========================================================="
echo "=========================================================="
echo "PAUSING FOR KEY MANAGEMENT EXCHANGE ..."
echo "=========================================================="
echo "=========================================================="
echo "=========================================================="
echo "=========================================================="
sleep 10


echo "=========================================================="
echo "=========================================================="
echo "=========================================================="
echo "=========================================================="
echo "TEST STARTING"
echo "=========================================================="
echo "=========================================================="
echo "=========================================================="
echo "=========================================================="


#
# Run test
#

PASS=0
if ! ping_test
then PASS=1
fi


#
# Cleanup
#

sudo kill "${CHILDREN[@]}" 2> /dev/null || true
sleep 1  # FIXME: let's do something better here
stty sane || true


#
# Report status
#

echo
if [[ "$PASS" == 0 ]]
then echo "SUCCESS"
else echo "FAILURE"
fi

exit "$PASS"
