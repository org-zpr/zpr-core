#!/usr/bin/bash
set -euo pipefail

PH_BIN=$(realpath "$(dirname $0)/../target/debug/ph")
PH_DEBUG_BIN=$(realpath "$(dirname $0)/../../ph-debug/target/debug/ph-debug")

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

function counters() {
  SOCKET=$1
  "$PH_DEBUG_BIN" -p "$SOCKET" counters
}


#
# Set up automatic cleanup
#


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
     node \
     --name "zpr-node" \
     --control-path "$NODE_SOCK" \
     --self-addr 0.0.0.0:12345 \
     --ca-file ca.crt \
     --certificate-file node.crt \
     --private-key-file node.key \
     --tun-if tun0 2>&1 |tee node.log &

sleep 2

sudo -E ip netns exec zpr-a sudo -E -u "$ZPR_USER" "$PH_BIN" \
  adapter \
  --name "zpr-a" \
  --control-path "$ADAPTER1_SOCK" \
  --self-addr "$A_SUBSTRATE_ADDR":12345 \
  --ca-file ca.crt \
  --certificate-file adapter1.crt \
  --private-key-file adapter1.key \
  --tun-if tun0 \
  --node-addr "$NODE_SUBSTRATE_ADDR_A":12345 \
  --node-public-key-file node.pubkey \
  --agent-addr "$A_ZPR_ADDR" 2>&1 |tee adapter1.log &


sudo -E ip netns exec zpr-b sudo -E -u "$ZPR_USER" "$PH_BIN" \
  adapter \
  --name "zpr-b" \
  --control-path "$ADAPTER2_SOCK" \
  --self-addr "$B_SUBSTRATE_ADDR":12345 \
  --ca-file ca.crt \
  --certificate-file adapter2.crt \
  --private-key-file adapter2.key \
  --tun-if tun0 \
  --node-addr "$NODE_SUBSTRATE_ADDR_B":12345 \
  --node-public-key-file node.pubkey \
  --agent-addr "$B_ZPR_ADDR" 2>&1 |tee adapter2.log &


#
# Wait for connectivity
#

echo "Wait for TUN carrier..."
wait_for 5 check_carrier zpr-a tun0 || { echo "FAILURE"; exit 1; }
wait_for 5 check_carrier zpr-b tun0 || { echo "FAILURE"; exit 1; }
wait_for 5 check_carrier zpr-node tun0 || { echo "FAILURE"; exit 1; }
echo "Carrier has arrived."
# This sleep solves a display issue because magic
sleep 1


#
# Run test
#

echo "TEST STARTING"

PASS=0
if ! ping_test
then PASS=1
fi

sleep 1


#
# Check stats
#

for SOCK in "$ADAPTER1_SOCK" "$ADAPTER2_SOCK" "$NODE_SOCK"
do
	# TODO: test also with encrypted agent traffic
	APOOO=$(counters "$SOCK" | awk -F': ' '$1 == "Agent Packets Out-Of-Order" { print $2 }')
	if (( APOOO != 0 ))
	then
		echo "$(basename "$SOCK"): ERROR: found agent packets out-of-order: $APOOO"
		PASS=1
	fi
done


#
# Cleanup
#

for pid in $(get_descendants)
do
    echo
    echo "Terminating $pid"
    sleep 1
    sudo kill -SIGTERM "$pid"
    sleep 1
done

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
