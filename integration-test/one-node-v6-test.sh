#!/usr/bin/bash
set -euo pipefail

PH_BIN=$(realpath "$(dirname $0)/../adapter/ph/target/debug/ph")
PH_DEBUG_BIN=$(realpath "$(dirname $0)/../adapter/ph-debug/target/debug/ph-debug")
VS_BIN=$(realpath "$(dirname $0)/../visaservice/core/build/vservice")
PREGEN=$(realpath "$(dirname $0)/pregen")

source "$(dirname $0)/common_funcs.sh"

ZPR_USER=$USER

# TODO: IPv6 link-local??
NODE_SUBSTRATE_ADDR_VS=10.0.0.1
NODE_SUBSTRATE_ADDR_A=10.0.1.1
NODE_SUBSTRATE_ADDR_B=10.0.2.1
VS_SUBSTRATE_ADDR=10.0.0.2
A_SUBSTRATE_ADDR=10.0.1.2
B_SUBSTRATE_ADDR=10.0.2.2

NODE_ZPR_ADDR6=fd5a:5052::2
VS_ZPR_ADDR6=fd5a:5052::1
A_ZPR_ADDR6=fd00:1:1::1
B_ZPR_ADDR6=fd00:1:2::1

NODE_SOCK=node.sock
VS_SOCK=vs.sock
ADAPTER1_SOCK=adapter1.sock
ADAPTER2_SOCK=adapter2.sock

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
create_agent_key_and_cert ca vs.zpr
#create_agent_key_and_cert ca node
create_agent_key_and_cert ca adapter1
create_agent_key_and_cert ca adapter2

# Temporary hack until our policy compiler is in-repo
cp "$PREGEN/node.key" node.key
cp "$PREGEN/node-cert.pem" node.crt
cp "$PREGEN/node-pubkey.pem" node.pubkey

emit_vs_config ca vs.zpr > vs-config.yaml

#
# Launch Visa Service
#

echo "Launching Visa Service"

sudo -E ip netns exec zpr-vs sudo -E -u "$ZPR_USER" "$VS_BIN" \
    -c vs-config.yaml \
    -p "$PREGEN/v6-1node-2agent-ping.bin" \
    --listen_addr "[$VS_ZPR_ADDR6]":5002 2>&1 | tee vs.log | prefix_log vs &

sleep 2

#
# Launch PHs
#

echo "Launching Node"

sudo -E ip netns exec zpr-node sudo -E -u "$ZPR_USER" "$PH_BIN" \
     node \
     --name "n0" \
     --control-path "$NODE_SOCK" \
     --self-addr 0.0.0.0:12345 \
     --ca-file ca.crt \
     --certificate-file node.crt \
     --private-key-file node.key \
     --tun-if tun0 \
     --agent-addr "$NODE_ZPR_ADDR6" 2>&1 | tee node.log | prefix_log zpr-node &

sleep 2  # TODO: remove?

echo "Launching Adapters"

sudo -E ip netns exec zpr-vs sudo -E -u "$ZPR_USER" "$PH_BIN" \
  adapter \
  --name "zpr-vs" \
  --control-path "$VS_SOCK" \
  --self-addr "$VS_SUBSTRATE_ADDR":0 \
  --ca-file ca.crt \
  --certificate-file vs.zpr.crt \
  --private-key-file vs.zpr.key \
  --tun-if tun0 \
  --node-addr "$NODE_SUBSTRATE_ADDR_VS":12345 \
  --node-public-key-file node.pubkey \
  --agent-addr "$VS_ZPR_ADDR6" 2>&1 | tee adapter-vs.log | prefix_log zpr-vs &

sleep 5

sudo -E ip netns exec zpr-a sudo -E -u "$ZPR_USER" "$PH_BIN" \
  adapter \
  --name "zpr-a" \
  --control-path "$ADAPTER1_SOCK" \
  --self-addr "$A_SUBSTRATE_ADDR":0 \
  --ca-file ca.crt \
  --certificate-file adapter1.crt \
  --private-key-file adapter1.key \
  --tun-if tun0 \
  --node-addr "$NODE_SUBSTRATE_ADDR_A":12345 \
  --node-public-key-file node.pubkey \
  --agent-addr "$A_ZPR_ADDR6" 2>&1 | tee adapter1.log | prefix_log zpr-a &

sudo -E ip netns exec zpr-b sudo -E -u "$ZPR_USER" "$PH_BIN" \
  adapter \
  --name "zpr-b" \
  --control-path "$ADAPTER2_SOCK" \
  --self-addr "$B_SUBSTRATE_ADDR":0 \
  --ca-file ca.crt \
  --certificate-file adapter2.crt \
  --private-key-file adapter2.key \
  --tun-if tun0 \
  --node-addr "$NODE_SUBSTRATE_ADDR_B":12345 \
  --node-public-key-file node.pubkey \
  --agent-addr "$B_ZPR_ADDR6" 2>&1 | tee adapter2.log | prefix_log zpr-b &

#
# Wait for connectivity
#

echo "Wait for TUN carrier..."
wait_for 5 check_carrier zpr-node tun0 || { echo "FAILURE"; exit 1; }
wait_for 5 check_carrier zpr-vs tun0 || { echo "FAILURE"; exit 1; }
wait_for 5 check_carrier zpr-a tun0 || { echo "FAILURE"; exit 1; }
wait_for 5 check_carrier zpr-b tun0 || { echo "FAILURE"; exit 1; }
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

for SOCK in "$NODE_SOCK" "$VS_SOCK" "$ADAPTER1_SOCK" "$ADAPTER2_SOCK"
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
