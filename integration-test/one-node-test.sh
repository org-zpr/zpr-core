#!/usr/bin/env bash
set -euo pipefail

export RUST_BACKTRACE=1
# DEBUG_TARGETS=${DEBUG_TARGETS:-none}
DEBUG_TARGETS=$"all=WARN visa_mgmt=INFO"

PH_BIN=$(realpath "$(dirname $0)/../adapter/ph/target/debug/ph")
PH_DEBUG_BIN=$(realpath "$(dirname $0)/../adapter/cli/target/debug/ph-cli")
VS_BIN=$(realpath "$(dirname $0)/vservice")
VS_ADMIN_BIN=$(realpath "$(dirname $0)/vs-admin")
PREGEN=$(realpath "$(dirname $0)/pregen")

source "$(dirname $0)/common_funcs.sh"

ZPR_USER=$USER

# TODO: IPv6 link-local??
NODE_SUBSTRATE_ADDR_VS=10.0.0.1
NODE_SUBSTRATE_ADDR_A=10.0.1.1
NODE_SUBSTRATE_ADDR_B=10.0.2.1
NODE_SUBSTRATE_ADDR_C=10.0.3.1
NODE_SUBSTRATE_ADDR_C_ALT=10.0.3.129  # Used for testing routing when a dock has multiple addresses.
VS_SUBSTRATE_ADDR=10.0.0.2
A_SUBSTRATE_ADDR=10.0.1.2
B_SUBSTRATE_ADDR=10.0.2.2
C_SUBSTRATE_ADDR=10.0.3.2

# Default protocol is ipv6.
ACTOR_PROTOCOL="ipv6"
NUM_ACTORS=3
# Note: POLICY_BIN, NODE_ZPR_ADDR, VS_ZPR_ADDR, A_ZPR_ADDR, and B_ZPR_ADDR are defined by parsing the input arguments.
source "$(dirname $0)/parse_arguments.sh"

if [ ! -e "$VS_BIN" ]; then
  echo "vservice binary not found, expected it at $VS_BIN"
  exit 1
fi

if [ ! -e "$VS_ADMIN_BIN" ]; then
  echo "vs-admin binary not found, expected it at $VS_ADMIN_BIN"
  exit 1
fi

NODE_SOCK=node.sock
VS_SOCK=vs.sock
ADAPTER1_SOCK=adapter1.sock
ADAPTER2_SOCK=adapter2.sock
ADAPTER3_SOCK=adapter3.sock

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
create_actor_key_and_cert ca vs.zpr
#create_actor_key_and_cert ca node
create_actor_key_and_cert ca adapter1
create_actor_key_and_cert ca adapter2
create_actor_key_and_cert ca adapter3

# Temporary hack until our policy compiler is in-repo
cp "$PREGEN/node.key" node.key
cp "$PREGEN/node-cert.pem" node.crt
cp "$PREGEN/node-pubkey.pem" node.pubkey
cp "$PREGEN/actor1-rsa.key" actor1-rsa.key
cp "$PREGEN/actor2-rsa.key" actor2-rsa.key
cp "$PREGEN/actor3-rsa.key" actor3-rsa.key
cp "$PREGEN/actorvs-rsa.key" actorvs-rsa.key

emit_vs_config ca vs.zpr > vs-config.yaml

#
# Launch Visa Service
#

echo "Launching Visa Service"

sudo -E ip netns exec zpr-vs sudo -E -u "$ZPR_USER" "$VS_BIN" \
    -c vs-config.yaml \
    -p "$PREGEN/$POLICY_BIN" \
    --listen_addr "[$VS_ZPR_ADDR]":5002 2>&1 | tee vs.log | prefix_log vs &

sleep 2

#
# Launch PHs
#

echo "Launching Node"

sudo -E ip netns exec zpr-node sudo -E -u "$ZPR_USER" "$PH_BIN" \
  node \
  --logging "$DEBUG_TARGETS" \
  --control-path "$NODE_SOCK" \
  --ca-file ca.crt \
  --certificate-file node.crt \
  --private-key-file node.key \
  --tun-if tun0 \
  --zpr-addr "$NODE_ZPR_ADDR" 2>&1 | tee node.log | prefix_log zpr-node &

sleep 2  # TODO: remove?

echo "Launching Adapters"

sudo -E ip netns exec zpr-vs sudo -E -u "$ZPR_USER" "$PH_BIN" \
  adapter \
  --logging "$DEBUG_TARGETS" \
  --control-path "$VS_SOCK" \
  --self-addr "$VS_SUBSTRATE_ADDR" \
  --ca-file ca.crt \
  --certificate-file vs.zpr.crt \
  --private-key-file vs.zpr.key \
  --bootstrap-key actorvs-rsa.key \
  --tun-if tun0 \
  --io-engine auto \
  --node-addr "$NODE_SUBSTRATE_ADDR_VS" \
  --node-public-key-file node.pubkey \
  --zpr-addr "$VS_ZPR_ADDR" 2>&1 | tee adapter-vs.log | prefix_log zpr-vs &

sleep 5

sudo -E ip netns exec zpr-a sudo -E -u "$ZPR_USER" "$PH_BIN" \
  adapter \
  --logging "$DEBUG_TARGETS" \
  --control-path "$ADAPTER1_SOCK" \
  --self-addr "$A_SUBSTRATE_ADDR" \
  --ca-file ca.crt \
  --certificate-file adapter1.crt \
  --private-key-file adapter1.key \
  --bootstrap-key actor1-rsa.key \
  --tun-if tun0 \
  --io-engine io_uring \
  --node-addr "$NODE_SUBSTRATE_ADDR_A" \
  --node-public-key-file node.pubkey \
  --zpr-addr "$A_ZPR_ADDR" 2>&1 | tee adapter1.log | prefix_log zpr-a &

sudo -E ip netns exec zpr-b sudo -E -u "$ZPR_USER" "$PH_BIN" \
  adapter \
  --logging "$DEBUG_TARGETS" \
  --control-path "$ADAPTER2_SOCK" \
  --self-addr "$B_SUBSTRATE_ADDR" \
  --ca-file ca.crt \
  --certificate-file adapter2.crt \
  --private-key-file adapter2.key \
  --bootstrap-key actor2-rsa.key \
  --tun-if tun0 \
  --io-engine posix_unbatched \
  --node-addr "$NODE_SUBSTRATE_ADDR_B" \
  --node-public-key-file node.pubkey \
  --zpr-addr "$B_ZPR_ADDR" 2>&1 | tee adapter2.log | prefix_log zpr-b &

if [[ "$NUM_ACTORS" -ge 3 ]]; then
  # Note, this adapter we connect to the "alternative" dock address
  # on this interface, to test that replies are still routed correctly.
  sudo -E ip netns exec zpr-c sudo -E -u "$ZPR_USER" "$PH_BIN" \
    adapter \
  --logging "$DEBUG_TARGETS" \
    --control-path "$ADAPTER3_SOCK" \
    --self-addr "$C_SUBSTRATE_ADDR" \
    --ca-file ca.crt \
    --certificate-file adapter3.crt \
    --private-key-file adapter3.key \
    --bootstrap-key actor3-rsa.key \
    --tun-if tun0 \
    --node-addr "$NODE_SUBSTRATE_ADDR_C_ALT" \
    --node-public-key-file node.pubkey \
    --zpr-addr "$C_ZPR_ADDR" 2>&1 | tee adapter3.log | prefix_log zpr-c &
fi

#
# Wait for connectivity
#

echo "Wait for TUN carrier..."
wait_for 5 check_carrier zpr-node tun0 || { echo "FAILURE"; exit 1; }
wait_for 5 check_carrier zpr-vs tun0 || { echo "FAILURE"; exit 1; }
wait_for 5 check_carrier zpr-a tun0 || { echo "FAILURE"; exit 1; }
wait_for 5 check_carrier zpr-b tun0 || { echo "FAILURE"; exit 1; }
if [[ "$NUM_ACTORS" -ge 3 ]]; then
  wait_for 5 check_carrier zpr-c tun0 || { echo "FAILURE"; exit 1; }
fi
echo "Carrier has arrived."
# This sleep solves a display issue because magic
sleep 100

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
# Revoke zpr-b's visa and try to ping again
#

sudo -E ip netns exec zpr-vs sudo -E -u "$ZPR_USER" "$VS_ADMIN_BIN" \
	--ca-cert ca.crt \
	--svc-url "https://[$VS_ZPR_ADDR]:8182" \
	revoke --actor-cn adapter2

if ! ping_a_b
then PASS=0
fi

#
# Check stats
#

for SOCK in "$NODE_SOCK" "$VS_SOCK" "$ADAPTER1_SOCK" "$ADAPTER2_SOCK"
do
	# TODO: test also with encrypted actor traffic
	APOOO=$(counters "$SOCK" | awk -F': ' '$1 == "Actor Packets Out-Of-Order" { print $2 }')
	if (( APOOO != 0 ))
	then
		echo "$(basename "$SOCK"): ERROR: found actor packets out-of-order: $APOOO"
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
