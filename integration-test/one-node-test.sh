#!/usr/bin/env bash
set -euo pipefail

export RUST_BACKTRACE=1
DEBUG_TARGETS=${DEBUG_TARGETS:-all=INFO}
KM_IMPL=${KM_IMPL:-noise}


PH_BIN="${PH_BIN:-$(realpath "$(dirname "$0")/../target/debug/ph")}"
PH_DEBUG_BIN="${PH_DEBUG_BIN:-$(realpath "$(dirname "$0")/../target/debug/ph-cli")}"
VS_BIN="${VS_BIN:-$(realpath "$(dirname "$0")/vs")}"
VS_ADMIN_BIN="${VS_ADMIN_BIN:-$(realpath "$(dirname "$0")/vs-admin")}"
VALKEY_SERVER_BIN="${VALKEY_SERVER_BIN:-$(realpath -s "$(dirname "$0")/valkey-server")}"

PREGEN=$(realpath "$(dirname $0)/pregen")
NODE_AUTH_PRIVATE_KEY="${NODE_AUTH_PRIVATE_KEY:-$PREGEN/node-rsa-key.pem}"

# netem parameters to configure on all links; e.g. "loss random 10%"
# blank for no netem
NETEM_PARAMS=${NETEM_PARAMS:-}

source "$(dirname $0)/lib/common_funcs.sh"

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
source "$(dirname $0)/lib/parse_arguments.sh"

if [ ! -e "$VS_BIN" ]; then
  echo "vs binary not found, expected it at $VS_BIN"
  exit 1
fi

if [ ! -e "$VS_ADMIN_BIN" ]; then
  echo "vs-admin binary not found, expected it at $VS_ADMIN_BIN"
  exit 1
fi

if systemctl is-active --quiet valkey-server 2>/dev/null; then
  echo "valkey-server system service is running. Please stop it before running this test:"
  echo "  sudo systemctl stop valkey-server"
  exit 1
fi

if [ ! -e "$VALKEY_SERVER_BIN" ]; then
  echo "valkey-server binary not found, expected it at $VALKEY_SERVER_BIN"
  exit 1
fi

if [ ! -e "$PREGEN/$POLICY_BIN" ]; then
  echo "policy file not found (expected .bin2): $PREGEN/$POLICY_BIN"
  exit 1
fi

if [ ! -x "$PH_BIN" ]; then
  echo "ph binary not found or not executable: $PH_BIN"
  exit 1
fi

if [ ! -x "$PH_DEBUG_BIN" ]; then
  echo "ph-cli binary not found or not executable: $PH_DEBUG_BIN"
  exit 1
fi

if [ ! -e "$NODE_AUTH_PRIVATE_KEY" ]; then
  echo "node auth private key not found: $NODE_AUTH_PRIVATE_KEY"
  exit 1
fi

NODE_SOCK=node.sock
VS_SOCK=vs.sock
ADAPTER1_SOCK=adapter1.sock
ADAPTER2_SOCK=adapter2.sock
ADAPTER3_SOCK=adapter3.sock
NODE_CAP_SOCK=node_cap.sock
VS_CAP_SOCK=vs_cap.sock
ADAPTER1_CAP_SOCK=adapter1_cap.sock
ADAPTER2_CAP_SOCK=adapter2_cap.sock
ADAPTER3_CAP_SOCK=adapter3_cap.sock

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

if [ -n "$NETEM_PARAMS" ]
then configure_netem $NETEM_PARAMS  # split on whitespace
fi

create_ca_key_and_cert ca
create_actor_key_and_cert ca vs.zpr
#create_actor_key_and_cert ca node

# Temporary hack until our policy compiler is in-repo
cp "$PREGEN/node.key" node.key
cp "$PREGEN/node-cert.pem" node.crt
cp "$PREGEN/node-pubkey.pem" node.pubkey
cp "$PREGEN/actor1-rsa.key" actor1-rsa.key
cp "$PREGEN/actor2-rsa.key" actor2-rsa.key
cp "$PREGEN/actor3-rsa.key" actor3-rsa.key
cp "$PREGEN/actorvs-rsa.key" actorvs-rsa.key

emit_vs_config ca vs.zpr > vs-config.toml

#
# Launch ValKey + Visa Service
#

echo "Launching ValKey"

sudo -E ip netns exec zpr-vs sudo -E -u "$ZPR_USER" "$VALKEY_SERVER_BIN" \
    --save "" \
    --appendonly no 2>&1 | tee valkey.log | prefix_log valkey &

wait_for 15 check_vs_valkey_port

echo "Launching Visa Service"

sudo -E ip netns exec zpr-vs sudo -E -u "$ZPR_USER" XDG_DATA_HOME=/tmp "$VS_BIN" \
    -c vs-config.toml \
    --clear-state \
    "$PREGEN/$POLICY_BIN" 2>&1 | tee vs.log | prefix_log vs &

sleep 2

#
# Launch PHs
#

echo "Launching Node"

sudo -E ip netns exec zpr-node sudo -E -u "$ZPR_USER" "$PH_BIN" \
  node \
  --logging "$DEBUG_TARGETS" \
  --control-path "$NODE_SOCK" \
  --capture-path "$NODE_CAP_SOCK" \
  --advertised-substrate-addr "$NODE_SUBSTRATE_ADDR_VS":5000 \
  --ca-file ca.crt \
  --certificate-file node.crt \
  --private-key-file node.key \
  --auth-private-key "$NODE_AUTH_PRIVATE_KEY" \
  --km-impl "$KM_IMPL" \
  --tun-if tun0 \
  --zpr-addr "$NODE_ZPR_ADDR" 2>&1 | tee node.log | prefix_log zpr-node &

sleep 2  # TODO: remove?

echo "Launching Adapters"

sudo -E ip netns exec zpr-vs sudo -E -u "$ZPR_USER" "$PH_BIN" \
  adapter \
  --logging "$DEBUG_TARGETS" \
  --control-path "$VS_SOCK" \
  --capture-path "$VS_CAP_SOCK" \
  --self-addr "$VS_SUBSTRATE_ADDR" \
  --ca-file ca.crt \
  --certificate-file vs.zpr.crt \
  --private-key-file vs.zpr.key \
  --bootstrap-key actorvs-rsa.key \
  --km-impl "$KM_IMPL" \
  --tun-if tun0 \
  --io-engine auto \
  --node-addr "$NODE_SUBSTRATE_ADDR_VS" \
  --zpr-addr "$VS_ZPR_ADDR" 2>&1 | tee adapter-vs.log | prefix_log zpr-vs &

sleep 5

sudo -E ip netns exec zpr-a sudo -E -u "$ZPR_USER" "$PH_BIN" \
  adapter \
  --logging "$DEBUG_TARGETS" \
  --control-path "$ADAPTER1_SOCK" \
  --capture-path "$ADAPTER1_CAP_SOCK" \
  --self-addr "$A_SUBSTRATE_ADDR" \
  --ca-file ca.crt \
  --bootstrap-key actor1-rsa.key \
  --name adapter1 \
  --km-impl "$KM_IMPL" \
  --tun-if tun0 \
  --io-engine io_uring \
  --node-addr "$NODE_SUBSTRATE_ADDR_A" \
  --zpr-addr "$A_ZPR_ADDR" 2>&1 | tee adapter1.log | prefix_log zpr-a &

sudo -E ip netns exec zpr-b sudo -E -u "$ZPR_USER" "$PH_BIN" \
  adapter \
  --logging "$DEBUG_TARGETS" \
  --control-path "$ADAPTER2_SOCK" \
  --capture-path "$ADAPTER2_CAP_SOCK" \
  --self-addr "$B_SUBSTRATE_ADDR" \
  --ca-file ca.crt \
  --bootstrap-key actor2-rsa.key \
  --name adapter2 \
  --km-impl "$KM_IMPL" \
  --tun-if tun0 \
  --io-engine posix_unbatched \
  --node-addr "$NODE_SUBSTRATE_ADDR_B" \
  --zpr-addr "$B_ZPR_ADDR" 2>&1 | tee adapter2.log | prefix_log zpr-b &

if [[ "$NUM_ACTORS" -ge 3 ]]; then
  # Note, this adapter we connect to the "alternative" dock address
  # on this interface, to test that replies are still routed correctly.
  sudo -E ip netns exec zpr-c sudo -E -u "$ZPR_USER" "$PH_BIN" \
    adapter \
    --logging "$DEBUG_TARGETS" \
    --control-path "$ADAPTER3_SOCK" \
    --capture-path "$ADAPTER3_CAP_SOCK" \
    --self-addr "$C_SUBSTRATE_ADDR" \
    --ca-file ca.crt \
    --bootstrap-key actor3-rsa.key \
    --name adapter3 \
    --km-impl "$KM_IMPL" \
    --tun-if tun0 \
    --node-addr "$NODE_SUBSTRATE_ADDR_C_ALT" \
    --zpr-addr "$C_ZPR_ADDR" 2>&1 | tee adapter3.log | prefix_log zpr-c &
fi

#
# Wait for connectivity
#
PASS=0
echo "Wait for TUN carrier..."
wait_for 15 check_carrier zpr-node tun0 || { PASS=1; }
if [[ "$PASS" == 0 ]] then
wait_for 15 check_carrier zpr-vs tun0 || { PASS=1; }
fi
if [[ "$PASS" == 0 ]] then
wait_for 15 check_carrier zpr-a tun0 || { PASS=1; }
fi
if [[ "$PASS" == 0 ]] then
wait_for 15 check_carrier zpr-b tun0 || { PASS=1; }
fi
if [[ "$PASS" == 0 && "$NUM_ACTORS" -ge 3 ]]; then
  wait_for 15 check_carrier zpr-c tun0 || { PASS=1; }
fi

if [[ "$PASS" == 0 ]] then
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

fi
#
# Check stats
#

for SOCK in "$NODE_SOCK" "$VS_SOCK" "$ADAPTER1_SOCK" "$ADAPTER2_SOCK"
do
	# TODO: test also with encrypted actor traffic
	APOOO=$(counters "$SOCK" | awk -F': ' '$1 == "Actor Packets Out-Of-Order" { apooo += $2 } END { print apooo }')
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
  sudo kill -SIGINT "$pid"
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
