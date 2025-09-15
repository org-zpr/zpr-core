#!/usr/bin/env bash
set -euo pipefail
PH_BIN=$(realpath "$(dirname $0)/../adapter/ph/target/debug/ph")
PH_DEBUG_BIN=$(realpath "$(dirname $0)/../adapter/cli/target/debug/ph-cli")
VS_BIN=$(realpath "$(dirname $0)/vservice")
PREGEN=$(realpath "$(dirname $0)/pregen")

source "$(dirname $0)/common_funcs.sh"

ZPR_USER=$USER

NODE_SUBSTRATE_ADDR_VS=10.0.0.1
NODE_SUBSTRATE_ADDR_A=10.0.1.1
NODE_SUBSTRATE_ADDR_B=10.0.2.1
NODE_SUBSTRATE_ADDR_C=10.0.3.1
VS_SUBSTRATE_ADDR=10.0.0.2
A_SUBSTRATE_ADDR=10.0.1.2
B_SUBSTRATE_ADDR=10.0.2.2
C_SUBSTRATE_ADDR=10.0.3.2

# Default protocol is ipv6.
ACTOR_PROTOCOL="ipv6"
NUM_ACTORS=2
# Note: POLICY_BIN, NODE_ZPR_ADDR, VS_ZPR_ADDR, A_ZPR_ADDR, and B_ZPR_ADDR are defined by parsing the input arguments.
source "$(dirname $0)/parse_arguments.sh"

if [ ! -e "$VS_BIN" ]; then
  echo "vservice binary not found, expected it at $VS_BIN"
  exit 1
fi

NODE_SOCK=node.sock
VS_SOCK=vs.sock
ADAPTER1_SOCK=adapter1.sock
ADAPTER2_SOCK=adapter2.sock
ADAPTER3_SOCK=adapter3.sock

SHOW_CAPTURE="${ZPR_TEST_VERBOSE:-no}"

#
# Helper functions
#

function set_program() {
  SOCKET=$1
  FILE_NAME=$2
  PROGRAM=$3
  "$PH_DEBUG_BIN" -p "$SOCKET" capture set-file "$FILE_NAME"

  if [ "$PROGRAM" != "None" ]; then
    "$PH_DEBUG_BIN" -p "$SOCKET" capture set-program "$PROGRAM"
  fi
}

function close_program() {
  SOCKET=$1
  "$PH_DEBUG_BIN" -p "$SOCKET" capture close-file
}

#
# Set up automatic cleanup
#

trap cleanup EXIT

TMPDIR=$(mktemp -d)
pushd "$TMPDIR" >/dev/null

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

sudo -E ip netns exec zpr-vs sudo -E -u "$ZPR_USER" "$VS_BIN" \
    -c vs-config.yaml \
    -p "$PREGEN/$POLICY_BIN" \
    --listen_addr ["$VS_ZPR_ADDR"]:5002 2>&1 | tee vs.log | prefix_log vs &

sleep 2

#
# Launch PHs
#
sudo -E ip netns exec zpr-node sudo -E -u "$ZPR_USER" "$PH_BIN" \
  node \
  --control-path "$NODE_SOCK" \
  --self-addr 0.0.0.0:12345 \
  --ca-file ca.crt \
  --certificate-file node.crt \
  --private-key-file node.key \
  --tun-if tun0 \
  --zpr-addr "$NODE_ZPR_ADDR" 2>&1 | tee node.log | prefix_log zpr-node &

sudo -E ip netns exec zpr-vs sudo -E -u "$ZPR_USER" "$PH_BIN" \
  adapter \
  --control-path "$VS_SOCK" \
  --self-addr "$VS_SUBSTRATE_ADDR":0 \
  --ca-file ca.crt \
  --certificate-file vs.zpr.crt \
  --private-key-file vs.zpr.key \
  --bootstrap-key actorvs-rsa.key \
  --tun-if tun0 \
  --node-addr "$NODE_SUBSTRATE_ADDR_VS":12345 \
  --node-public-key-file node.pubkey \
  --zpr-addr "$VS_ZPR_ADDR" 2>&1 | tee adapter-vs.log | prefix_log zpr-vs &

sleep 2

sudo -E ip netns exec zpr-a sudo -E -u "$ZPR_USER" "$PH_BIN" \
  adapter \
  --control-path "$ADAPTER1_SOCK" \
  --self-addr "$A_SUBSTRATE_ADDR":0 \
  --ca-file ca.crt \
  --certificate-file adapter1.crt \
  --private-key-file adapter1.key \
  --bootstrap-key actor1-rsa.key \
  --tun-if tun0 \
  --node-addr "$NODE_SUBSTRATE_ADDR_A":12345 \
  --zpr-addr "$A_ZPR_ADDR" \
  --node-public-key-file node.pubkey 2>&1 | tee adapter1.log | prefix_log zpr-a &

sudo -E ip netns exec zpr-b sudo -E -u "$ZPR_USER" "$PH_BIN" \
  adapter \
  --control-path "$ADAPTER2_SOCK" \
  --self-addr "$B_SUBSTRATE_ADDR":0 \
  --ca-file ca.crt \
  --certificate-file adapter2.crt \
  --private-key-file adapter2.key \
  --bootstrap-key actor2-rsa.key \
  --tun-if tun0 \
  --node-addr "$NODE_SUBSTRATE_ADDR_B":12345 \
  --zpr-addr "$B_ZPR_ADDR" \
  --node-public-key-file node.pubkey 2>&1 | tee adapter2.log | prefix_log zpr-b &

if [[ "$NUM_ACTORS" -ge 3 ]]; then
  sudo -E ip netns exec zpr-c sudo -E -u "$ZPR_USER" "$PH_BIN" \
    adapter \
    --control-path "$ADAPTER3_SOCK" \
    --self-addr "$C_SUBSTRATE_ADDR":0 \
    --ca-file ca.crt \
    --certificate-file adapter3.crt \
    --private-key-file adapter3.key \
    --bootstrap-key actor3-rsa.key \
    --tun-if tun0 \
    --node-addr "$NODE_SUBSTRATE_ADDR_C":12345 \
    --node-public-key-file node.pubkey \
    --zpr-addr "$C_ZPR_ADDR" 2>&1 | tee adapter3.log | prefix_log zpr-c &
fi

sleep 1 # FIXME: I think we need this b/c DTLS doesn't deal with dropped initial packet well
set_program "$ADAPTER1_SOCK" "$TMPDIR/cap_test1.pcap" 'link[0] == 1'

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
sleep 1

stty sane || true

#
# Run test
#

set_program "$ADAPTER2_SOCK" "$TMPDIR/cap_test2.pcap" None

echo "starting PING test..."

PASS=0
if ! ping_test; then
  PASS=1
fi

close_program "$ADAPTER1_SOCK"
close_program "$ADAPTER2_SOCK"

# Make sure at least both actor and mgmt packets were captured.
tcpdump -r "$TMPDIR/cap_test1.pcap" 'link[0] = 1 or link[0] == 0' >"$TMPDIR/checker.txt"

# The node is configured in main.rs to expect ZPI 5 for management packets and 6 for transit
# when getting messages from peer 1.
MGMT_PACKET_COUNT="$(grep -c '0x0105: ' "$TMPDIR/checker.txt" || echo 0)"
ACTOR_PACKET_COUNT="$(grep -c '0x0106: ' "$TMPDIR/checker.txt" || echo 0)"

if [ "$SHOW_CAPTURE" != "no" ]; then
  echo -e "\n============================= CHECKER\n"
  cat "$TMPDIR/checker.txt"
  echo
fi

if [[ MGMT_PACKET_COUNT == 0 || ACTOR_PACKET_COUNT == 0 ]]; then
  PASS=1
fi

# Make sure no data was captured when program is not set
SIZE="$(stat -c %s "$TMPDIR/cap_test2.pcap")"

if [[ "$SIZE" != "24" ]]; then
  PASS=1
fi

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
if [[ "$PASS" == 0 ]]; then
  echo "SUCCESS"
else
  echo "FAILURE"
fi

exit "$PASS"
