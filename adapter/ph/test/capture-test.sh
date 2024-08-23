#!/usr/bin/bash
set -euo pipefail

PH_BIN=$(realpath "$(dirname $0)/../target/debug/ph")
PH_DEBUG_BIN=$(realpath "$(dirname $0)/../../ph-debug/target/debug/ph-debug")

source "$(dirname $0)/common_funcs.sh"

ZPR_USER=$USER

A_HOST_ADDR=10.0.0.1
B_HOST_ADDR=10.0.0.2

A_ZPR_ADDR=192.168.1.1
B_ZPR_ADDR=192.168.1.2
A_ZPR_ADDR6=fd00:1:1::1
B_ZPR_ADDR6=fd00:1:1::2

A_ZPR_SOCK=server.sock
B_ZPR_SOCK=client.sock

#
# Helper functions
#

function set_program() {
  SOCKET=$1
  FILE_NAME=$2
  PROGRAM=$3
  "$PH_DEBUG_BIN" -c SET-CAPTURE-FILE -p "$SOCKET" --file-path "$FILE_NAME"

  if [ "$PROGRAM" != "None" ]
  then "$PH_DEBUG_BIN" -c SET-CAPTURE-PROGRAM -p "$SOCKET" --program "$PROGRAM"
  fi
}

function close_program() {
  SOCKET=$1
  "$PH_DEBUG_BIN" -c CLOSE-CAPTURE-FILE -p "$SOCKET"
}

#
# Set up automatic cleanup
#

CHILDREN=()

trap cleanup EXIT

TMPDIR=$(mktemp -d)
pushd "$TMPDIR" > /dev/null


#
# Prepare for test
#

destroy_network

create_network

create_ca_key_and_cert ca
create_agent_key_and_cert ca server
create_agent_key_and_cert ca client


#
# Launch PHs
#

sudo -E ip netns exec zpr-a sudo -E -u "$ZPR_USER" "$PH_BIN" \
  --mode=server --control-path "$A_ZPR_SOCK" \
  --self-addr "$A_HOST_ADDR":12345 --dock-addr "$B_HOST_ADDR":12345 \
  --ca-file ca.crt --certificate-file server.crt --private-key-file server.key \
  --tun-if tun0 &
CHILDREN=(${CHILDREN[@]} "$!")

sleep 1  # FIXME: I think we need this b/c DTLS doesn't deal with dropped initial packet well
set_program "$A_ZPR_SOCK" "$TMPDIR/cap_test1.pcap" 'link[0] == 1'

sudo -E ip netns exec zpr-b sudo -E -u "$ZPR_USER" "$PH_BIN" \
  --mode=client --control-path "$B_ZPR_SOCK" \
  --self-addr "$B_HOST_ADDR":12345 --dock-addr "$A_HOST_ADDR":12345 \
  --ca-file ca.crt --certificate-file client.crt --private-key-file client.key \
  --tun-if tun0 &
CHILDREN=(${CHILDREN[@]} "$!")

#
# Wait for connectivity
#

echo "Wait for TUN carrier..."
wait_for 5 check_carrier zpr-a tun0 || { echo "FAILURE"; exit 1; }
wait_for 5 check_carrier zpr-b tun0 || { echo "FAILURE"; exit 1; }
echo "Carrier has arrived."

stty sane || true

#
# Run test
#

set_program "$B_ZPR_SOCK" "$TMPDIR/cap_test2.pcap" None

PASS=0
if ! ping_test
then PASS=1
fi

close_program "$A_ZPR_SOCK"
close_program "$B_ZPR_SOCK"

# Make sure correct number of incoming packets were captured, either 23 or 24 depending 
# on whether two hello requests are received 
tcpdump -r "$TMPDIR/cap_test1.pcap" 'link[0] = 1 or link[0] == 0' > "$TMPDIR/checker.txt"
HELLO_COUNT="$(grep -c '0x0000:  0100 8800 0000' "$TMPDIR/checker.txt" || 0)"
PACKET_COUNT="$(grep -c '0x0000:  0' "$TMPDIR/checker.txt" || true)"

if [[ "$(($PACKET_COUNT - $HELLO_COUNT))" != "23" ]]
then PASS=1
fi

# Make sure no data was captured when program is not set
SIZE="$(stat -c %s "$TMPDIR/cap_test2.pcap")" 

if [[ "$SIZE" != "24" ]]
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
