#!/usr/bin/bash
set -euo pipefail

PH_BIN=$(realpath "$(dirname $0)/../target/debug/ph")

source "$(dirname $0)/common_funcs.sh"

ZPR_USER=$USER

A_HOST_ADDR=10.0.0.1
B_HOST_ADDR=10.0.0.2

A_ZPR_ADDR=192.168.1.1
B_ZPR_ADDR=192.168.1.2
A_ZPR_ADDR6=fd00:1:1::1
B_ZPR_ADDR6=fd00:1:1::2

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
  --mode=server --control-path server.sock \
  --self-addr "$A_HOST_ADDR":12345 --dock-addr "$B_HOST_ADDR":12345 \
  --ca-file ca.crt --certificate-file server.crt --private-key-file server.key \
  --disable-km --allow-insecure-zpi-zero --tun-if tun0 &
CHILDREN=(${CHILDREN[@]} "$!")

sleep 1  # FIXME: I think we need this b/c DTLS doesn't deal with dropped initial packet well

sudo -E ip netns exec zpr-b sudo -E -u "$ZPR_USER" "$PH_BIN" \
  --mode=client --control-path client.sock \
  --self-addr "$B_HOST_ADDR":12345 --dock-addr "$A_HOST_ADDR":12345 \
  --ca-file ca.crt --certificate-file client.crt --private-key-file client.key \
  --disable-km --allow-insecure-zpi-zero --tun-if tun0 &
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
