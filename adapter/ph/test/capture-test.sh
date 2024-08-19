#!/usr/bin/bash
set -euo pipefail

PH_BIN=$(realpath "$(dirname $0)/../target/debug/ph")
PH_DEBUG_BIN=$(realpath "$(dirname $0)/../../ph-debug/target/debug/ph-debug")

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

function wait_for() {
  RETRIES=$1
  shift
  CMD=("$@")

  if "${CMD[@]}"
  then return 0
  else RET=$?
  fi

  for ((i = 0; i < RETRIES; ++i))
  do
    sleep 1

    if "${CMD[@]}"
    then return 0
    else RET=$?
    fi
  done

  return "$RET"
}

function create_network() {
  sudo ip netns add zpr-a
  sudo ip netns add zpr-b


  # loopback

  sudo ip -n zpr-a link set lo up
  sudo ip -n zpr-b link set lo up


  # virtual ethenet pair

  sudo ip link add veth0 netns zpr-a type veth peer veth0 netns zpr-b

  sudo ip -n zpr-a addr add "$A_HOST_ADDR" peer "$B_HOST_ADDR" dev veth0
  sudo ip -n zpr-b addr add "$B_HOST_ADDR" peer "$A_HOST_ADDR" dev veth0

  sudo ip -n zpr-a link set veth0 up
  sudo ip -n zpr-b link set veth0 up


  # TUN devices

  sudo ip -n zpr-a tuntap add name tun0 mode tun user "$ZPR_USER" multi_queue
  sudo ip -n zpr-b tuntap add name tun0 mode tun user "$ZPR_USER" multi_queue

  sudo ip -n zpr-a addr add "$A_ZPR_ADDR" peer "$B_ZPR_ADDR" dev tun0 
  sudo ip -n zpr-b addr add "$B_ZPR_ADDR" peer "$A_ZPR_ADDR" dev tun0

  sudo ip -n zpr-a link set tun0 up
  sudo ip -n zpr-b link set tun0 up

  # Kernel bug: kernels older than 6.10 don't set peer route correctly
  # when interface is down.  I think <https://github.com/torvalds/linux/commit/d0098e4c6b83e502cc1cd96d67ca86bc79a6c559>
  # fixes this issue.  For now, add the addresses after we bring the link up.
  sudo ip -n zpr-a addr add "$A_ZPR_ADDR6" peer "$B_ZPR_ADDR6" dev tun0
  sudo ip -n zpr-b addr add "$B_ZPR_ADDR6" peer "$A_ZPR_ADDR6" dev tun0
}

function destroy_network() {
  sudo ip netns delete zpr-a 2> /dev/null || true
  sudo ip netns delete zpr-b 2> /dev/null || true
}

function create_ca_key_and_cert() {
  CA_NAME=$1
  openssl genrsa -out "$CA_NAME.key"
  openssl x509 -new -subj /CN="$CA_NAME" -key "$CA_NAME.key" -extfile /etc/ssl/openssl.cnf -extensions v3_ca -days 1 -out "$CA_NAME.crt"
}

function create_agent_key_and_cert() {
  CA_NAME=$1
  AGENT_NAME=$2
  openssl genrsa -out "$AGENT_NAME.key"
  openssl req -new -subj /CN="$AGENT_NAME" -key "$AGENT_NAME.key" -config /etc/ssl/openssl.cnf -reqexts v3_req -out "$AGENT_NAME.csr" 2> /dev/null
  openssl x509 -req -CA "$CA_NAME.crt" -CAkey "$CA_NAME.key" -copy_extensions copyall -days 1 -in "$AGENT_NAME.csr" -out "$AGENT_NAME.crt" 2> /dev/null
}

function ping_test() {
  sudo ip netns exec zpr-a ping -q -c 5 -w 5 "$B_ZPR_ADDR" & wait -f $!
  sudo ip netns exec zpr-b ping -q -c 5 -w 5 "$A_ZPR_ADDR" & wait -f $!

  sudo ip netns exec zpr-a ping -q -c 5 -w 5 "$B_ZPR_ADDR6" & wait -f $!
  sudo ip netns exec zpr-b ping -q -c 5 -w 5 "$A_ZPR_ADDR6" & wait -f $!
}

function set_program() {
  SOCKET=$1
  FILE_NAME=$2
  PROGRAM=$3
  sudo "$PH_DEBUG_BIN" -c SET-CAPTURE -p "$SOCKET" --file-path "$FILE_NAME"

  if [ "$PROGRAM" != "None" ]
  then sudo "$PH_DEBUG_BIN" -c SET-CAPTURE-PROGRAM -p "$SOCKET" --program "$PROGRAM"
  fi 
}

function close_program() {
  SOCKET=$1
  sudo "$PH_DEBUG_BIN" -c DELETE-CAPTURE-PROGRAM -p "$SOCKET"
  sudo "$PH_DEBUG_BIN" -c CLOSE-CAPTURE -p "$SOCKET"
}
function check_carrier() {
  NETNS=$1
  IF=$2

  return $(( ! $(sudo ip netns exec "$NETNS" cat "/sys/class/net/$IF/carrier") ))
}

function cleanup() {
  for child in $(jobs -p)
  do kill -9 "$child" 2> /dev/null || true
  done

  wait -f

  destroy_network || true

  popd > /dev/null
  rm -r "$TMPDIR" || true
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

set_program "$A_ZPR_SOCK" cap_test1.pcap 'link[0] == 1 || link[0] == 0'
set_program "$B_ZPR_SOCK" cap_test2.pcap None

PASS=0
if ! ping_test
then PASS=1
fi

close_program "$A_ZPR_SOCK"
close_program "$B_ZPR_SOCK"

# Make sure correct number of incoming packets were captured, either 23 or 24 depending 
# on whether two hello requests are received
sudo tcpdump -r cap_test1.pcap 'link[0] = 1' > checker1.txt
HELLO_COUNT="$(grep -c '0x0000:  0100 8800 0000' checker1.txt)"
PACKET_COUNT="$(grep -c '0x0000:  01' checker1.txt)"

if [[ ("$PACKET_COUNT" != "23" || "$HELLO_COUNT" != "1") &&  ("$PACKET_COUNT" != "24" || "$HELLO_COUNT" != "2") ]]
then PASS=1
fi

# Make sure no data was captured when program is not set
SIZE="$(wc -c cap_test2.pcap | awk '{print $1}')"

if [[ "$SIZE" != "0" ]]
then PASS=1
fi

#
# Cleanup
#

sudo rm cap_test1.pcap
sudo rm cap_test2.pcap

kill "${CHILDREN[@]}" 2> /dev/null || true
sleep 1  # FIXME: let's do something better here


#
# Report status
#

echo
if [[ "$PASS" == 0 ]]
then echo "SUCCESS"
else echo "FAILURE"
fi

exit "$PASS"