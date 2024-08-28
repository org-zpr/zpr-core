#!/usr/bin/bash

#
# Functions used in multiple integration tests
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
