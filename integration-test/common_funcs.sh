#!/usr/bin/env bash


# Our PKI helper tool
ZPR_PKI_BIN=$(realpath "$(dirname $0)/../tools/zpr-pki")


#
# Functions used in multiple integration tests
#

function prefix_log() {
  SYSNAME=$1
  printf -v PREFIX '%10s' "[$SYSNAME]"
  sed "s/^/$PREFIX /"
}

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
  sudo ip netns add zpr-node
  sudo ip netns add zpr-vs
  sudo ip netns add zpr-a
  sudo ip netns add zpr-b
  sudo ip netns add zpr-c

  # loopback

  sudo ip -n zpr-node link set lo up
  sudo ip -n zpr-vs link set lo up
  sudo ip -n zpr-a link set lo up
  sudo ip -n zpr-b link set lo up
  sudo ip -n zpr-c link set lo up

  # virtual Ethernet pair

  # Kernel bug: Linux refuses to create a veth device in a netns with
  # a name matching that of a veth device in the root ns, but not the other
  # way around.  And weirdly, it will happily _autogenerate_ such names.
  # So we rely on that for now rather than explicitly specifying the names.
  sudo ip link add netns zpr-vs type veth peer veth-zpr-vs netns zpr-node  # zpr-a:veth0 / zpr-node:veth-zpr-vs
  sudo ip link add netns zpr-a type veth peer veth-zpr-a netns zpr-node  # zpr-a:veth0 / zpr-node:veth-zpr-a
  sudo ip link add netns zpr-b type veth peer veth-zpr-b netns zpr-node  # zpr-b:veth0 / zpr-node:veth-zpr-b
  sudo ip link add netns zpr-c type veth peer veth-zpr-c netns zpr-node  # zpr-c:veth0 / zpr-node:veth-zpr-c

  sudo ip -n zpr-node addr add "$NODE_SUBSTRATE_ADDR_VS" peer "$VS_SUBSTRATE_ADDR" dev veth-zpr-vs
  sudo ip -n zpr-node addr add "$NODE_SUBSTRATE_ADDR_A" peer "$A_SUBSTRATE_ADDR" dev veth-zpr-a
  sudo ip -n zpr-node addr add "$NODE_SUBSTRATE_ADDR_B" peer "$B_SUBSTRATE_ADDR" dev veth-zpr-b
  sudo ip -n zpr-node addr add "$NODE_SUBSTRATE_ADDR_C/24" dev veth-zpr-c
  if [ -n "${NODE_SUBSTRATE_ADDR_C_ALT-}" ]
  then sudo ip -n zpr-node addr add "$NODE_SUBSTRATE_ADDR_C_ALT/24" dev veth-zpr-c  # Used for testing routing.
  fi
  sudo ip -n zpr-vs addr add "$VS_SUBSTRATE_ADDR" peer "$NODE_SUBSTRATE_ADDR_VS" dev veth0
  sudo ip -n zpr-a addr add "$A_SUBSTRATE_ADDR" peer "$NODE_SUBSTRATE_ADDR_A" dev veth0
  sudo ip -n zpr-b addr add "$B_SUBSTRATE_ADDR" peer "$NODE_SUBSTRATE_ADDR_B" dev veth0
  sudo ip -n zpr-c addr add "$C_SUBSTRATE_ADDR/24" dev veth0

  sudo ip -n zpr-node link set veth-zpr-vs up
  sudo ip -n zpr-node link set veth-zpr-a up
  sudo ip -n zpr-node link set veth-zpr-b up
  sudo ip -n zpr-node link set veth-zpr-c up
  sudo ip -n zpr-vs link set veth0 up
  sudo ip -n zpr-a link set veth0 up
  sudo ip -n zpr-b link set veth0 up
  sudo ip -n zpr-c link set veth0 up

  # TUN devices

  sudo ip -n zpr-node tuntap add name tun0 mode tun user "$ZPR_USER" multi_queue
  sudo ip -n zpr-vs tuntap add name tun0 mode tun user "$ZPR_USER" multi_queue
  sudo ip -n zpr-a tuntap add name tun0 mode tun user "$ZPR_USER" multi_queue
  sudo ip -n zpr-b tuntap add name tun0 mode tun user "$ZPR_USER" multi_queue
  sudo ip -n zpr-c tuntap add name tun0 mode tun user "$ZPR_USER" multi_queue

  sudo ip -n zpr-node link set tun0 up
  sudo ip -n zpr-vs link set tun0 up
  sudo ip -n zpr-a link set tun0 up
  sudo ip -n zpr-b link set tun0 up
  sudo ip -n zpr-c link set tun0 up

  # Kernel bug: kernels older than 6.10 don't set peer route correctly
  # when interface is down.  I think <https://github.com/torvalds/linux/commit/d0098e4c6b83e502cc1cd96d67ca86bc79a6c559>
  # fixes this issue.  For now, add the addresses after we bring the link up.
  sudo ip -n zpr-node addr add "$NODE_ZPR_ADDR" peer "$VS_ZPR_ADDR" dev tun0
  sudo ip -n zpr-vs addr add "$VS_ZPR_ADDR" peer "$NODE_ZPR_ADDR" dev tun0
  sudo ip -n zpr-a addr add "$A_ZPR_ADDR" peer "$ZPR_SUBNET" dev tun0
  sudo ip -n zpr-b addr add "$B_ZPR_ADDR" peer "$ZPR_SUBNET" dev tun0
  sudo ip -n zpr-c addr add "$C_ZPR_ADDR" peer "$ZPR_SUBNET" dev tun0
}

function destroy_network() {
  sudo ip netns delete zpr-node 2> /dev/null || true
  sudo ip netns delete zpr-vs 2> /dev/null || true
  sudo ip netns delete zpr-a 2> /dev/null || true
  sudo ip netns delete zpr-b 2> /dev/null || true
  sudo ip netns delete zpr-c 2> /dev/null || true
}

function create_ca_key_and_cert() {
  CA_NAME=$1
  # We can't do this properly until we pull in the policy compiler
  # So just use the pair set up in the examples directory for now
  cp "$PREGEN/ca-key.pem" "$CA_NAME.key"
  cp "$PREGEN/ca-cert.pem" "$CA_NAME.crt"
  #"$ZPR_PKI_BIN" gencakey >"$CA_NAME.key"
  #"$ZPR_PKI_BIN" gencacert /CN="$CA_NAME" 1 <"$CA_NAME.key" >"$CA_NAME.crt"
  #openssl genrsa -out "$CA_NAME.key"
  #openssl x509 -new -subj /CN="$CA_NAME" -key "$CA_NAME.key" -extfile /etc/ssl/openssl.cnf -extensions v3_ca -days 1 -out "$CA_NAME.crt"
}

function create_actor_key_and_cert() {
  CA_NAME=$1
  ACTOR_NAME=$2
  "$ZPR_PKI_BIN" genkey >"$ACTOR_NAME.key"
  "$ZPR_PKI_BIN" pubkey <"$ACTOR_NAME.key" >"$ACTOR_NAME.pubkey"
  "$ZPR_PKI_BIN" gensignedcert "$CA_NAME.crt" "$CA_NAME.key" /CN="$ACTOR_NAME" 1 <"$ACTOR_NAME.pubkey" >"$ACTOR_NAME.crt"
  
  #openssl genrsa -out "$ACTOR_NAME.key"
  #openssl req -new -subj /CN="$ACTOR_NAME" -key "$ACTOR_NAME.key" -config /etc/ssl/openssl.cnf -reqexts v3_req -out "$ACTOR_NAME.csr" 2> /dev/null
  #openssl x509 -req -CA "$CA_NAME.crt" -CAkey "$CA_NAME.key" -copy_extensions copyall -days 1 -in "$ACTOR_NAME.csr" -out "$ACTOR_NAME.crt" 2> /dev/null
}

function emit_vs_config() {
  CA_NAME=$1
  VS_ACTOR_NAME=$2
  cat <<EOF
adapter_cert: $(realpath "$2.crt")
root_ca: $(realpath "$1.crt")
disable_connect_validation: true
vs_cert: "$PREGEN/zpr-rsa-cert.pem"
vs_key: "$PREGEN/zpr-rsa-key.pem"
EOF
}

function ping_a_b() {
  sudo ip netns exec zpr-a ping -q -c 5 -w 5 "$B_ZPR_ADDR" & wait -f $!
  sudo ip netns exec zpr-b ping -q -c 5 -w 5 "$A_ZPR_ADDR" & wait -f $!
}

function ping_test() {
  sudo ip netns exec zpr-node ping -q -c 5 -w 5 "$VS_ZPR_ADDR" & wait -f $!
  sudo ip netns exec zpr-vs ping -q -c 5 -w 5 "$NODE_ZPR_ADDR" & wait -f $!
  ping_a_b

  if [[ "$NUM_ACTORS" -ge 3 ]]; then
    sudo ip netns exec zpr-a ping -q -c 5 -w 5 "$C_ZPR_ADDR" & wait -f $!
    sudo ip netns exec zpr-b ping -q -c 5 -w 5 "$C_ZPR_ADDR" & wait -f $!
    sudo ip netns exec zpr-c ping -q -c 5 -w 5 "$A_ZPR_ADDR" & wait -f $!
    sudo ip netns exec zpr-c ping -q -c 5 -w 5 "$B_ZPR_ADDR" & wait -f $!
  fi
}

function check_carrier() {
  NETNS=$1
  IF=$2

  return $(( ! $(sudo ip netns exec "$NETNS" cat "/sys/class/net/$IF/carrier") ))
}

# Visible sleep for n seconds.  Takes one arg: number of seconds.
function countdown() {
    count=$1
    (( ++count ))
    while (( --count > 0 )); do
        echo -n "$count...   "
        sleep 1
    done
    echo
}

# Get all descendant PIDs whose name matches a specific list
function get_descendants() {
    exenames="(ph|node|adapter|vservice)"
    regex="$exenames\(([0-9]+)\)"
    echo $(pstree -pT "$$" | egrep -o "$regex" | sed -E "s/$regex/\2/")
}


# Takes one arg- filepath relative to TMPDIR
function emitlog() {
    echo -e "\n\n==== $1 ====\n"
    if [ -e "$TMPDIR/$1" ]
        then
            cat "$TMPDIR/$1"
        else
            echo "(MISSING)"
    fi
}


function cleanup() {
  for child in $(jobs -p)
  do kill -9 "$child" 2> /dev/null || true
  done

  wait -f

  destroy_network || true

  SHOW_LOGS="${ZPR_TEST_VERBOSE:-no}"

  if [ "$SHOW_LOGS" != "no" ]
     then
         emitlog "node.log"
         emitlog "vs.log"
         emitlog "adapter1.log"
         emitlog "adapter2.log"
         emitlog "adapter3.log"
  fi

  popd > /dev/null
  rm -r "$TMPDIR" || true
}
