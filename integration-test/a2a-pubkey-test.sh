#!/usr/bin/env bash
#
# SECURITY TESTING integration test.
#
# Models a malicious node (a compromised binary) that corrupts forwarded ICMP
# echo requests and re-forges their A2A MICV.  A correct receiver rejects the
# forgery, so the mangled ping never reaches zpr-b.  A tcpdump running in the
# zpr-b namespace watches for the injected "YOU HAVE BEEN PWNED" payload and
# FAILS the test if it ever arrives.
#
# The node is launched with --security-testing-mangle-forwarded-pings, so the
# PH binaries MUST be built with the `enable-security-testing` feature:
#   cargo build -p ph --features enable-security-testing
#
# Run it several ways to see the A2A MICV do its job:
#   ./a2a-pubkey-test.sh                     # keyed MICV: PASSES (forgery rejected)
#   ./a2a-pubkey-test.sh --unkeyed           # unkeyed MICV: FAILS (forgery accepted)
#   ./a2a-pubkey-test.sh --unkeyed --reuse   # unkeyed, no recompute: PASSES
#
# The last case is the key extra evidence: with --reuse the node mangles the
# payload but keeps the original MICV, so even an unkeyed receiver rejects it --
# proving the MICV genuinely covers the payload (not just a prefix of it).
#
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

# The payload the malicious node injects; see security_testing_mangle_ping().
PWNED_STRING="YOU HAVE BEEN PWNED"

source "$(dirname $0)/lib/common_funcs.sh"

ZPR_USER=$USER

# Optionally force old-style unkeyed A2A MICVs on all PH instances (the "old way"
# the A2A key replaced).  With this set the forgery succeeds and the test fails.
UNKEYED_ARG=""
# By default the node recomputes the MICV after mangling (the forgery). With
# --reuse it keeps the original MICV instead, so the mangled ping is rejected
# regardless of keying.
RECOMPUTE_ARG=""
while [[ "$#" -gt 0 ]]; do
  case $1 in
    --unkeyed)
      UNKEYED_ARG="--security-testing-unkeyed-a2a-micv"
      shift
      ;;
    --reuse)
      RECOMPUTE_ARG="--security-testing-recompute-micvs false"
      shift
      ;;
    --help)
      echo "Usage: $0 [--unkeyed] [--reuse]"
      exit 1
      ;;
    *)
      echo "Error: unexpected argument $1" >&2
      echo "Usage: $0 [--unkeyed] [--reuse]"
      exit 1
      ;;
  esac
done

# Substrate (underlay) addresses.
NODE_SUBSTRATE_ADDR_VS=10.0.0.1
NODE_SUBSTRATE_ADDR_A=10.0.1.1
NODE_SUBSTRATE_ADDR_B=10.0.2.1
NODE_SUBSTRATE_ADDR_C=10.0.3.1
NODE_SUBSTRATE_ADDR_C_ALT=10.0.3.129
VS_SUBSTRATE_ADDR=10.0.0.2
A_SUBSTRATE_ADDR=10.0.1.2
B_SUBSTRATE_ADDR=10.0.2.2
C_SUBSTRATE_ADDR=10.0.3.2

# ZPR (overlay) addresses -- IPv6, matching the v6 ping policy.  create_network
# sets up a zpr-c namespace unconditionally, so its address must be defined even
# though this test runs no adapter there.
NODE_ZPR_ADDR=fd5a:5052::2
VS_ZPR_ADDR=fd5a:5052::1
A_ZPR_ADDR=fd00:1:1::1
B_ZPR_ADDR=fd00:1:2::1
C_ZPR_ADDR=fd00:1:3::1
ZPR_SUBNET=fd00:1::0/32

POLICY_BIN="v6-1node-2actor-ping.bin2"

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

# The mangle flag only exists in a feature build; bail early with a clear message
# rather than failing obscurely at node launch.
if ! "$PH_BIN" node --help 2>&1 | grep -q -- --security-testing-mangle-forwarded-pings; then
  echo "ph binary was not built with the 'enable-security-testing' feature."
  echo "Rebuild with: cargo build -p ph --features enable-security-testing"
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

if ! command -v tcpdump > /dev/null; then
  echo "tcpdump not found; it is required to detect the injected payload"
  exit 1
fi

NODE_SOCK=node.sock
VS_SOCK=vs.sock
ADAPTER1_SOCK=adapter1.sock
ADAPTER2_SOCK=adapter2.sock
NODE_CAP_SOCK=node_cap.sock
VS_CAP_SOCK=vs_cap.sock
ADAPTER1_CAP_SOCK=adapter1_cap.sock
ADAPTER2_CAP_SOCK=adapter2_cap.sock

#
# Set up automatic cleanup
#

trap cleanup EXIT

TMPDIR=$(mktemp -d)
pushd "$TMPDIR" > /dev/null

PWNED_PCAP="$TMPDIR/zpr-b-icmp.pcap"

echo "Setting up network"

destroy_network
create_network

create_ca_key_and_cert ca
create_actor_key_and_cert ca vs.zpr
create_actor_key_and_cert ca adapter1
create_actor_key_and_cert ca adapter2

# Temporary hack until our policy compiler is in-repo
cp "$PREGEN/node.key" node.key
cp "$PREGEN/node-cert.pem" node.crt
cp "$PREGEN/node-pubkey.pem" node.pubkey
cp "$PREGEN/actor1-rsa.key" actor1-rsa.key
cp "$PREGEN/actor2-rsa.key" actor2-rsa.key
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

echo "Launching Node (MALICIOUS: mangling forwarded pings${UNKEYED_ARG:+, unkeyed MICVs}${RECOMPUTE_ARG:+, reusing original MICV})"

sudo -E ip netns exec zpr-node sudo -E -u "$ZPR_USER" "$PH_BIN" \
  node \
  --logging "$DEBUG_TARGETS" \
  --control-path "$NODE_SOCK" \
  --capture-path "$NODE_CAP_SOCK" \
  --ca-file ca.crt \
  --certificate-file node.crt \
  --private-key-file node.key \
  --auth-private-key "$NODE_AUTH_PRIVATE_KEY" \
  --advertised-substrate-addr "$NODE_SUBSTRATE_ADDR_VS":5000 \
  --km-impl "$KM_IMPL" \
  --tun-if tun0 \
  --zpr-addr "$NODE_ZPR_ADDR" \
  --security-testing-mangle-forwarded-pings \
  $UNKEYED_ARG $RECOMPUTE_ARG 2>&1 | tee node.log | prefix_log zpr-node &

sleep 2

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
  --zpr-addr "$VS_ZPR_ADDR" \
  $UNKEYED_ARG 2>&1 | tee adapter-vs.log | prefix_log zpr-vs &

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
  --zpr-addr "$A_ZPR_ADDR" \
  $UNKEYED_ARG 2>&1 | tee adapter1.log | prefix_log zpr-a &

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
  --zpr-addr "$B_ZPR_ADDR" \
  $UNKEYED_ARG 2>&1 | tee adapter2.log | prefix_log zpr-b &

#
# Wait for connectivity
#
PASS=0
echo "Wait for TUN carrier..."
wait_for 15 check_carrier zpr-node tun0 || { PASS=1; }
if [[ "$PASS" == 0 ]]; then wait_for 15 check_carrier zpr-vs tun0 || { PASS=1; }; fi
if [[ "$PASS" == 0 ]]; then wait_for 15 check_carrier zpr-a tun0 || { PASS=1; }; fi
if [[ "$PASS" == 0 ]]; then wait_for 15 check_carrier zpr-b tun0 || { PASS=1; }; fi

if [[ "$PASS" == 0 ]]; then
  echo "Carrier has arrived."
  sleep 1

  #
  # Watch zpr-b for the injected payload.  We capture the decapsulated ICMP the
  # zpr-b adapter delivers to its TUN: a rejected forgery never reaches here, an
  # accepted one arrives carrying the PWNED string.
  #
  echo "Starting packet capture on zpr-b..."
  # Safety net: SIGTERM lets tcpdump exit cleanly (and restore the terminal it
  # touched); --kill-after escalates to SIGKILL only if it's wedged in an idle
  # poll() ignoring catchable signals. -U writes each packet immediately, so the
  # pcap is complete even under a hard kill.
  # The unique pcap path makes the pkill match exactly this tcpdump.
  sudo -E ip netns exec zpr-b timeout -s TERM --kill-after=3 30 \
    tcpdump -i tun0 -n -U -w "$PWNED_PCAP" icmp6 2>/dev/null &
  sleep 2

  echo "TEST STARTING: ping zpr-a -> zpr-b"
  # We do NOT check whether the ping succeeds: a correctly-rejected forgery just
  # means no reply, which is the passing case.
  sudo ip netns exec zpr-a ping -6 -q -c 5 -w 5 "$B_ZPR_ADDR" || true

  sleep 2
  # Stop the capture: SIGTERM first so tcpdump cleans up and restores the tty,
  # then SIGKILL as a backstop if it's stuck idle. DON'T block on wait: the outer
  # sudo wrapper does not reliably reap, which previously hung the whole script.
  sudo pkill -TERM -f "tcpdump -i tun0 -n -U -w $PWNED_PCAP" 2>/dev/null || true
  sleep 1
  sudo pkill -KILL -f "tcpdump -i tun0 -n -U -w $PWNED_PCAP" 2>/dev/null || true
  stty sane 2>/dev/null || true

  #
  # Verdict: any captured packet containing the injected string is a breach.
  #
  if grep -a -q "$PWNED_STRING" "$PWNED_PCAP" 2>/dev/null; then
    echo "SECURITY FAILURE: mangled payload \"$PWNED_STRING\" reached zpr-b!"
    PASS=1
  else
    echo "No mangled payload reached zpr-b (forgery rejected)."
  fi
fi

# The pcap was written by root (tcpdump ran under sudo), so it is write-protected
# for us. Remove it as root here so the trap cleanup's rm doesn't stop for an
# interactive "remove write-protected file?" prompt.
sudo rm -f "$PWNED_PCAP" 2>/dev/null || true

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
