#!/usr/bin/env bash
set -euo pipefail
VS_BIN=$(realpath "$(dirname $0)/../visaservice/core/build/vservice")
VS_CONFORM_BIN=$(realpath "$(dirname $0)/../visaservice/vs-conform/build/vs-conform")
PREGEN=$(realpath "$(dirname $0)/pregen")

source "$(dirname $0)/common_funcs.sh"

VS_ADDR=127.0.0.1
VS_PORT=12345
VS_LISTEN_ADDR="$VS_ADDR":"$VS_PORT"


SHOW_CAPTURE="${ZPR_TEST_VERBOSE:-no}"


#
# Set up automatic cleanup
#
function cleanupvs() {
    for child in $(jobs -p)
    do kill -9 "$child" 2> /dev/null || true
    done

    wait

    SHOW_LOGS="${ZPR_TEST_VERBOSE:-no}"

    if [ "$SHOW_LOGS" != "no" ]
    then
        emitlog "vs.log"
        emitlog "conform.log"
    fi

    popd > /dev/null
    rm -r "$TMPDIR" || true
}

trap cleanupvs EXIT

TMPDIR=$(mktemp -d)
pushd "$TMPDIR" >/dev/null


#
# Launch Visa Service
#
"$VS_BIN" -c "$PREGEN/conform-vs-config.yaml" \
    -p "$PREGEN/conform-policy.bin" \
    --listen_addr "$VS_LISTEN_ADDR" 2>&1 | tee vs.log | prefix_log vs &
VS_PID=$!

sleep 2

#
# Run the conform test in foreground
#
"$VS_CONFORM_BIN" -v "$VS_PORT" "$VS_ADDR" \
    "$PREGEN/conform-node-cert.pem" 2>&1 | tee conform.log | prefix_log conform 

PASS=$?

#
# Cleanup
#

echo
echo "Terminating visa service (PID=$VS_PID)"
sleep 1
kill -SIGINT "$VS_PID"
sleep 1

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
