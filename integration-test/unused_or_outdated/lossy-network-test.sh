#!/usr/bin/env bash
NETEM_PARAMS="loss random 10%" exec "$(dirname $0)/one-node-test.sh"
