#!/usr/bin/env bash

# Usage message
usage() {
    echo "Usage:"
	echo "    $0 [--actor_protocol <IPv4|IPv6>] [--num_actors <number of actors>]"
    exit 1
}

# Parse command-line arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --actor_protocol)
            if [[ -n $2 && ! $2 == --* ]]; then
                ACTOR_PROTOCOL="${2,,}"
                shift 2
            else
                echo "Error: --actor_protocol requires an argument [IPv4|IPv6]." >&2
                usage
            fi
            ;;
	--num_actors)
            if [[ -n $2 && ! $2 == --* && $2 -ge 2 && $2 -le 3 ]]; then
	        NUM_ACTORS=$2
	        shift 2
	    else
	        echo "Error: Only 2 or 3 actors currently supported." >&2
		usage
	    fi
	    ;;
        --help)
            usage
            ;;
        --*)
            echo "Error: Invalid option $1" >&2
            usage
            ;;
        *)
            echo "Error: Unexpected argument $1" >&2
            usage
            ;;
    esac
done

# Check if protocol is set
if [ -z "$ACTOR_PROTOCOL" ]; then
    echo "Error: --actor_protocol is required."
    usage
fi

case "$ACTOR_PROTOCOL" in
    ipv4)
        echo "Running test in IPv4 mode"

		NODE_ZPR_ADDR=fd5a:5052::2
		VS_ZPR_ADDR=fd5a:5052::1

		A_ZPR_ADDR=10.253.1.1
		B_ZPR_ADDR=10.253.2.1
		C_ZPR_ADDR=10.253.3.1
		ZPR_SUBNET=10.253.0.0/16

		POLICY_BIN="v4-1node-${NUM_ACTORS}actor-ping.bin2"
        ;;
    ipv6)
        echo "Running test in IPv6 mode"

		NODE_ZPR_ADDR=fd5a:5052::2
		VS_ZPR_ADDR=fd5a:5052::1

		A_ZPR_ADDR=fd00:1:1::1
		B_ZPR_ADDR=fd00:1:2::1
		C_ZPR_ADDR=fd00:1:3::1
		ZPR_SUBNET=fd00:1::0/32

		POLICY_BIN="v6-1node-${NUM_ACTORS}actor-ping.bin2"
        ;;
    *)
        echo "Protocol '$ACTOR_PROTOCOL' not supported."
		echo
		usage
        ;;
esac
