#!/usr/bin/env bash

# Usage message
usage() {
    echo "Usage:"
	echo "    $0 [--agent_protocol <IPv4|IPv6>] [--num_agents <number of agents>"
    exit 1
}

# Parse command-line arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --agent_protocol)
            if [[ -n $2 && ! $2 == --* ]]; then
                AGENT_PROTOCOL="${2,,}"
                shift 2
            else
                echo "Error: --agent_protocol requires an argument [IPv4|IPv6]." >&2
                usage
            fi
            ;;
	--num_agents)
            if [[ -n $2 && ! $2 == --* && $2 -ge 2 && $2 -le 3 ]]; then
	        NUM_AGENTS=$2
	        shift 2
	    else
	        echo "Error: Only 2 or 3 agents currently supported." >&2
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
if [ -z "$AGENT_PROTOCOL" ]; then
    echo "Error: --agent_protocol is required."
    usage
fi

case "$AGENT_PROTOCOL" in
    ipv4)
        echo "Running test in IPv4 mode"

		NODE_ZPR_ADDR=fd5a:5052::2
		VS_ZPR_ADDR=fd5a:5052::1

		A_ZPR_ADDR=10.253.1.1
		B_ZPR_ADDR=10.253.2.1
		C_ZPR_ADDR=10.253.3.1
		ZPR_SUBNET=10.253.0.0/16

		POLICY_BIN="v4-1node-${NUM_AGENTS}agent-ping.bin"
        ;;
    ipv6)
        echo "Running test in IPv6 mode"

		NODE_ZPR_ADDR=fd5a:5052::2
		VS_ZPR_ADDR=fd5a:5052::1

		A_ZPR_ADDR=fd00:1:1::1
		B_ZPR_ADDR=fd00:1:2::1
		C_ZPR_ADDR=fd00:1:3::1
		ZPR_SUBNET=fd00:1::0/32

		POLICY_BIN="v6-1node-${NUM_AGENTS}agent-ping.bin"
        ;;
    *)
        echo "Protocol '$AGENT_PROTOCOL' not supported."
		echo
		usage
        ;;
esac
