# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_ph_global_optspecs
	string join \n h/help V/version
end

function __fish_ph_needs_command
	# Figure out if the current invocation already has a command.
	set -l cmd (commandline -opc)
	set -e cmd[1]
	argparse -s (__fish_ph_global_optspecs) -- $cmd 2>/dev/null
	or return
	if set -q argv[1]
		# Also print the command, so this can be used to figure out what it is.
		echo $argv[1]
		return 1
	end
	return 0
end

function __fish_ph_using_subcommand
	set -l cmd (__fish_ph_needs_command)
	test -z "$cmd"
	and return 1
	contains -- $cmd[1] $argv
end

complete -c ph -n "__fish_ph_needs_command" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c ph -n "__fish_ph_needs_command" -s V -l version -d 'Print version'
complete -c ph -n "__fish_ph_needs_command" -f -a "adapter" -d 'Start the handler in adapter mode'
complete -c ph -n "__fish_ph_needs_command" -f -a "node" -d 'Start the handler in node mode'
complete -c ph -n "__fish_ph_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c ph -n "__fish_ph_using_subcommand adapter" -s c -l config-file -d 'Path to adapter configuration file (any options specified on command line will override configuration file)' -r -F
complete -c ph -n "__fish_ph_using_subcommand adapter" -l control-path -d 'Unix domain socket path for the "control" interface' -r
complete -c ph -n "__fish_ph_using_subcommand adapter" -s a -l self-addr -d 'For a node this is listen substrate address for dock, for adapter it is best to leave this at its default setting (0.0.0.0:0)' -r
complete -c ph -n "__fish_ph_using_subcommand adapter" -l ca-file -d 'Certificate of the Certificate Authority' -r
complete -c ph -n "__fish_ph_using_subcommand adapter" -l certificate-file -d 'Certificate including the noise public key, signed by the authority' -r
complete -c ph -n "__fish_ph_using_subcommand adapter" -s k -l private-key-file -d 'Path to the noise private key file (PEM format)' -r
complete -c ph -n "__fish_ph_using_subcommand adapter" -s K -l noise-private-key -d 'Base64 encoded noise private key (alternative to specifying a PEM encoded private-key-file)' -r
complete -c ph -n "__fish_ph_using_subcommand adapter" -s i -l tun-if -d 'TUN device to use, eg "tun1" (leave blank for automatic selection -- the default)' -r
complete -c ph -n "__fish_ph_using_subcommand adapter" -s z -l zpr-addr -d 'ZPR address (no port) of the adapter (must match your TUN address if it has one)' -r
complete -c ph -n "__fish_ph_using_subcommand adapter" -s l -l logging -d 'Set log level using key value pairs: <target>=<LEVEL> The options for targets are:     all, capture, datapath, flow_mgmt, link_state,     mgmt_events, net_os, peer_mgmt, reporting, rpc,     startup, visa_mgmt, zdp The options for levels are:     OFF, ERROR, WARN, INFO, DEBUG, TRACE You can include as many key-value pairs as you want. If you do multiple pairs with the same key, the last last pair will be the one considered. If you include a pair with the target all, you can still set the level for individual targets --logging zdp=TRACE link_state=TRACE all=DEBUG would set all the targets to the DEBUG level, except zdp and link_state, which would be set to TRACE' -r
complete -c ph -n "__fish_ph_using_subcommand adapter" -l io-engine -d 'Which packet I/O engine to use' -r -f -a "auto\t''
io_uring\t''
posix_unbatched\t''"
complete -c ph -n "__fish_ph_using_subcommand adapter" -s g -l generate -r
complete -c ph -n "__fish_ph_using_subcommand adapter" -s N -l node-addr -d 'Substrate address of the node to connect to' -r
complete -c ph -n "__fish_ph_using_subcommand adapter" -s b -l node-public-key-file -d 'PEM file holding the nodes noise public key' -r -F
complete -c ph -n "__fish_ph_using_subcommand adapter" -l bootstrap-key -d 'PEM file holding the boostrap RSA private key' -r -F
complete -c ph -n "__fish_ph_using_subcommand adapter" -s h -l help -d 'Print help'
complete -c ph -n "__fish_ph_using_subcommand node" -s c -l config-file -d 'Path to node configuration file (any options specified on command line will override configuration file)' -r -F
complete -c ph -n "__fish_ph_using_subcommand node" -l control-path -d 'Unix domain socket path for the "control" interface' -r
complete -c ph -n "__fish_ph_using_subcommand node" -s a -l self-addr -d 'For a node this is listen substrate address for dock, for adapter it is best to leave this at its default setting (0.0.0.0:0)' -r
complete -c ph -n "__fish_ph_using_subcommand node" -l ca-file -d 'Certificate of the Certificate Authority' -r
complete -c ph -n "__fish_ph_using_subcommand node" -l certificate-file -d 'Certificate including the noise public key, signed by the authority' -r
complete -c ph -n "__fish_ph_using_subcommand node" -s k -l private-key-file -d 'Path to the noise private key file (PEM format)' -r
complete -c ph -n "__fish_ph_using_subcommand node" -s K -l noise-private-key -d 'Base64 encoded noise private key (alternative to specifying a PEM encoded private-key-file)' -r
complete -c ph -n "__fish_ph_using_subcommand node" -s i -l tun-if -d 'TUN device to use, eg "tun1" (leave blank for automatic selection -- the default)' -r
complete -c ph -n "__fish_ph_using_subcommand node" -s z -l zpr-addr -d 'ZPR address (no port) of the adapter (must match your TUN address if it has one)' -r
complete -c ph -n "__fish_ph_using_subcommand node" -s l -l logging -d 'Set log level using key value pairs: <target>=<LEVEL> The options for targets are:     all, capture, datapath, flow_mgmt, link_state,     mgmt_events, net_os, peer_mgmt, reporting, rpc,     startup, visa_mgmt, zdp The options for levels are:     OFF, ERROR, WARN, INFO, DEBUG, TRACE You can include as many key-value pairs as you want. If you do multiple pairs with the same key, the last last pair will be the one considered. If you include a pair with the target all, you can still set the level for individual targets --logging zdp=TRACE link_state=TRACE all=DEBUG would set all the targets to the DEBUG level, except zdp and link_state, which would be set to TRACE' -r
complete -c ph -n "__fish_ph_using_subcommand node" -l io-engine -d 'Which packet I/O engine to use' -r -f -a "auto\t''
io_uring\t''
posix_unbatched\t''"
complete -c ph -n "__fish_ph_using_subcommand node" -s g -l generate -r
complete -c ph -n "__fish_ph_using_subcommand node" -s h -l help -d 'Print help'
complete -c ph -n "__fish_ph_using_subcommand help; and not __fish_seen_subcommand_from adapter node help" -f -a "adapter" -d 'Start the handler in adapter mode'
complete -c ph -n "__fish_ph_using_subcommand help; and not __fish_seen_subcommand_from adapter node help" -f -a "node" -d 'Start the handler in node mode'
complete -c ph -n "__fish_ph_using_subcommand help; and not __fish_seen_subcommand_from adapter node help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
