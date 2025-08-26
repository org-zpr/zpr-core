# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_ph_cli_global_optspecs
	string join \n p/socket= g/generate h/help V/version
end

function __fish_ph_cli_needs_command
	# Figure out if the current invocation already has a command.
	set -l cmd (commandline -opc)
	set -e cmd[1]
	argparse -s (__fish_ph_cli_global_optspecs) -- $cmd 2>/dev/null
	or return
	if set -q argv[1]
		# Also print the command, so this can be used to figure out what it is.
		echo $argv[1]
		return 1
	end
	return 0
end

function __fish_ph_cli_using_subcommand
	set -l cmd (__fish_ph_cli_needs_command)
	test -z "$cmd"
	and return 1
	contains -- $cmd[1] $argv
end

complete -c ph-cli -n "__fish_ph_cli_needs_command" -s p -l socket -d 'Path to the Packet Handler\'s management socket' -r
complete -c ph-cli -n "__fish_ph_cli_needs_command" -s g -l generate
complete -c ph-cli -n "__fish_ph_cli_needs_command" -s h -l help -d 'Print help'
complete -c ph-cli -n "__fish_ph_cli_needs_command" -s V -l version -d 'Print version'
complete -c ph-cli -n "__fish_ph_cli_needs_command" -f -a "echo"
complete -c ph-cli -n "__fish_ph_cli_needs_command" -f -a "counters" -d 'Display or reset counters'
complete -c ph-cli -n "__fish_ph_cli_needs_command" -f -a "watch" -d 'Connect to the Packet Handler for periodic counter updates'
complete -c ph-cli -n "__fish_ph_cli_needs_command" -f -a "perf-sample" -d 'Start performance sampling (currently not functional)'
complete -c ph-cli -n "__fish_ph_cli_needs_command" -f -a "capture" -d 'Set up or tear down packet captures'
complete -c ph-cli -n "__fish_ph_cli_needs_command" -f -a "link" -d 'Change link state'
complete -c ph-cli -n "__fish_ph_cli_needs_command" -f -a "logging" -d 'Change the log level of a node or adapter'
complete -c ph-cli -n "__fish_ph_cli_needs_command" -f -a "quit" -d 'Exit the CLI'
complete -c ph-cli -n "__fish_ph_cli_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand echo" -s h -l help -d 'Print help'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand counters" -s r -l reset -d 'Reset counters'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand counters" -s h -l help -d 'Print help'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand watch" -s h -l help -d 'Print help'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand perf-sample" -s h -l help -d 'Print help'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand capture; and not __fish_seen_subcommand_from set-file close-file set-program delete-program flush-file sequence help" -s h -l help -d 'Print help'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand capture; and not __fish_seen_subcommand_from set-file close-file set-program delete-program flush-file sequence help" -f -a "set-file" -d 'Set a capture file'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand capture; and not __fish_seen_subcommand_from set-file close-file set-program delete-program flush-file sequence help" -f -a "close-file" -d 'Close a capture file'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand capture; and not __fish_seen_subcommand_from set-file close-file set-program delete-program flush-file sequence help" -f -a "set-program" -d 'Set a BPF to filter captured packets'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand capture; and not __fish_seen_subcommand_from set-file close-file set-program delete-program flush-file sequence help" -f -a "delete-program" -d 'Delete any set BPF'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand capture; and not __fish_seen_subcommand_from set-file close-file set-program delete-program flush-file sequence help" -f -a "flush-file" -d 'Flush any outstanding packets to the capture file'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand capture; and not __fish_seen_subcommand_from set-file close-file set-program delete-program flush-file sequence help" -f -a "sequence" -d 'Create a temporary packet capture'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand capture; and not __fish_seen_subcommand_from set-file close-file set-program delete-program flush-file sequence help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand capture; and __fish_seen_subcommand_from set-file" -s h -l help -d 'Print help'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand capture; and __fish_seen_subcommand_from close-file" -s h -l help -d 'Print help'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand capture; and __fish_seen_subcommand_from set-program" -s h -l help -d 'Print help'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand capture; and __fish_seen_subcommand_from delete-program" -s h -l help -d 'Print help'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand capture; and __fish_seen_subcommand_from flush-file" -s h -l help -d 'Print help'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand capture; and __fish_seen_subcommand_from sequence" -s h -l help -d 'Print help'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand capture; and __fish_seen_subcommand_from help" -f -a "set-file" -d 'Set a capture file'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand capture; and __fish_seen_subcommand_from help" -f -a "close-file" -d 'Close a capture file'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand capture; and __fish_seen_subcommand_from help" -f -a "set-program" -d 'Set a BPF to filter captured packets'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand capture; and __fish_seen_subcommand_from help" -f -a "delete-program" -d 'Delete any set BPF'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand capture; and __fish_seen_subcommand_from help" -f -a "flush-file" -d 'Flush any outstanding packets to the capture file'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand capture; and __fish_seen_subcommand_from help" -f -a "sequence" -d 'Create a temporary packet capture'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand capture; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand link; and not __fish_seen_subcommand_from show configure start stop reset help" -s h -l help -d 'Print help'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand link; and not __fish_seen_subcommand_from show configure start stop reset help" -f -a "show" -d 'Show a link\'s status'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand link; and not __fish_seen_subcommand_from show configure start stop reset help" -f -a "configure" -d 'Configure a link'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand link; and not __fish_seen_subcommand_from show configure start stop reset help" -f -a "start" -d 'Start a link'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand link; and not __fish_seen_subcommand_from show configure start stop reset help" -f -a "stop" -d 'Stop a link'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand link; and not __fish_seen_subcommand_from show configure start stop reset help" -f -a "reset" -d 'Reset a link.  It will require a configure before starting again'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand link; and not __fish_seen_subcommand_from show configure start stop reset help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand link; and __fish_seen_subcommand_from show" -s h -l help -d 'Print help'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand link; and __fish_seen_subcommand_from configure" -s h -l help -d 'Print help'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand link; and __fish_seen_subcommand_from start" -s h -l help -d 'Print help'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand link; and __fish_seen_subcommand_from stop" -s h -l help -d 'Print help'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand link; and __fish_seen_subcommand_from reset" -s h -l help -d 'Print help'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand link; and __fish_seen_subcommand_from help" -f -a "show" -d 'Show a link\'s status'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand link; and __fish_seen_subcommand_from help" -f -a "configure" -d 'Configure a link'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand link; and __fish_seen_subcommand_from help" -f -a "start" -d 'Start a link'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand link; and __fish_seen_subcommand_from help" -f -a "stop" -d 'Stop a link'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand link; and __fish_seen_subcommand_from help" -f -a "reset" -d 'Reset a link.  It will require a configure before starting again'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand link; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand logging" -s h -l help -d 'Print help'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand quit" -s h -l help -d 'Print help'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand help; and not __fish_seen_subcommand_from echo counters watch perf-sample capture link logging quit help" -f -a "echo"
complete -c ph-cli -n "__fish_ph_cli_using_subcommand help; and not __fish_seen_subcommand_from echo counters watch perf-sample capture link logging quit help" -f -a "counters" -d 'Display or reset counters'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand help; and not __fish_seen_subcommand_from echo counters watch perf-sample capture link logging quit help" -f -a "watch" -d 'Connect to the Packet Handler for periodic counter updates'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand help; and not __fish_seen_subcommand_from echo counters watch perf-sample capture link logging quit help" -f -a "perf-sample" -d 'Start performance sampling (currently not functional)'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand help; and not __fish_seen_subcommand_from echo counters watch perf-sample capture link logging quit help" -f -a "capture" -d 'Set up or tear down packet captures'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand help; and not __fish_seen_subcommand_from echo counters watch perf-sample capture link logging quit help" -f -a "link" -d 'Change link state'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand help; and not __fish_seen_subcommand_from echo counters watch perf-sample capture link logging quit help" -f -a "logging" -d 'Change the log level of a node or adapter'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand help; and not __fish_seen_subcommand_from echo counters watch perf-sample capture link logging quit help" -f -a "quit" -d 'Exit the CLI'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand help; and not __fish_seen_subcommand_from echo counters watch perf-sample capture link logging quit help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand help; and __fish_seen_subcommand_from capture" -f -a "set-file" -d 'Set a capture file'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand help; and __fish_seen_subcommand_from capture" -f -a "close-file" -d 'Close a capture file'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand help; and __fish_seen_subcommand_from capture" -f -a "set-program" -d 'Set a BPF to filter captured packets'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand help; and __fish_seen_subcommand_from capture" -f -a "delete-program" -d 'Delete any set BPF'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand help; and __fish_seen_subcommand_from capture" -f -a "flush-file" -d 'Flush any outstanding packets to the capture file'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand help; and __fish_seen_subcommand_from capture" -f -a "sequence" -d 'Create a temporary packet capture'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand help; and __fish_seen_subcommand_from link" -f -a "show" -d 'Show a link\'s status'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand help; and __fish_seen_subcommand_from link" -f -a "configure" -d 'Configure a link'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand help; and __fish_seen_subcommand_from link" -f -a "start" -d 'Start a link'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand help; and __fish_seen_subcommand_from link" -f -a "stop" -d 'Stop a link'
complete -c ph-cli -n "__fish_ph_cli_using_subcommand help; and __fish_seen_subcommand_from link" -f -a "reset" -d 'Reset a link.  It will require a configure before starting again'
