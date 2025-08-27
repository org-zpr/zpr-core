
using namespace System.Management.Automation
using namespace System.Management.Automation.Language

Register-ArgumentCompleter -Native -CommandName 'ph' -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $commandElements = $commandAst.CommandElements
    $command = @(
        'ph'
        for ($i = 1; $i -lt $commandElements.Count; $i++) {
            $element = $commandElements[$i]
            if ($element -isnot [StringConstantExpressionAst] -or
                $element.StringConstantType -ne [StringConstantType]::BareWord -or
                $element.Value.StartsWith('-') -or
                $element.Value -eq $wordToComplete) {
                break
        }
        $element.Value
    }) -join ';'

    $completions = @(switch ($command) {
        'ph' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('adapter', 'adapter', [CompletionResultType]::ParameterValue, 'Start the handler in adapter mode')
            [CompletionResult]::new('node', 'node', [CompletionResultType]::ParameterValue, 'Start the handler in node mode')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'ph;adapter' {
            [CompletionResult]::new('-c', '-c', [CompletionResultType]::ParameterName, 'Path to adapter configuration file (any options specified on command line will override configuration file)')
            [CompletionResult]::new('--config-file', '--config-file', [CompletionResultType]::ParameterName, 'Path to adapter configuration file (any options specified on command line will override configuration file)')
            [CompletionResult]::new('--control-path', '--control-path', [CompletionResultType]::ParameterName, 'Unix domain socket path for the "control" interface')
            [CompletionResult]::new('-a', '-a', [CompletionResultType]::ParameterName, 'For a node this is listen substrate address for dock, for adapter it is best to leave this at its default setting (0.0.0.0:0)')
            [CompletionResult]::new('--self-addr', '--self-addr', [CompletionResultType]::ParameterName, 'For a node this is listen substrate address for dock, for adapter it is best to leave this at its default setting (0.0.0.0:0)')
            [CompletionResult]::new('--ca-file', '--ca-file', [CompletionResultType]::ParameterName, 'Certificate of the Certificate Authority')
            [CompletionResult]::new('--certificate-file', '--certificate-file', [CompletionResultType]::ParameterName, 'Certificate including the noise public key, signed by the authority')
            [CompletionResult]::new('-k', '-k', [CompletionResultType]::ParameterName, 'Path to the noise private key file (PEM format)')
            [CompletionResult]::new('--private-key-file', '--private-key-file', [CompletionResultType]::ParameterName, 'Path to the noise private key file (PEM format)')
            [CompletionResult]::new('-K', '-K ', [CompletionResultType]::ParameterName, 'Base64 encoded noise private key (alternative to specifying a PEM encoded private-key-file)')
            [CompletionResult]::new('--noise-private-key', '--noise-private-key', [CompletionResultType]::ParameterName, 'Base64 encoded noise private key (alternative to specifying a PEM encoded private-key-file)')
            [CompletionResult]::new('-i', '-i', [CompletionResultType]::ParameterName, 'TUN device to use, eg "tun1" (leave blank for automatic selection -- the default)')
            [CompletionResult]::new('--tun-if', '--tun-if', [CompletionResultType]::ParameterName, 'TUN device to use, eg "tun1" (leave blank for automatic selection -- the default)')
            [CompletionResult]::new('-z', '-z', [CompletionResultType]::ParameterName, 'ZPR address (no port) of the adapter (must match your TUN address if it has one)')
            [CompletionResult]::new('--zpr-addr', '--zpr-addr', [CompletionResultType]::ParameterName, 'ZPR address (no port) of the adapter (must match your TUN address if it has one)')
            [CompletionResult]::new('-l', '-l', [CompletionResultType]::ParameterName, 'Set log level using key value pairs: <target>=<LEVEL> The options for targets are:     all, capture, datapath, flow_mgmt, link_state,     mgmt_events, net_os, peer_mgmt, reporting, rpc,     startup, visa_mgmt, zdp The options for levels are:     OFF, ERROR, WARN, INFO, DEBUG, TRACE You can include as many key-value pairs as you want. If you do multiple pairs with the same key, the last last pair will be the one considered. If you include a pair with the target all, you can still set the level for individual targets --logging zdp=TRACE link_state=TRACE all=DEBUG would set all the targets to the DEBUG level, except zdp and link_state, which would be set to TRACE')
            [CompletionResult]::new('--logging', '--logging', [CompletionResultType]::ParameterName, 'Set log level using key value pairs: <target>=<LEVEL> The options for targets are:     all, capture, datapath, flow_mgmt, link_state,     mgmt_events, net_os, peer_mgmt, reporting, rpc,     startup, visa_mgmt, zdp The options for levels are:     OFF, ERROR, WARN, INFO, DEBUG, TRACE You can include as many key-value pairs as you want. If you do multiple pairs with the same key, the last last pair will be the one considered. If you include a pair with the target all, you can still set the level for individual targets --logging zdp=TRACE link_state=TRACE all=DEBUG would set all the targets to the DEBUG level, except zdp and link_state, which would be set to TRACE')
            [CompletionResult]::new('--io-engine', '--io-engine', [CompletionResultType]::ParameterName, 'Which packet I/O engine to use')
            [CompletionResult]::new('-g', '-g', [CompletionResultType]::ParameterName, 'g')
            [CompletionResult]::new('--generate', '--generate', [CompletionResultType]::ParameterName, 'generate')
            [CompletionResult]::new('-N', '-N ', [CompletionResultType]::ParameterName, 'Substrate address of the node to connect to')
            [CompletionResult]::new('--node-addr', '--node-addr', [CompletionResultType]::ParameterName, 'Substrate address of the node to connect to')
            [CompletionResult]::new('-b', '-b', [CompletionResultType]::ParameterName, 'PEM file holding the nodes noise public key')
            [CompletionResult]::new('--node-public-key-file', '--node-public-key-file', [CompletionResultType]::ParameterName, 'PEM file holding the nodes noise public key')
            [CompletionResult]::new('--bootstrap-key', '--bootstrap-key', [CompletionResultType]::ParameterName, 'PEM file holding the boostrap RSA private key')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'ph;node' {
            [CompletionResult]::new('-c', '-c', [CompletionResultType]::ParameterName, 'Path to node configuration file (any options specified on command line will override configuration file)')
            [CompletionResult]::new('--config-file', '--config-file', [CompletionResultType]::ParameterName, 'Path to node configuration file (any options specified on command line will override configuration file)')
            [CompletionResult]::new('--control-path', '--control-path', [CompletionResultType]::ParameterName, 'Unix domain socket path for the "control" interface')
            [CompletionResult]::new('-a', '-a', [CompletionResultType]::ParameterName, 'For a node this is listen substrate address for dock, for adapter it is best to leave this at its default setting (0.0.0.0:0)')
            [CompletionResult]::new('--self-addr', '--self-addr', [CompletionResultType]::ParameterName, 'For a node this is listen substrate address for dock, for adapter it is best to leave this at its default setting (0.0.0.0:0)')
            [CompletionResult]::new('--ca-file', '--ca-file', [CompletionResultType]::ParameterName, 'Certificate of the Certificate Authority')
            [CompletionResult]::new('--certificate-file', '--certificate-file', [CompletionResultType]::ParameterName, 'Certificate including the noise public key, signed by the authority')
            [CompletionResult]::new('-k', '-k', [CompletionResultType]::ParameterName, 'Path to the noise private key file (PEM format)')
            [CompletionResult]::new('--private-key-file', '--private-key-file', [CompletionResultType]::ParameterName, 'Path to the noise private key file (PEM format)')
            [CompletionResult]::new('-K', '-K ', [CompletionResultType]::ParameterName, 'Base64 encoded noise private key (alternative to specifying a PEM encoded private-key-file)')
            [CompletionResult]::new('--noise-private-key', '--noise-private-key', [CompletionResultType]::ParameterName, 'Base64 encoded noise private key (alternative to specifying a PEM encoded private-key-file)')
            [CompletionResult]::new('-i', '-i', [CompletionResultType]::ParameterName, 'TUN device to use, eg "tun1" (leave blank for automatic selection -- the default)')
            [CompletionResult]::new('--tun-if', '--tun-if', [CompletionResultType]::ParameterName, 'TUN device to use, eg "tun1" (leave blank for automatic selection -- the default)')
            [CompletionResult]::new('-z', '-z', [CompletionResultType]::ParameterName, 'ZPR address (no port) of the adapter (must match your TUN address if it has one)')
            [CompletionResult]::new('--zpr-addr', '--zpr-addr', [CompletionResultType]::ParameterName, 'ZPR address (no port) of the adapter (must match your TUN address if it has one)')
            [CompletionResult]::new('-l', '-l', [CompletionResultType]::ParameterName, 'Set log level using key value pairs: <target>=<LEVEL> The options for targets are:     all, capture, datapath, flow_mgmt, link_state,     mgmt_events, net_os, peer_mgmt, reporting, rpc,     startup, visa_mgmt, zdp The options for levels are:     OFF, ERROR, WARN, INFO, DEBUG, TRACE You can include as many key-value pairs as you want. If you do multiple pairs with the same key, the last last pair will be the one considered. If you include a pair with the target all, you can still set the level for individual targets --logging zdp=TRACE link_state=TRACE all=DEBUG would set all the targets to the DEBUG level, except zdp and link_state, which would be set to TRACE')
            [CompletionResult]::new('--logging', '--logging', [CompletionResultType]::ParameterName, 'Set log level using key value pairs: <target>=<LEVEL> The options for targets are:     all, capture, datapath, flow_mgmt, link_state,     mgmt_events, net_os, peer_mgmt, reporting, rpc,     startup, visa_mgmt, zdp The options for levels are:     OFF, ERROR, WARN, INFO, DEBUG, TRACE You can include as many key-value pairs as you want. If you do multiple pairs with the same key, the last last pair will be the one considered. If you include a pair with the target all, you can still set the level for individual targets --logging zdp=TRACE link_state=TRACE all=DEBUG would set all the targets to the DEBUG level, except zdp and link_state, which would be set to TRACE')
            [CompletionResult]::new('--io-engine', '--io-engine', [CompletionResultType]::ParameterName, 'Which packet I/O engine to use')
            [CompletionResult]::new('-g', '-g', [CompletionResultType]::ParameterName, 'g')
            [CompletionResult]::new('--generate', '--generate', [CompletionResultType]::ParameterName, 'generate')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'ph;help' {
            [CompletionResult]::new('adapter', 'adapter', [CompletionResultType]::ParameterValue, 'Start the handler in adapter mode')
            [CompletionResult]::new('node', 'node', [CompletionResultType]::ParameterValue, 'Start the handler in node mode')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'ph;help;adapter' {
            break
        }
        'ph;help;node' {
            break
        }
        'ph;help;help' {
            break
        }
    })

    $completions.Where{ $_.CompletionText -like "$wordToComplete*" } |
        Sort-Object -Property ListItemText
}
