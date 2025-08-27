
use builtin;
use str;

set edit:completion:arg-completer[ph] = {|@words|
    fn spaces {|n|
        builtin:repeat $n ' ' | str:join ''
    }
    fn cand {|text desc|
        edit:complex-candidate $text &display=$text' '(spaces (- 14 (wcswidth $text)))$desc
    }
    var command = 'ph'
    for word $words[1..-1] {
        if (str:has-prefix $word '-') {
            break
        }
        set command = $command';'$word
    }
    var completions = [
        &'ph'= {
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand adapter 'Start the handler in adapter mode'
            cand node 'Start the handler in node mode'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'ph;adapter'= {
            cand -c 'Path to adapter configuration file (any options specified on command line will override configuration file)'
            cand --config-file 'Path to adapter configuration file (any options specified on command line will override configuration file)'
            cand --control-path 'Unix domain socket path for the "control" interface'
            cand -a 'For a node this is listen substrate address for dock, for adapter it is best to leave this at its default setting (0.0.0.0:0)'
            cand --self-addr 'For a node this is listen substrate address for dock, for adapter it is best to leave this at its default setting (0.0.0.0:0)'
            cand --ca-file 'Certificate of the Certificate Authority'
            cand --certificate-file 'Certificate including the noise public key, signed by the authority'
            cand -k 'Path to the noise private key file (PEM format)'
            cand --private-key-file 'Path to the noise private key file (PEM format)'
            cand -K 'Base64 encoded noise private key (alternative to specifying a PEM encoded private-key-file)'
            cand --noise-private-key 'Base64 encoded noise private key (alternative to specifying a PEM encoded private-key-file)'
            cand -i 'TUN device to use, eg "tun1" (leave blank for automatic selection -- the default)'
            cand --tun-if 'TUN device to use, eg "tun1" (leave blank for automatic selection -- the default)'
            cand -z 'ZPR address (no port) of the adapter (must match your TUN address if it has one)'
            cand --zpr-addr 'ZPR address (no port) of the adapter (must match your TUN address if it has one)'
            cand -l 'Set log level using key value pairs: <target>=<LEVEL> The options for targets are:     all, capture, datapath, flow_mgmt, link_state,     mgmt_events, net_os, peer_mgmt, reporting, rpc,     startup, visa_mgmt, zdp The options for levels are:     OFF, ERROR, WARN, INFO, DEBUG, TRACE You can include as many key-value pairs as you want. If you do multiple pairs with the same key, the last last pair will be the one considered. If you include a pair with the target all, you can still set the level for individual targets --logging zdp=TRACE link_state=TRACE all=DEBUG would set all the targets to the DEBUG level, except zdp and link_state, which would be set to TRACE'
            cand --logging 'Set log level using key value pairs: <target>=<LEVEL> The options for targets are:     all, capture, datapath, flow_mgmt, link_state,     mgmt_events, net_os, peer_mgmt, reporting, rpc,     startup, visa_mgmt, zdp The options for levels are:     OFF, ERROR, WARN, INFO, DEBUG, TRACE You can include as many key-value pairs as you want. If you do multiple pairs with the same key, the last last pair will be the one considered. If you include a pair with the target all, you can still set the level for individual targets --logging zdp=TRACE link_state=TRACE all=DEBUG would set all the targets to the DEBUG level, except zdp and link_state, which would be set to TRACE'
            cand --io-engine 'Which packet I/O engine to use'
            cand -g 'g'
            cand --generate 'generate'
            cand -N 'Substrate address of the node to connect to'
            cand --node-addr 'Substrate address of the node to connect to'
            cand -b 'PEM file holding the nodes noise public key'
            cand --node-public-key-file 'PEM file holding the nodes noise public key'
            cand --bootstrap-key 'PEM file holding the boostrap RSA private key'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'ph;node'= {
            cand -c 'Path to node configuration file (any options specified on command line will override configuration file)'
            cand --config-file 'Path to node configuration file (any options specified on command line will override configuration file)'
            cand --control-path 'Unix domain socket path for the "control" interface'
            cand -a 'For a node this is listen substrate address for dock, for adapter it is best to leave this at its default setting (0.0.0.0:0)'
            cand --self-addr 'For a node this is listen substrate address for dock, for adapter it is best to leave this at its default setting (0.0.0.0:0)'
            cand --ca-file 'Certificate of the Certificate Authority'
            cand --certificate-file 'Certificate including the noise public key, signed by the authority'
            cand -k 'Path to the noise private key file (PEM format)'
            cand --private-key-file 'Path to the noise private key file (PEM format)'
            cand -K 'Base64 encoded noise private key (alternative to specifying a PEM encoded private-key-file)'
            cand --noise-private-key 'Base64 encoded noise private key (alternative to specifying a PEM encoded private-key-file)'
            cand -i 'TUN device to use, eg "tun1" (leave blank for automatic selection -- the default)'
            cand --tun-if 'TUN device to use, eg "tun1" (leave blank for automatic selection -- the default)'
            cand -z 'ZPR address (no port) of the adapter (must match your TUN address if it has one)'
            cand --zpr-addr 'ZPR address (no port) of the adapter (must match your TUN address if it has one)'
            cand -l 'Set log level using key value pairs: <target>=<LEVEL> The options for targets are:     all, capture, datapath, flow_mgmt, link_state,     mgmt_events, net_os, peer_mgmt, reporting, rpc,     startup, visa_mgmt, zdp The options for levels are:     OFF, ERROR, WARN, INFO, DEBUG, TRACE You can include as many key-value pairs as you want. If you do multiple pairs with the same key, the last last pair will be the one considered. If you include a pair with the target all, you can still set the level for individual targets --logging zdp=TRACE link_state=TRACE all=DEBUG would set all the targets to the DEBUG level, except zdp and link_state, which would be set to TRACE'
            cand --logging 'Set log level using key value pairs: <target>=<LEVEL> The options for targets are:     all, capture, datapath, flow_mgmt, link_state,     mgmt_events, net_os, peer_mgmt, reporting, rpc,     startup, visa_mgmt, zdp The options for levels are:     OFF, ERROR, WARN, INFO, DEBUG, TRACE You can include as many key-value pairs as you want. If you do multiple pairs with the same key, the last last pair will be the one considered. If you include a pair with the target all, you can still set the level for individual targets --logging zdp=TRACE link_state=TRACE all=DEBUG would set all the targets to the DEBUG level, except zdp and link_state, which would be set to TRACE'
            cand --io-engine 'Which packet I/O engine to use'
            cand -g 'g'
            cand --generate 'generate'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'ph;help'= {
            cand adapter 'Start the handler in adapter mode'
            cand node 'Start the handler in node mode'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'ph;help;adapter'= {
        }
        &'ph;help;node'= {
        }
        &'ph;help;help'= {
        }
    ]
    $completions[$command]
}
