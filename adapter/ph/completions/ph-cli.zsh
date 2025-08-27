#compdef ph

autoload -U is-at-least

_ph() {
    typeset -A opt_args
    typeset -a _arguments_options
    local ret=1

    if is-at-least 5.2; then
        _arguments_options=(-s -S -C)
    else
        _arguments_options=(-s -C)
    fi

    local context curcontext="$curcontext" state line
    _arguments "${_arguments_options[@]}" : \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'-V[Print version]' \
'--version[Print version]' \
":: :_ph_commands" \
"*::: :->ph" \
&& ret=0
    case $state in
    (ph)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:ph-command-$line[1]:"
        case $line[1] in
            (adapter)
_arguments "${_arguments_options[@]}" : \
'-c+[Path to adapter configuration file (any options specified on command line will override configuration file)]:PATH:_files' \
'--config-file=[Path to adapter configuration file (any options specified on command line will override configuration file)]:PATH:_files' \
'--control-path=[Unix domain socket path for the "control" interface]:DOMAIN_SOCKET_PATH:_default' \
'-a+[For a node this is listen substrate address for dock, for adapter it is best to leave this at its default setting (0.0.0.0\:0)]:ADDR:PORT:_default' \
'--self-addr=[For a node this is listen substrate address for dock, for adapter it is best to leave this at its default setting (0.0.0.0\:0)]:ADDR:PORT:_default' \
'--ca-file=[Certificate of the Certificate Authority]:PATH:_default' \
'--certificate-file=[Certificate including the noise public key, signed by the authority]:PATH:_default' \
'-k+[Path to the noise private key file (PEM format)]:PATH:_default' \
'--private-key-file=[Path to the noise private key file (PEM format)]:PATH:_default' \
'-K+[Base64 encoded noise private key (alternative to specifying a PEM encoded private-key-file)]:NOISE_KEY:_default' \
'--noise-private-key=[Base64 encoded noise private key (alternative to specifying a PEM encoded private-key-file)]:NOISE_KEY:_default' \
'-i+[TUN device to use, eg "tun1" (leave blank for automatic selection -- the default)]:DEVICE:_default' \
'--tun-if=[TUN device to use, eg "tun1" (leave blank for automatic selection -- the default)]:DEVICE:_default' \
'*-z+[ZPR address (no port) of the adapter (must match your TUN address if it has one)]:ZPR_ADDR:_default' \
'*--zpr-addr=[ZPR address (no port) of the adapter (must match your TUN address if it has one)]:ZPR_ADDR:_default' \
'*-l+[Set log level using key value pairs\: <target>=<LEVEL> The options for targets are\:     all, capture, datapath, flow_mgmt, link_state,     mgmt_events, net_os, peer_mgmt, reporting, rpc,     startup, visa_mgmt, zdp The options for levels are\:     OFF, ERROR, WARN, INFO, DEBUG, TRACE You can include as many key-value pairs as you want. If you do multiple pairs with the same key, the last last pair will be the one considered. If you include a pair with the target all, you can still set the level for individual targets --logging zdp=TRACE link_state=TRACE all=DEBUG would set all the targets to the DEBUG level, except zdp and link_state, which would be set to TRACE]:LOGGING:_default' \
'*--logging=[Set log level using key value pairs\: <target>=<LEVEL> The options for targets are\:     all, capture, datapath, flow_mgmt, link_state,     mgmt_events, net_os, peer_mgmt, reporting, rpc,     startup, visa_mgmt, zdp The options for levels are\:     OFF, ERROR, WARN, INFO, DEBUG, TRACE You can include as many key-value pairs as you want. If you do multiple pairs with the same key, the last last pair will be the one considered. If you include a pair with the target all, you can still set the level for individual targets --logging zdp=TRACE link_state=TRACE all=DEBUG would set all the targets to the DEBUG level, except zdp and link_state, which would be set to TRACE]:LOGGING:_default' \
'--io-engine=[Which packet I/O engine to use]:IO_ENGINE:(auto io_uring posix_unbatched)' \
'-g+[]:GENERATE:_default' \
'--generate=[]:GENERATE:_default' \
'-N+[Substrate address of the node to connect to]:ADDR:PORT:_default' \
'--node-addr=[Substrate address of the node to connect to]:ADDR:PORT:_default' \
'-b+[PEM file holding the nodes noise public key]:PATH:_files' \
'--node-public-key-file=[PEM file holding the nodes noise public key]:PATH:_files' \
'--bootstrap-key=[PEM file holding the boostrap RSA private key]:PATH:_files' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(node)
_arguments "${_arguments_options[@]}" : \
'-c+[Path to node configuration file (any options specified on command line will override configuration file)]:PATH:_files' \
'--config-file=[Path to node configuration file (any options specified on command line will override configuration file)]:PATH:_files' \
'--control-path=[Unix domain socket path for the "control" interface]:DOMAIN_SOCKET_PATH:_default' \
'-a+[For a node this is listen substrate address for dock, for adapter it is best to leave this at its default setting (0.0.0.0\:0)]:ADDR:PORT:_default' \
'--self-addr=[For a node this is listen substrate address for dock, for adapter it is best to leave this at its default setting (0.0.0.0\:0)]:ADDR:PORT:_default' \
'--ca-file=[Certificate of the Certificate Authority]:PATH:_default' \
'--certificate-file=[Certificate including the noise public key, signed by the authority]:PATH:_default' \
'-k+[Path to the noise private key file (PEM format)]:PATH:_default' \
'--private-key-file=[Path to the noise private key file (PEM format)]:PATH:_default' \
'-K+[Base64 encoded noise private key (alternative to specifying a PEM encoded private-key-file)]:NOISE_KEY:_default' \
'--noise-private-key=[Base64 encoded noise private key (alternative to specifying a PEM encoded private-key-file)]:NOISE_KEY:_default' \
'-i+[TUN device to use, eg "tun1" (leave blank for automatic selection -- the default)]:DEVICE:_default' \
'--tun-if=[TUN device to use, eg "tun1" (leave blank for automatic selection -- the default)]:DEVICE:_default' \
'*-z+[ZPR address (no port) of the adapter (must match your TUN address if it has one)]:ZPR_ADDR:_default' \
'*--zpr-addr=[ZPR address (no port) of the adapter (must match your TUN address if it has one)]:ZPR_ADDR:_default' \
'*-l+[Set log level using key value pairs\: <target>=<LEVEL> The options for targets are\:     all, capture, datapath, flow_mgmt, link_state,     mgmt_events, net_os, peer_mgmt, reporting, rpc,     startup, visa_mgmt, zdp The options for levels are\:     OFF, ERROR, WARN, INFO, DEBUG, TRACE You can include as many key-value pairs as you want. If you do multiple pairs with the same key, the last last pair will be the one considered. If you include a pair with the target all, you can still set the level for individual targets --logging zdp=TRACE link_state=TRACE all=DEBUG would set all the targets to the DEBUG level, except zdp and link_state, which would be set to TRACE]:LOGGING:_default' \
'*--logging=[Set log level using key value pairs\: <target>=<LEVEL> The options for targets are\:     all, capture, datapath, flow_mgmt, link_state,     mgmt_events, net_os, peer_mgmt, reporting, rpc,     startup, visa_mgmt, zdp The options for levels are\:     OFF, ERROR, WARN, INFO, DEBUG, TRACE You can include as many key-value pairs as you want. If you do multiple pairs with the same key, the last last pair will be the one considered. If you include a pair with the target all, you can still set the level for individual targets --logging zdp=TRACE link_state=TRACE all=DEBUG would set all the targets to the DEBUG level, except zdp and link_state, which would be set to TRACE]:LOGGING:_default' \
'--io-engine=[Which packet I/O engine to use]:IO_ENGINE:(auto io_uring posix_unbatched)' \
'-g+[]:GENERATE:_default' \
'--generate=[]:GENERATE:_default' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_ph__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:ph-help-command-$line[1]:"
        case $line[1] in
            (adapter)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(node)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
}

(( $+functions[_ph_commands] )) ||
_ph_commands() {
    local commands; commands=(
'adapter:Start the handler in adapter mode' \
'node:Start the handler in node mode' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'ph commands' commands "$@"
}
(( $+functions[_ph__adapter_commands] )) ||
_ph__adapter_commands() {
    local commands; commands=()
    _describe -t commands 'ph adapter commands' commands "$@"
}
(( $+functions[_ph__help_commands] )) ||
_ph__help_commands() {
    local commands; commands=(
'adapter:Start the handler in adapter mode' \
'node:Start the handler in node mode' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'ph help commands' commands "$@"
}
(( $+functions[_ph__help__adapter_commands] )) ||
_ph__help__adapter_commands() {
    local commands; commands=()
    _describe -t commands 'ph help adapter commands' commands "$@"
}
(( $+functions[_ph__help__help_commands] )) ||
_ph__help__help_commands() {
    local commands; commands=()
    _describe -t commands 'ph help help commands' commands "$@"
}
(( $+functions[_ph__help__node_commands] )) ||
_ph__help__node_commands() {
    local commands; commands=()
    _describe -t commands 'ph help node commands' commands "$@"
}
(( $+functions[_ph__node_commands] )) ||
_ph__node_commands() {
    local commands; commands=()
    _describe -t commands 'ph node commands' commands "$@"
}

if [ "$funcstack[1]" = "_ph" ]; then
    _ph "$@"
else
    compdef _ph ph
fi
