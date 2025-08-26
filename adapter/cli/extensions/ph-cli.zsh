#compdef ph-cli

autoload -U is-at-least

_ph-cli() {
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
'-p+[Path to the Packet Handler'\''s management socket]:SOCKET:_default' \
'--socket=[Path to the Packet Handler'\''s management socket]:SOCKET:_default' \
'-g+[]:GENERATE:_default' \
'--generate=[]:GENERATE:_default' \
'-h[Print help]' \
'--help[Print help]' \
'-V[Print version]' \
'--version[Print version]' \
":: :_ph-cli_commands" \
"*::: :->ph-cli" \
&& ret=0
    case $state in
    (ph-cli)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:ph-cli-command-$line[1]:"
        case $line[1] in
            (echo)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(counters)
_arguments "${_arguments_options[@]}" : \
'-r[Reset counters]' \
'--reset[Reset counters]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(watch)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
':interval -- How frequently to receive updates:_default' \
&& ret=0
;;
(perf-sample)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
':duration -- How long the sampling should run:_default' \
':frequency -- How frequently packets should be injected:_default' \
&& ret=0
;;
(capture)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
":: :_ph-cli__capture_commands" \
"*::: :->capture" \
&& ret=0

    case $state in
    (capture)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:ph-cli-capture-command-$line[1]:"
        case $line[1] in
            (set-file)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
':file_path:_default' \
&& ret=0
;;
(close-file)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(set-program)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
'::program:_default' \
&& ret=0
;;
(delete-program)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(flush-file)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(sequence)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
':file_path:_default' \
':duration:_default' \
'::program:_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_ph-cli__capture__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:ph-cli-capture-help-command-$line[1]:"
        case $line[1] in
            (set-file)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(close-file)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(set-program)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(delete-program)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(flush-file)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(sequence)
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
;;
(link)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
":: :_ph-cli__link_commands" \
"*::: :->link" \
&& ret=0

    case $state in
    (link)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:ph-cli-link-command-$line[1]:"
        case $line[1] in
            (show)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
'::id:_default' \
&& ret=0
;;
(configure)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
':id:_default' \
&& ret=0
;;
(start)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
':id:_default' \
&& ret=0
;;
(stop)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
':id:_default' \
&& ret=0
;;
(reset)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
':id:_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_ph-cli__link__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:ph-cli-link-help-command-$line[1]:"
        case $line[1] in
            (show)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(configure)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(start)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(stop)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(reset)
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
;;
(logging)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
'*::logs:_default' \
&& ret=0
;;
(quit)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_ph-cli__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:ph-cli-help-command-$line[1]:"
        case $line[1] in
            (echo)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(counters)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(watch)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(perf-sample)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(capture)
_arguments "${_arguments_options[@]}" : \
":: :_ph-cli__help__capture_commands" \
"*::: :->capture" \
&& ret=0

    case $state in
    (capture)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:ph-cli-help-capture-command-$line[1]:"
        case $line[1] in
            (set-file)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(close-file)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(set-program)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(delete-program)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(flush-file)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(sequence)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(link)
_arguments "${_arguments_options[@]}" : \
":: :_ph-cli__help__link_commands" \
"*::: :->link" \
&& ret=0

    case $state in
    (link)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:ph-cli-help-link-command-$line[1]:"
        case $line[1] in
            (show)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(configure)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(start)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(stop)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(reset)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(logging)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(quit)
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

(( $+functions[_ph-cli_commands] )) ||
_ph-cli_commands() {
    local commands; commands=(
'echo:' \
'counters:Display or reset counters' \
'watch:Connect to the Packet Handler for periodic counter updates' \
'perf-sample:Start performance sampling (currently not functional)' \
'capture:Set up or tear down packet captures' \
'link:Change link state' \
'logging:Change the log level of a node or adapter' \
'quit:Exit the CLI' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'ph-cli commands' commands "$@"
}
(( $+functions[_ph-cli__capture_commands] )) ||
_ph-cli__capture_commands() {
    local commands; commands=(
'set-file:Set a capture file' \
'close-file:Close a capture file' \
'set-program:Set a BPF to filter captured packets' \
'delete-program:Delete any set BPF' \
'flush-file:Flush any outstanding packets to the capture file' \
'sequence:Create a temporary packet capture' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'ph-cli capture commands' commands "$@"
}
(( $+functions[_ph-cli__capture__close-file_commands] )) ||
_ph-cli__capture__close-file_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli capture close-file commands' commands "$@"
}
(( $+functions[_ph-cli__capture__delete-program_commands] )) ||
_ph-cli__capture__delete-program_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli capture delete-program commands' commands "$@"
}
(( $+functions[_ph-cli__capture__flush-file_commands] )) ||
_ph-cli__capture__flush-file_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli capture flush-file commands' commands "$@"
}
(( $+functions[_ph-cli__capture__help_commands] )) ||
_ph-cli__capture__help_commands() {
    local commands; commands=(
'set-file:Set a capture file' \
'close-file:Close a capture file' \
'set-program:Set a BPF to filter captured packets' \
'delete-program:Delete any set BPF' \
'flush-file:Flush any outstanding packets to the capture file' \
'sequence:Create a temporary packet capture' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'ph-cli capture help commands' commands "$@"
}
(( $+functions[_ph-cli__capture__help__close-file_commands] )) ||
_ph-cli__capture__help__close-file_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli capture help close-file commands' commands "$@"
}
(( $+functions[_ph-cli__capture__help__delete-program_commands] )) ||
_ph-cli__capture__help__delete-program_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli capture help delete-program commands' commands "$@"
}
(( $+functions[_ph-cli__capture__help__flush-file_commands] )) ||
_ph-cli__capture__help__flush-file_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli capture help flush-file commands' commands "$@"
}
(( $+functions[_ph-cli__capture__help__help_commands] )) ||
_ph-cli__capture__help__help_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli capture help help commands' commands "$@"
}
(( $+functions[_ph-cli__capture__help__sequence_commands] )) ||
_ph-cli__capture__help__sequence_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli capture help sequence commands' commands "$@"
}
(( $+functions[_ph-cli__capture__help__set-file_commands] )) ||
_ph-cli__capture__help__set-file_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli capture help set-file commands' commands "$@"
}
(( $+functions[_ph-cli__capture__help__set-program_commands] )) ||
_ph-cli__capture__help__set-program_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli capture help set-program commands' commands "$@"
}
(( $+functions[_ph-cli__capture__sequence_commands] )) ||
_ph-cli__capture__sequence_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli capture sequence commands' commands "$@"
}
(( $+functions[_ph-cli__capture__set-file_commands] )) ||
_ph-cli__capture__set-file_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli capture set-file commands' commands "$@"
}
(( $+functions[_ph-cli__capture__set-program_commands] )) ||
_ph-cli__capture__set-program_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli capture set-program commands' commands "$@"
}
(( $+functions[_ph-cli__counters_commands] )) ||
_ph-cli__counters_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli counters commands' commands "$@"
}
(( $+functions[_ph-cli__echo_commands] )) ||
_ph-cli__echo_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli echo commands' commands "$@"
}
(( $+functions[_ph-cli__help_commands] )) ||
_ph-cli__help_commands() {
    local commands; commands=(
'echo:' \
'counters:Display or reset counters' \
'watch:Connect to the Packet Handler for periodic counter updates' \
'perf-sample:Start performance sampling (currently not functional)' \
'capture:Set up or tear down packet captures' \
'link:Change link state' \
'logging:Change the log level of a node or adapter' \
'quit:Exit the CLI' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'ph-cli help commands' commands "$@"
}
(( $+functions[_ph-cli__help__capture_commands] )) ||
_ph-cli__help__capture_commands() {
    local commands; commands=(
'set-file:Set a capture file' \
'close-file:Close a capture file' \
'set-program:Set a BPF to filter captured packets' \
'delete-program:Delete any set BPF' \
'flush-file:Flush any outstanding packets to the capture file' \
'sequence:Create a temporary packet capture' \
    )
    _describe -t commands 'ph-cli help capture commands' commands "$@"
}
(( $+functions[_ph-cli__help__capture__close-file_commands] )) ||
_ph-cli__help__capture__close-file_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli help capture close-file commands' commands "$@"
}
(( $+functions[_ph-cli__help__capture__delete-program_commands] )) ||
_ph-cli__help__capture__delete-program_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli help capture delete-program commands' commands "$@"
}
(( $+functions[_ph-cli__help__capture__flush-file_commands] )) ||
_ph-cli__help__capture__flush-file_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli help capture flush-file commands' commands "$@"
}
(( $+functions[_ph-cli__help__capture__sequence_commands] )) ||
_ph-cli__help__capture__sequence_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli help capture sequence commands' commands "$@"
}
(( $+functions[_ph-cli__help__capture__set-file_commands] )) ||
_ph-cli__help__capture__set-file_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli help capture set-file commands' commands "$@"
}
(( $+functions[_ph-cli__help__capture__set-program_commands] )) ||
_ph-cli__help__capture__set-program_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli help capture set-program commands' commands "$@"
}
(( $+functions[_ph-cli__help__counters_commands] )) ||
_ph-cli__help__counters_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli help counters commands' commands "$@"
}
(( $+functions[_ph-cli__help__echo_commands] )) ||
_ph-cli__help__echo_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli help echo commands' commands "$@"
}
(( $+functions[_ph-cli__help__help_commands] )) ||
_ph-cli__help__help_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli help help commands' commands "$@"
}
(( $+functions[_ph-cli__help__link_commands] )) ||
_ph-cli__help__link_commands() {
    local commands; commands=(
'show:Show a link'\''s status' \
'configure:Configure a link' \
'start:Start a link' \
'stop:Stop a link' \
'reset:Reset a link.  It will require a configure before starting again' \
    )
    _describe -t commands 'ph-cli help link commands' commands "$@"
}
(( $+functions[_ph-cli__help__link__configure_commands] )) ||
_ph-cli__help__link__configure_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli help link configure commands' commands "$@"
}
(( $+functions[_ph-cli__help__link__reset_commands] )) ||
_ph-cli__help__link__reset_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli help link reset commands' commands "$@"
}
(( $+functions[_ph-cli__help__link__show_commands] )) ||
_ph-cli__help__link__show_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli help link show commands' commands "$@"
}
(( $+functions[_ph-cli__help__link__start_commands] )) ||
_ph-cli__help__link__start_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli help link start commands' commands "$@"
}
(( $+functions[_ph-cli__help__link__stop_commands] )) ||
_ph-cli__help__link__stop_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli help link stop commands' commands "$@"
}
(( $+functions[_ph-cli__help__logging_commands] )) ||
_ph-cli__help__logging_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli help logging commands' commands "$@"
}
(( $+functions[_ph-cli__help__perf-sample_commands] )) ||
_ph-cli__help__perf-sample_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli help perf-sample commands' commands "$@"
}
(( $+functions[_ph-cli__help__quit_commands] )) ||
_ph-cli__help__quit_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli help quit commands' commands "$@"
}
(( $+functions[_ph-cli__help__watch_commands] )) ||
_ph-cli__help__watch_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli help watch commands' commands "$@"
}
(( $+functions[_ph-cli__link_commands] )) ||
_ph-cli__link_commands() {
    local commands; commands=(
'show:Show a link'\''s status' \
'configure:Configure a link' \
'start:Start a link' \
'stop:Stop a link' \
'reset:Reset a link.  It will require a configure before starting again' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'ph-cli link commands' commands "$@"
}
(( $+functions[_ph-cli__link__configure_commands] )) ||
_ph-cli__link__configure_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli link configure commands' commands "$@"
}
(( $+functions[_ph-cli__link__help_commands] )) ||
_ph-cli__link__help_commands() {
    local commands; commands=(
'show:Show a link'\''s status' \
'configure:Configure a link' \
'start:Start a link' \
'stop:Stop a link' \
'reset:Reset a link.  It will require a configure before starting again' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'ph-cli link help commands' commands "$@"
}
(( $+functions[_ph-cli__link__help__configure_commands] )) ||
_ph-cli__link__help__configure_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli link help configure commands' commands "$@"
}
(( $+functions[_ph-cli__link__help__help_commands] )) ||
_ph-cli__link__help__help_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli link help help commands' commands "$@"
}
(( $+functions[_ph-cli__link__help__reset_commands] )) ||
_ph-cli__link__help__reset_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli link help reset commands' commands "$@"
}
(( $+functions[_ph-cli__link__help__show_commands] )) ||
_ph-cli__link__help__show_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli link help show commands' commands "$@"
}
(( $+functions[_ph-cli__link__help__start_commands] )) ||
_ph-cli__link__help__start_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli link help start commands' commands "$@"
}
(( $+functions[_ph-cli__link__help__stop_commands] )) ||
_ph-cli__link__help__stop_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli link help stop commands' commands "$@"
}
(( $+functions[_ph-cli__link__reset_commands] )) ||
_ph-cli__link__reset_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli link reset commands' commands "$@"
}
(( $+functions[_ph-cli__link__show_commands] )) ||
_ph-cli__link__show_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli link show commands' commands "$@"
}
(( $+functions[_ph-cli__link__start_commands] )) ||
_ph-cli__link__start_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli link start commands' commands "$@"
}
(( $+functions[_ph-cli__link__stop_commands] )) ||
_ph-cli__link__stop_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli link stop commands' commands "$@"
}
(( $+functions[_ph-cli__logging_commands] )) ||
_ph-cli__logging_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli logging commands' commands "$@"
}
(( $+functions[_ph-cli__perf-sample_commands] )) ||
_ph-cli__perf-sample_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli perf-sample commands' commands "$@"
}
(( $+functions[_ph-cli__quit_commands] )) ||
_ph-cli__quit_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli quit commands' commands "$@"
}
(( $+functions[_ph-cli__watch_commands] )) ||
_ph-cli__watch_commands() {
    local commands; commands=()
    _describe -t commands 'ph-cli watch commands' commands "$@"
}

if [ "$funcstack[1]" = "_ph-cli" ]; then
    _ph-cli "$@"
else
    compdef _ph-cli ph-cli
fi
