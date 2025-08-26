
use builtin;
use str;

set edit:completion:arg-completer[ph-cli] = {|@words|
    fn spaces {|n|
        builtin:repeat $n ' ' | str:join ''
    }
    fn cand {|text desc|
        edit:complex-candidate $text &display=$text' '(spaces (- 14 (wcswidth $text)))$desc
    }
    var command = 'ph-cli'
    for word $words[1..-1] {
        if (str:has-prefix $word '-') {
            break
        }
        set command = $command';'$word
    }
    var completions = [
        &'ph-cli'= {
            cand -p 'Path to the Packet Handler''s management socket'
            cand --socket 'Path to the Packet Handler''s management socket'
            cand -g 'g'
            cand --generate 'generate'
            cand -h 'Print help'
            cand --help 'Print help'
            cand -V 'Print version'
            cand --version 'Print version'
            cand echo 'echo'
            cand counters 'Display or reset counters'
            cand watch 'Connect to the Packet Handler for periodic counter updates'
            cand perf-sample 'Start performance sampling (currently not functional)'
            cand capture 'Set up or tear down packet captures'
            cand link 'Change link state'
            cand logging 'Change the log level of a node or adapter'
            cand quit 'Exit the CLI'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'ph-cli;echo'= {
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'ph-cli;counters'= {
            cand -r 'Reset counters'
            cand --reset 'Reset counters'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'ph-cli;watch'= {
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'ph-cli;perf-sample'= {
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'ph-cli;capture'= {
            cand -h 'Print help'
            cand --help 'Print help'
            cand set-file 'Set a capture file'
            cand close-file 'Close a capture file'
            cand set-program 'Set a BPF to filter captured packets'
            cand delete-program 'Delete any set BPF'
            cand flush-file 'Flush any outstanding packets to the capture file'
            cand sequence 'Create a temporary packet capture'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'ph-cli;capture;set-file'= {
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'ph-cli;capture;close-file'= {
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'ph-cli;capture;set-program'= {
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'ph-cli;capture;delete-program'= {
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'ph-cli;capture;flush-file'= {
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'ph-cli;capture;sequence'= {
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'ph-cli;capture;help'= {
            cand set-file 'Set a capture file'
            cand close-file 'Close a capture file'
            cand set-program 'Set a BPF to filter captured packets'
            cand delete-program 'Delete any set BPF'
            cand flush-file 'Flush any outstanding packets to the capture file'
            cand sequence 'Create a temporary packet capture'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'ph-cli;capture;help;set-file'= {
        }
        &'ph-cli;capture;help;close-file'= {
        }
        &'ph-cli;capture;help;set-program'= {
        }
        &'ph-cli;capture;help;delete-program'= {
        }
        &'ph-cli;capture;help;flush-file'= {
        }
        &'ph-cli;capture;help;sequence'= {
        }
        &'ph-cli;capture;help;help'= {
        }
        &'ph-cli;link'= {
            cand -h 'Print help'
            cand --help 'Print help'
            cand show 'Show a link''s status'
            cand configure 'Configure a link'
            cand start 'Start a link'
            cand stop 'Stop a link'
            cand reset 'Reset a link.  It will require a configure before starting again'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'ph-cli;link;show'= {
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'ph-cli;link;configure'= {
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'ph-cli;link;start'= {
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'ph-cli;link;stop'= {
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'ph-cli;link;reset'= {
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'ph-cli;link;help'= {
            cand show 'Show a link''s status'
            cand configure 'Configure a link'
            cand start 'Start a link'
            cand stop 'Stop a link'
            cand reset 'Reset a link.  It will require a configure before starting again'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'ph-cli;link;help;show'= {
        }
        &'ph-cli;link;help;configure'= {
        }
        &'ph-cli;link;help;start'= {
        }
        &'ph-cli;link;help;stop'= {
        }
        &'ph-cli;link;help;reset'= {
        }
        &'ph-cli;link;help;help'= {
        }
        &'ph-cli;logging'= {
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'ph-cli;quit'= {
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'ph-cli;help'= {
            cand echo 'echo'
            cand counters 'Display or reset counters'
            cand watch 'Connect to the Packet Handler for periodic counter updates'
            cand perf-sample 'Start performance sampling (currently not functional)'
            cand capture 'Set up or tear down packet captures'
            cand link 'Change link state'
            cand logging 'Change the log level of a node or adapter'
            cand quit 'Exit the CLI'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'ph-cli;help;echo'= {
        }
        &'ph-cli;help;counters'= {
        }
        &'ph-cli;help;watch'= {
        }
        &'ph-cli;help;perf-sample'= {
        }
        &'ph-cli;help;capture'= {
            cand set-file 'Set a capture file'
            cand close-file 'Close a capture file'
            cand set-program 'Set a BPF to filter captured packets'
            cand delete-program 'Delete any set BPF'
            cand flush-file 'Flush any outstanding packets to the capture file'
            cand sequence 'Create a temporary packet capture'
        }
        &'ph-cli;help;capture;set-file'= {
        }
        &'ph-cli;help;capture;close-file'= {
        }
        &'ph-cli;help;capture;set-program'= {
        }
        &'ph-cli;help;capture;delete-program'= {
        }
        &'ph-cli;help;capture;flush-file'= {
        }
        &'ph-cli;help;capture;sequence'= {
        }
        &'ph-cli;help;link'= {
            cand show 'Show a link''s status'
            cand configure 'Configure a link'
            cand start 'Start a link'
            cand stop 'Stop a link'
            cand reset 'Reset a link.  It will require a configure before starting again'
        }
        &'ph-cli;help;link;show'= {
        }
        &'ph-cli;help;link;configure'= {
        }
        &'ph-cli;help;link;start'= {
        }
        &'ph-cli;help;link;stop'= {
        }
        &'ph-cli;help;link;reset'= {
        }
        &'ph-cli;help;logging'= {
        }
        &'ph-cli;help;quit'= {
        }
        &'ph-cli;help;help'= {
        }
    ]
    $completions[$command]
}
