
using namespace System.Management.Automation
using namespace System.Management.Automation.Language

Register-ArgumentCompleter -Native -CommandName 'ph-cli' -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $commandElements = $commandAst.CommandElements
    $command = @(
        'ph-cli'
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
        'ph-cli' {
            [CompletionResult]::new('-p', '-p', [CompletionResultType]::ParameterName, 'Path to the Packet Handler''s management socket')
            [CompletionResult]::new('--socket', '--socket', [CompletionResultType]::ParameterName, 'Path to the Packet Handler''s management socket')
            [CompletionResult]::new('-g', '-g', [CompletionResultType]::ParameterName, 'g')
            [CompletionResult]::new('--generate', '--generate', [CompletionResultType]::ParameterName, 'generate')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('echo', 'echo', [CompletionResultType]::ParameterValue, 'echo')
            [CompletionResult]::new('counters', 'counters', [CompletionResultType]::ParameterValue, 'Display or reset counters')
            [CompletionResult]::new('watch', 'watch', [CompletionResultType]::ParameterValue, 'Connect to the Packet Handler for periodic counter updates')
            [CompletionResult]::new('perf-sample', 'perf-sample', [CompletionResultType]::ParameterValue, 'Start performance sampling (currently not functional)')
            [CompletionResult]::new('capture', 'capture', [CompletionResultType]::ParameterValue, 'Set up or tear down packet captures')
            [CompletionResult]::new('link', 'link', [CompletionResultType]::ParameterValue, 'Change link state')
            [CompletionResult]::new('logging', 'logging', [CompletionResultType]::ParameterValue, 'Change the log level of a node or adapter')
            [CompletionResult]::new('quit', 'quit', [CompletionResultType]::ParameterValue, 'Exit the CLI')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'ph-cli;echo' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'ph-cli;counters' {
            [CompletionResult]::new('-r', '-r', [CompletionResultType]::ParameterName, 'Reset counters')
            [CompletionResult]::new('--reset', '--reset', [CompletionResultType]::ParameterName, 'Reset counters')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'ph-cli;watch' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'ph-cli;perf-sample' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'ph-cli;capture' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('set-file', 'set-file', [CompletionResultType]::ParameterValue, 'Set a capture file')
            [CompletionResult]::new('close-file', 'close-file', [CompletionResultType]::ParameterValue, 'Close a capture file')
            [CompletionResult]::new('set-program', 'set-program', [CompletionResultType]::ParameterValue, 'Set a BPF to filter captured packets')
            [CompletionResult]::new('delete-program', 'delete-program', [CompletionResultType]::ParameterValue, 'Delete any set BPF')
            [CompletionResult]::new('flush-file', 'flush-file', [CompletionResultType]::ParameterValue, 'Flush any outstanding packets to the capture file')
            [CompletionResult]::new('sequence', 'sequence', [CompletionResultType]::ParameterValue, 'Create a temporary packet capture')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'ph-cli;capture;set-file' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'ph-cli;capture;close-file' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'ph-cli;capture;set-program' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'ph-cli;capture;delete-program' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'ph-cli;capture;flush-file' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'ph-cli;capture;sequence' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'ph-cli;capture;help' {
            [CompletionResult]::new('set-file', 'set-file', [CompletionResultType]::ParameterValue, 'Set a capture file')
            [CompletionResult]::new('close-file', 'close-file', [CompletionResultType]::ParameterValue, 'Close a capture file')
            [CompletionResult]::new('set-program', 'set-program', [CompletionResultType]::ParameterValue, 'Set a BPF to filter captured packets')
            [CompletionResult]::new('delete-program', 'delete-program', [CompletionResultType]::ParameterValue, 'Delete any set BPF')
            [CompletionResult]::new('flush-file', 'flush-file', [CompletionResultType]::ParameterValue, 'Flush any outstanding packets to the capture file')
            [CompletionResult]::new('sequence', 'sequence', [CompletionResultType]::ParameterValue, 'Create a temporary packet capture')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'ph-cli;capture;help;set-file' {
            break
        }
        'ph-cli;capture;help;close-file' {
            break
        }
        'ph-cli;capture;help;set-program' {
            break
        }
        'ph-cli;capture;help;delete-program' {
            break
        }
        'ph-cli;capture;help;flush-file' {
            break
        }
        'ph-cli;capture;help;sequence' {
            break
        }
        'ph-cli;capture;help;help' {
            break
        }
        'ph-cli;link' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show a link''s status')
            [CompletionResult]::new('configure', 'configure', [CompletionResultType]::ParameterValue, 'Configure a link')
            [CompletionResult]::new('start', 'start', [CompletionResultType]::ParameterValue, 'Start a link')
            [CompletionResult]::new('stop', 'stop', [CompletionResultType]::ParameterValue, 'Stop a link')
            [CompletionResult]::new('reset', 'reset', [CompletionResultType]::ParameterValue, 'Reset a link.  It will require a configure before starting again')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'ph-cli;link;show' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'ph-cli;link;configure' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'ph-cli;link;start' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'ph-cli;link;stop' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'ph-cli;link;reset' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'ph-cli;link;help' {
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show a link''s status')
            [CompletionResult]::new('configure', 'configure', [CompletionResultType]::ParameterValue, 'Configure a link')
            [CompletionResult]::new('start', 'start', [CompletionResultType]::ParameterValue, 'Start a link')
            [CompletionResult]::new('stop', 'stop', [CompletionResultType]::ParameterValue, 'Stop a link')
            [CompletionResult]::new('reset', 'reset', [CompletionResultType]::ParameterValue, 'Reset a link.  It will require a configure before starting again')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'ph-cli;link;help;show' {
            break
        }
        'ph-cli;link;help;configure' {
            break
        }
        'ph-cli;link;help;start' {
            break
        }
        'ph-cli;link;help;stop' {
            break
        }
        'ph-cli;link;help;reset' {
            break
        }
        'ph-cli;link;help;help' {
            break
        }
        'ph-cli;logging' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'ph-cli;quit' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'ph-cli;help' {
            [CompletionResult]::new('echo', 'echo', [CompletionResultType]::ParameterValue, 'echo')
            [CompletionResult]::new('counters', 'counters', [CompletionResultType]::ParameterValue, 'Display or reset counters')
            [CompletionResult]::new('watch', 'watch', [CompletionResultType]::ParameterValue, 'Connect to the Packet Handler for periodic counter updates')
            [CompletionResult]::new('perf-sample', 'perf-sample', [CompletionResultType]::ParameterValue, 'Start performance sampling (currently not functional)')
            [CompletionResult]::new('capture', 'capture', [CompletionResultType]::ParameterValue, 'Set up or tear down packet captures')
            [CompletionResult]::new('link', 'link', [CompletionResultType]::ParameterValue, 'Change link state')
            [CompletionResult]::new('logging', 'logging', [CompletionResultType]::ParameterValue, 'Change the log level of a node or adapter')
            [CompletionResult]::new('quit', 'quit', [CompletionResultType]::ParameterValue, 'Exit the CLI')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'ph-cli;help;echo' {
            break
        }
        'ph-cli;help;counters' {
            break
        }
        'ph-cli;help;watch' {
            break
        }
        'ph-cli;help;perf-sample' {
            break
        }
        'ph-cli;help;capture' {
            [CompletionResult]::new('set-file', 'set-file', [CompletionResultType]::ParameterValue, 'Set a capture file')
            [CompletionResult]::new('close-file', 'close-file', [CompletionResultType]::ParameterValue, 'Close a capture file')
            [CompletionResult]::new('set-program', 'set-program', [CompletionResultType]::ParameterValue, 'Set a BPF to filter captured packets')
            [CompletionResult]::new('delete-program', 'delete-program', [CompletionResultType]::ParameterValue, 'Delete any set BPF')
            [CompletionResult]::new('flush-file', 'flush-file', [CompletionResultType]::ParameterValue, 'Flush any outstanding packets to the capture file')
            [CompletionResult]::new('sequence', 'sequence', [CompletionResultType]::ParameterValue, 'Create a temporary packet capture')
            break
        }
        'ph-cli;help;capture;set-file' {
            break
        }
        'ph-cli;help;capture;close-file' {
            break
        }
        'ph-cli;help;capture;set-program' {
            break
        }
        'ph-cli;help;capture;delete-program' {
            break
        }
        'ph-cli;help;capture;flush-file' {
            break
        }
        'ph-cli;help;capture;sequence' {
            break
        }
        'ph-cli;help;link' {
            [CompletionResult]::new('show', 'show', [CompletionResultType]::ParameterValue, 'Show a link''s status')
            [CompletionResult]::new('configure', 'configure', [CompletionResultType]::ParameterValue, 'Configure a link')
            [CompletionResult]::new('start', 'start', [CompletionResultType]::ParameterValue, 'Start a link')
            [CompletionResult]::new('stop', 'stop', [CompletionResultType]::ParameterValue, 'Stop a link')
            [CompletionResult]::new('reset', 'reset', [CompletionResultType]::ParameterValue, 'Reset a link.  It will require a configure before starting again')
            break
        }
        'ph-cli;help;link;show' {
            break
        }
        'ph-cli;help;link;configure' {
            break
        }
        'ph-cli;help;link;start' {
            break
        }
        'ph-cli;help;link;stop' {
            break
        }
        'ph-cli;help;link;reset' {
            break
        }
        'ph-cli;help;logging' {
            break
        }
        'ph-cli;help;quit' {
            break
        }
        'ph-cli;help;help' {
            break
        }
    })

    $completions.Where{ $_.CompletionText -like "$wordToComplete*" } |
        Sort-Object -Property ListItemText
}
