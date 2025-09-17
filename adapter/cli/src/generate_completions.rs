mod main_args;

use clap::{CommandFactory, Parser};
use clap_complete::{generate, shells::Shell};
use std::fs::create_dir_all;
use std::fs::File;
use std::io::BufWriter;

#[derive(Parser, Debug)]
#[command(version, about = "This program creates the shell completion files for the CLI", long_about = None, override_usage = "cargo run --features complete --bin generate_completions -- --generate <PATH>")]
struct Args {
    // Path to the generations file you want to create
    #[arg(long, short = 'g')]
    generate: String,
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    generate_completion(args.generate)?;

    Ok(())
}

fn generate_completion(path: String) -> std::io::Result<()> {
    let shells_exts: Vec<(Shell, &str)> = Vec::from([
        (Shell::Bash, "sh"),
        (Shell::Elvish, "elv"),
        (Shell::Fish, "fish"),
        (Shell::PowerShell, "ps1"),
        (Shell::Zsh, "zsh"),
    ]);

    create_dir_all(&path)?;

    for (shell, extension) in shells_exts {
        let formatted_path = format!("{path}/ph-cli.{extension}");
        let file = File::create(formatted_path)?;
        let mut writer = BufWriter::new(file);
        generate(
            shell,
            &mut main_args::CmdlineArgs::command(),
            main_args::CmdlineArgs::command().get_name().to_string(),
            &mut writer,
        );
    }

    Ok(())
}
