.PHONY: all
all: build

.PHONY: build
build:
	cargo build --verbose

.PHONY: release
release:
	cargo build -r

.PHONY: test
test:
	cargo test --verbose

.PHONY: clean
clean:
	cargo clean
	rm -r extensions

# Create the completion scripts for the CLI
TARGET_DIR = extensions

.PHONY: generate
generate:
	./target/debug/ph-cli --generate $(TARGET_DIR)
	
	@echo "\nInstallation of the completion script depends on your shell"
	@echo "\nBash: Source the file in your .bashrc or .bash_profile, or copy the file into one of the bash completions folders"
	@echo "\nZsh: There are several ways, including using oh-my-zsh, the zsh_completions package, or creating a symlink to your completions file in the ~/.local/share/zsh/site-functions/ then adding that to your fpath"
	@echo "\nElvish: 'Use' the file in ~/.config/elvish/rc.elv"
	@echo "\nFish: Copy the file into ~/.config/fish/completions/"
	@echo "\nPowerShell: Use 'Import-Module' to add the script to your user profile"


