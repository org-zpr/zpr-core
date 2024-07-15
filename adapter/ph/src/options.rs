#[derive(Copy, Clone, Default, clap::ValueEnum, PartialEq)]
pub enum PhMode {
    #[default]
    Client,
    Server,
}
