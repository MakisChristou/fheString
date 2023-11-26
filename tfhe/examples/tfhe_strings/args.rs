use clap::Parser;

/// A FHE string implementation using tfhe-rs
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// The string to do the processing on
    #[arg(short, long)]
    pub string: String,

    /// The pattern for the algoritmhs that need it
    #[arg(short, long)]
    pub pattern: String,

    /// The number of times to make an operation for the algoritmhs that need it
    #[arg(short, long)]
    pub n: usize,

    /// What will be replaced (for replace algorithms)
    #[arg(short, long)]
    pub from: String,

    /// What will replace it (for replace algorithms)
    #[arg(short, long)]
    pub to: String,
}
