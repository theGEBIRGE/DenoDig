use clap::Parser;
use std::error::Error;
use std::fs::create_dir_all;
use std::path::PathBuf;
use std::path::absolute;
use std::env;

#[derive(Parser, Debug)]
#[command(
    name = "Deno Dig",
    version = "1.1.0",
    author = "Frederic Linn",
    about = "A tool for excavating application code and npm packages from stand-alone Deno binaries "
)]
struct Cli {
    /// Input file path (required)
    #[arg(short, long)]
    input: PathBuf,

    /// Output directory (optional, defaults to the current working directory)
    #[arg(short, long)]
    output_directory: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    print_logo();

    // Get the output path: use the provided one, or fallback to the current working directory.
    let mut output_directory = args.output_directory.unwrap_or_else(|| {
        env::current_dir().expect("[!] Failed to get the current executable path")
    });

    output_directory = output_directory.join("excavated");
    output_directory = absolute(output_directory)?;
    create_dir_all(&output_directory).expect("[!] Failed to create output directory");


    deno_dig_lib::process_binary_file(&args.input, &output_directory).await?;

    Ok(())
}

fn print_logo() {
    let logo = r#"
                    ██████████████████████████████████░█ ███████████
            ██████████             ██████████████████ █████ ███░████
          ██████                       █████████████▒████▒███████▒████
        ██ ░                     █       █████████░█████████████████▒███
       █                      ██  ██      ██████████████████████████ ████
                              ███████      ███████▒██████████████████████▒
     ░                         █████        ███████████████████████████████
    █                             ░          ████▒██████████████████████████
    ░                                        ░██████████████████████████████
                                              ▒█████████████████████████████
    █                                          █████████████████████████████
    █████████████████   ░░░░       ██████      ███████████ ░  ██████████████
    ████████████████████████████████           █████████░        ███████████
    █████▒█████████████████████ ░          ▒█▒ ████████░         ███████████
    ████  ███████████████               ▒███   ▒██████░███  ███ ▒████▒███▒██
    ███   █████████                   ████     ▒██████ ██░█ ████ ███████████
    ███░                         ░█▒ ███▒█ ▒    ██████ █░██▒     ███████▒███
      ███                  ▒       ██▒           ███████     ███     ███████
    ░ ██████             ░ ▒█ ░░ ██▒  █ ▒        ██████████████     ▒ ██████
      ██████████████████ ░  ░ ██▒█ █             ████████▒████▒   █ ████▒█▒
    █████████████████████████████ ▒               ██░ █ ▒ ███ ▒██ ▒       ██
    ████████████████████████████▒            ░█   ░█  ████  █ ░░░ ░█░ ▒█████
     ██ ▒██████████████████  ░ ▒            █      ▒█████████░▒█▒▒██ ██████
      █░  ░█████████████████              ▒         ██████████ █████ ▒▒░ ░
       ███▒▒████████████████ █   ░                  ███▒███████ █████████
        █████▒ ██████████▒▒░  ░               ░█▒▒█▒ ▒ ░     █████████▒
          █████▒▒███████                  ▒  ░ ▒▒ █░░          ░██▒ ▒▒
             ███████▒█▒█▒██▒██       ░█▒  ▒▒ ▒  ▒█░    ▒     ▒  ▒▒ █
                ▒██  ▒█ █▒█ ████  █▒ █ ▒█▒████▒ ▒▒▒█▒    ▒  ██▒
                  DENO DIG DENO DIG DENO DIG DENO DIG DENO DIG
    "#;
    println!("{}", logo);
}
