use clap::Parser;
use std::env;
use std::error::Error;
use std::fs::{read, File};
use std::io::Write;
use std::path::absolute;
use std::path::PathBuf;
use std::time::Instant;

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

    let mut output_path= output_directory.join("excavated.zip");
    output_path= absolute(output_path)?;

    let binary_data = read(args.input).expect("[!] Failed to open input file");

    let timer = Instant::now();

    let zip = deno_dig_lib::process_binary_file(binary_data)
        .await
        .unwrap();

    println!("======================================================");
    println!("✓ Digging took : {:.2}s", timer.elapsed().as_secs_f64());

    let mut file = File::create(output_path).expect("[!] Failed to create file");
    file.write_all(&zip).expect("[!] Failed to write to file");

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
