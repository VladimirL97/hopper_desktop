use hopper_ssh::{HopperSourceFile, read_hopper_source};
use std::time::Duration;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 6 {
        eprintln!("Usage:");
        eprintln!(
            "cargo run -p hopper-ssh --example hopper_source -- \
             <IP> <PORT> <USER> <FINGERPRINT> \
             <start|configure|status>"
        );

        std::process::exit(1);
    }

    let host = &args[1];

    let port = match args[2].parse::<u16>() {
        Ok(port) if port != 0 => port,

        _ => {
            eprintln!("Invalid SSH port.");
            std::process::exit(1);
        }
    };

    let user = &args[3];
    let fingerprint = &args[4];

    let source = match args[5].as_str() {
        "start" => HopperSourceFile::Start,
        "configure" => HopperSourceFile::Configure,
        "status" => HopperSourceFile::Status,

        other => {
            eprintln!("Unknown source file: {other}");
            eprintln!("Expected: start, configure, or status");

            std::process::exit(1);
        }
    };

    let password = match rpassword::prompt_password("SSH password: ") {
        Ok(password) => password,

        Err(error) => {
            eprintln!("Could not read password: {error}");

            std::process::exit(1);
        }
    };

    println!();
    println!("Reading Hopper source in read-only mode...");
    println!("No files will be modified.");
    println!();

    match read_hopper_source(
        host,
        port,
        user,
        &password,
        fingerprint,
        source,
        Duration::from_secs(10),
    )
    .await
    {
        Ok(source) => {
            println!("{}", source.content);
        }

        Err(error) => {
            eprintln!("Could not read Hopper source:");
            eprintln!("{error}");

            std::process::exit(1);
        }
    }
}
