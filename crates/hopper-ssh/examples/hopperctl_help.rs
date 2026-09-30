use hopper_ssh::{HopperCtlHelpCommand, read_hopperctl_help};
use std::time::Duration;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 5 {
        eprintln!("Usage:");
        eprintln!(
            "cargo run -p hopper-ssh --example hopperctl_help -- \
             <IP> <PORT> <USER> <FINGERPRINT>"
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

    let password = match rpassword::prompt_password("SSH password: ") {
        Ok(password) => password,

        Err(error) => {
            eprintln!("Could not read password: {error}");
            std::process::exit(1);
        }
    };

    println!();
    println!("Reading hopperctl help...");
    println!("No Hopper command will be started.");
    println!("No files will be modified.");
    println!();

    match read_hopperctl_help(
        host,
        port,
        user,
        &password,
        fingerprint,
        HopperCtlHelpCommand::Start,
        Duration::from_secs(10),
    )
    .await
    {
        Ok(help) => {
            println!("=== STDOUT ===");
            println!("{}", help.stdout);

            if !help.stderr.trim().is_empty() {
                println!();
                println!("=== STDERR ===");
                println!("{}", help.stderr);
            }

            println!();
            println!("Exit status: {:?}", help.exit_status);

            println!("No files were modified.");
        }

        Err(error) => {
            eprintln!("Could not read hopperctl help:");
            eprintln!("{error}");

            std::process::exit(1);
        }
    }
}
