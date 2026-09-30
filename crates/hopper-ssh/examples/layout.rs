use hopper_ssh::diagnose_hopper_layout;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 5 {
        eprintln!("Usage:");
        eprintln!(
            "cargo run -p hopper-ssh --example layout -- \
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
    println!("Reading Hopper server layout...");
    println!("No files will be modified.");
    println!();

    match diagnose_hopper_layout(
        host,
        port,
        user,
        &password,
        fingerprint,
        Duration::from_secs(10),
    )
    .await
    {
        Ok(diagnostic) => {
            println!("{}", diagnostic.output);
        }

        Err(error) => {
            eprintln!("Diagnostic failed:");
            eprintln!("{error}");

            std::process::exit(1);
        }
    }
}
