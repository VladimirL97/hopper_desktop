use hopper_ssh::probe_host_key;
use std::time::Duration;

#[tokio::main]
async fn main() {
    // Аргументы командной строки:
    //
    // cargo run -p hopper-ssh --example probe -- 1.2.3.4 22

    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("cargo run -p hopper-ssh --example probe -- <IP> [PORT]");

        std::process::exit(1);
    }

    let host = &args[1];

    let port = if args.len() >= 3 {
        match args[2].parse::<u16>() {
            Ok(port) if port != 0 => port,

            _ => {
                eprintln!("Invalid SSH port.");
                std::process::exit(1);
            }
        }
    } else {
        22
    };

    println!("Hopper SSH probe");
    println!();
    println!("Target: {host}:{port}");
    println!("Password will NOT be sent.");
    println!("No commands will be executed.");
    println!();

    match probe_host_key(host, port, Duration::from_secs(10)).await {
        Ok(host_key) => {
            println!("SSH server found.");
            println!();
            println!("Algorithm:   {}", host_key.algorithm);
            println!("Fingerprint: {}", host_key.fingerprint);
            println!();
            println!("The key was NOT trusted or saved.");
        }

        Err(error) => {
            eprintln!("SSH probe failed:");
            eprintln!("{error}");

            std::process::exit(1);
        }
    }
}
