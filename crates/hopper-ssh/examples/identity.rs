use hopper_ssh::read_hopper_node_identity;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 5 {
        eprintln!(
            "Usage: cargo run -p hopper-ssh \
             --example identity -- \
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
    println!("Reading existing Hopper node identity...");
    println!("The private key will NOT be printed.");
    println!("No server files will be modified.");
    println!();

    match read_hopper_node_identity(
        host,
        port,
        user,
        &password,
        fingerprint,
        Duration::from_secs(10),
    )
    .await
    {
        Ok(identity) => {
            println!("Hopper private key: loaded and valid");

            println!("Hopper public key: {}", identity.public_key);

            println!();
            println!("No server files were modified.");
        }

        Err(error) => {
            eprintln!("Could not read Hopper identity: {error}");

            std::process::exit(1);
        }
    }
}
