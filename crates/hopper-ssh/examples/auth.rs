use hopper_ssh::test_password_authentication;
use std::time::Duration;

#[tokio::main]
async fn main() {
    // Использование:
    //
    // cargo run -p hopper-ssh --example auth -- \
    //     <IP> <PORT> <USER> <FINGERPRINT>
    //
    // Пароль в командной строке НЕ передаём.
    //
    // Это важно:
    // command-line аргументы могут попасть:
    //
    // - в shell history;
    // - process list;
    // - IDE logs;
    // - terminal logs.

    let args: Vec<String> = std::env::args().collect();

    if args.len() != 5 {
        eprintln!("Usage:");
        eprintln!(
            "cargo run -p hopper-ssh --example auth -- \
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

    println!("Hopper SSH authentication test");
    println!();
    println!("Target:      {host}:{port}");
    println!("User:        {user}");
    println!("Fingerprint: {fingerprint}");
    println!();
    println!("No SSH commands will be executed.");
    println!("No files will be modified.");
    println!();

    // Пароль читается непосредственно из TTY.
    //
    // Он НЕ отображается на экране
    // и НЕ передаётся как CLI argument.
    let password = match rpassword::prompt_password("SSH password: ") {
        Ok(password) => password,

        Err(error) => {
            eprintln!("Could not read password: {error}");
            std::process::exit(1);
        }
    };

    println!();
    println!("Connecting...");

    match test_password_authentication(
        host,
        port,
        user,
        &password,
        fingerprint,
        Duration::from_secs(10),
    )
    .await
    {
        Ok(()) => {
            println!();
            println!("SSH authentication successful.");
            println!();
            println!("No commands were executed.");
            println!("Connection closed.");
        }

        Err(error) => {
            eprintln!();
            eprintln!("SSH authentication failed:");
            eprintln!("{error}");

            std::process::exit(1);
        }
    }
}
