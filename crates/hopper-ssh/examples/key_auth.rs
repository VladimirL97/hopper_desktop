use hopper_ssh::{read_hopper_node_identity, test_private_key_authentication};
use std::time::Duration;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 5 {
        eprintln!("Usage:");
        eprintln!(
            "cargo run -p hopper-ssh \
             --example key_auth -- \
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

    // Пароль нужен только сейчас,
    // чтобы безопасно забрать уже существующий
    // Hopper private key с подготовленного VPS.
    //
    // В будущем при добавлении сервера этот key
    // будет сохраняться локально через защищённое
    // Windows-хранилище, а root password сохранять
    // мы не будем.
    let password = match rpassword::prompt_password("SSH password: ") {
        Ok(password) => password,

        Err(error) => {
            eprintln!("Could not read password: {error}");

            std::process::exit(1);
        }
    };

    println!();
    println!("Reading existing Hopper identity...");
    println!("The private key will NOT be printed.");
    println!();

    let identity = match read_hopper_node_identity(
        host,
        port,
        user,
        &password,
        fingerprint,
        Duration::from_secs(10),
    )
    .await
    {
        Ok(identity) => identity,

        Err(error) => {
            eprintln!("Could not read Hopper identity:");
            eprintln!("{error}");

            std::process::exit(1);
        }
    };

    println!("Hopper identity loaded.");
    println!("Testing SSH authentication with Hopper key...");
    println!();

    // Самое важное:
    //
    // password здесь больше НЕ используется.
    //
    // Второе SSH-соединение должно пройти
    // исключительно по Hopper private key.
    match test_private_key_authentication(
        host,
        port,
        user,
        identity.private_key(),
        fingerprint,
        Duration::from_secs(10),
    )
    .await
    {
        Ok(()) => {
            println!("Hopper key authentication successful.");

            println!("No SSH commands were executed.");

            println!("No server files were modified.");
        }

        Err(error) => {
            eprintln!("Hopper key authentication failed:");

            eprintln!("{error}");

            std::process::exit(1);
        }
    }
}
