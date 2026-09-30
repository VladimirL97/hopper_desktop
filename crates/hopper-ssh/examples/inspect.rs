use hopper_ssh::inspect_hopper_server;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 5 {
        eprintln!("Usage:");
        eprintln!(
            "cargo run -p hopper-ssh --example inspect -- \
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
    println!("Inspecting server in read-only mode...");
    println!();

    match inspect_hopper_server(
        host,
        port,
        user,
        &password,
        fingerprint,
        Duration::from_secs(10),
    )
    .await
    {
        Ok(info) => {
            println!("OS:           {}", info.os);
            println!("Architecture: {}", info.architecture);

            if let Some(version) = &info.version {
                println!("Hopper:       {}", version.version);
                println!("Protocol:     {}", version.protocol_version);
                println!("Min app:      {}", version.min_app_version);
            }

            println!();

            println!("Layout:       {:?}", info.layout_kind());

            println!();

            println!("hopperctl:       {}", info.hopperctl);
            println!("command start:    {}", info.command_start);
            println!("command configure:{}", info.command_configure);
            println!("command status:   {}", info.command_status);
            println!("command install:  {}", info.command_install);
            println!("command update:   {}", info.command_update);

            println!();

            println!("hopperd amd64:    {}", info.hopperd_amd64);
            println!("hopperd arm64:    {}", info.hopperd_arm64);

            println!();

            println!("private key:      {}", info.hop_private_key);
            println!("public key:       {}", info.hop_public_key);
            println!("registry.json:    {}", info.registry_file);
            println!("chains/:          {}", info.chains_directory);

            println!();

            if info.looks_like_hopper() {
                println!("Compatible Hopper installation detected.");
            } else {
                println!("Unsupported or incomplete Hopper installation.");
            }

            println!();
            println!("No files were modified.");
        }

        Err(error) => {
            eprintln!("Inspection failed:");
            eprintln!("{error}");

            std::process::exit(1);
        }
    }
}
