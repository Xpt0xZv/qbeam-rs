use std::path::{Path, PathBuf};

fn print_usage() {
    println!("qbeam-rs v0.2.0 — Multi-Gigabit Rust TLS 1.3 Point-to-Point Transfer Engine");
    println!("\nUsage:");
    println!("  Machine A (Serve): qbeam-rs serve <folder_or_file> [-p PORT]");
    println!("  Machine B (Pull):  qbeam-rs pull <ticket> [-o OUTPUT_DIR] [-w WORKERS]");
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 || (args[1] != "serve" && args[1] != "pull") {
        print_usage();
        std::process::exit(1);
    }

    let mode = &args[1];
    let target_or_ticket = &args[2];

    let mut port: u16 = 8000;
    let mut workers: usize = 15;
    let mut output_dir = PathBuf::from(".");

    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" | "--dest" => {
                if i + 1 < args.len() {
                    output_dir = PathBuf::from(&args[i + 1]);
                    i += 2;
                } else {
                    eprintln!("Error: {} requires a directory path", args[i]);
                    std::process::exit(1);
                }
            }
            "-w" | "--workers" | "-c" | "--concurrency" => {
                if i + 1 < args.len() {
                    workers = args[i + 1].parse().unwrap_or(15);
                    i += 2;
                } else {
                    eprintln!("Error: {} requires a number", args[i]);
                    std::process::exit(1);
                }
            }
            "-p" | "--port" => {
                if i + 1 < args.len() {
                    port = args[i + 1].parse().unwrap_or(8000);
                    i += 2;
                } else {
                    eprintln!("Error: {} requires a port number", args[i]);
                    std::process::exit(1);
                }
            }
            val => {
                if mode == "serve" {
                    if let Ok(p) = val.parse::<u16>() {
                        port = p;
                    }
                } else if let Ok(w) = val.parse::<usize>() {
                    workers = w;
                }
                i += 1;
            }
        }
    }

    let res = if mode == "serve" {
        qbeam_rs::run_sender(Path::new(target_or_ticket), port).await
    } else {
        qbeam_rs::run_receiver(target_or_ticket, workers, &output_dir)
            .await
            .map(|_| ())
    };

    if let Err(e) = res {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
