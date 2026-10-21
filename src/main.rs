use std::path::Path;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 || (args[1] != "serve" && args[1] != "pull") {
        println!("qbeam-rs v0.2.0 — Multi-Gigabit Rust TLS 1.3 Point-to-Point Transfer Engine");
        println!("\nUsage:");
        println!("  Machine A (Serve): qbeam-rs serve <folder_or_file> [port=8443]");
        println!("  Machine B (Pull):  qbeam-rs pull <ticket> [concurrency=15]");
        std::process::exit(1);
    }

    let mode = &args[1];
    let res = if mode == "serve" {
        let path = Path::new(&args[2]);
        let port: u16 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(8443);
        qbeam_rs::run_sender(path, port).await
    } else {
        let ticket = &args[2];
        let workers: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(15);
        qbeam_rs::run_receiver(ticket, workers, Path::new("."))
            .await
            .map(|_| ())
    };

    if let Err(e) = res {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
