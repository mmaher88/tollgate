use std::process::ExitCode;

use devproxy::args::{self, Command, USAGE};
use devproxy::server::{DevProxy, instructions};

fn main() -> ExitCode {
    let args = match args::parse(std::env::args().skip(1)) {
        Ok(Command::Run(args)) => args,
        Ok(Command::Help) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("devproxy: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    // One thread, like the tunnel's runtime.
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("devproxy: {e}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async {
        let proxy = match DevProxy::prepare(&args).await {
            Ok(proxy) => proxy,
            Err(e) => {
                eprintln!("devproxy: {e}");
                return ExitCode::FAILURE;
            }
        };
        println!(
            "{}",
            instructions(proxy.proxy_addr(), proxy.dns_addr(), &proxy.ca_path())
        );
        let stats = proxy
            .serve(async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await;
        println!("{stats:#?}");
        ExitCode::SUCCESS
    })
}
