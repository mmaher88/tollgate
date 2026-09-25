use std::path::PathBuf;

use devproxy::args::{Args, Command, DEFAULT_LISTS, ListKind, ListSpec, parse};

fn run(args: &[&str]) -> Result<Command, String> {
    parse(args.iter().map(|a| a.to_string()))
}

fn defaults() -> Args {
    Args {
        data_dir: PathBuf::from("devproxy-data"),
        config: None,
        lists: Vec::new(),
        dns: "127.0.0.1:5353".parse().unwrap(),
        proxy: "127.0.0.1:8080".parse().unwrap(),
    }
}

#[test]
fn no_arguments_give_the_defaults() {
    assert_eq!(run(&[]), Ok(Command::Run(defaults())));
}

#[test]
fn every_option_is_read() {
    let parsed = run(&[
        "--data-dir",
        "/tmp/tg",
        "--config",
        "config.json",
        "--url-list",
        "easylist.txt",
        "--dns-list",
        "https://example.com/dns.txt",
        "--hosts-list",
        "hosts",
        "--dns",
        "127.0.0.1:0",
        "--proxy",
        "[::1]:8888",
    ]);
    assert_eq!(
        parsed,
        Ok(Command::Run(Args {
            data_dir: PathBuf::from("/tmp/tg"),
            config: Some(PathBuf::from("config.json")),
            lists: vec![
                ListSpec {
                    kind: ListKind::Url,
                    source: "easylist.txt".to_string()
                },
                ListSpec {
                    kind: ListKind::Dns,
                    source: "https://example.com/dns.txt".to_string()
                },
                ListSpec {
                    kind: ListKind::Hosts,
                    source: "hosts".to_string()
                },
            ],
            dns: "127.0.0.1:0".parse().unwrap(),
            proxy: "[::1]:8888".parse().unwrap(),
        }))
    );
}

#[test]
fn default_lists_expand_in_place() {
    let Ok(Command::Run(args)) = run(&["--url-list", "mine.txt", "--default-lists"]) else {
        panic!("expected run");
    };
    let sources: Vec<(ListKind, &str)> = args
        .lists
        .iter()
        .map(|l| (l.kind, l.source.as_str()))
        .collect();
    let mut expected = vec![(ListKind::Url, "mine.txt")];
    expected.extend(DEFAULT_LISTS);
    assert_eq!(sources, expected);
    assert_eq!(
        DEFAULT_LISTS.map(|(kind, _)| kind),
        [
            ListKind::Url,
            ListKind::Url,
            ListKind::Url,
            ListKind::Dns,
            ListKind::Hosts
        ]
    );
}

#[test]
fn help_wins_anywhere() {
    assert_eq!(run(&["--dns", "127.0.0.1:1", "-h"]), Ok(Command::Help));
    assert_eq!(run(&["--help"]), Ok(Command::Help));
}

#[test]
fn mistakes_are_reported() {
    assert_eq!(
        run(&["--data-dir"]),
        Err("--data-dir needs a value".to_string())
    );
    assert_eq!(
        run(&["--dns", "localhost:53"]),
        Err("--dns: invalid socket address \"localhost:53\"".to_string())
    );
    assert_eq!(
        run(&["--proxy", "8080"]),
        Err("--proxy: invalid socket address \"8080\"".to_string())
    );
    assert_eq!(
        run(&["--verbose"]),
        Err("unknown argument \"--verbose\"".to_string())
    );
    assert_eq!(
        run(&["lists.txt"]),
        Err("unknown argument \"lists.txt\"".to_string())
    );
}
