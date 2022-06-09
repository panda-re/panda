use std::collections::HashMap;
use std::net::Ipv4Addr;

use once_cell::sync::Lazy;
use owo_colors::OwoColorize;
use tabled::{object::FirstRow, style::Style, Format, Modify, Table, Tabled};

use tcp_shared_types::SocketInfo;

#[derive(Tabled)]
struct TableEntry {
    #[tabled(rename = "Listening")]
    listening: &'static str,

    #[tabled(rename = "Local IP")]
    ip: Ipv4Addr,

    #[tabled(rename = "Port")]
    port: u16,

    #[tabled(rename = "PID")]
    pid: String,

    #[tabled(rename = "Description")]
    description: &'static str,
}

static TCP_NAMES_CSV: &str = include_str!("tcp.csv");

static PORT_TO_NAME: Lazy<HashMap<u16, &'static str>> = Lazy::new(|| {
    TCP_NAMES_CSV
        .trim()
        .split('\n')
        .filter(|line| !line.is_empty())
        .filter_map(|line| line.split_once(','))
        .filter_map(|(port, name)| port.parse().ok().map(move |port| (port, name)))
        .collect()
});

const CHECK_MARK: &str = "\u{1f5f8}";

pub(crate) fn print_table(sockets: Vec<SocketInfo>) {
    let tcp_server_table = sockets
        .into_iter()
        .map(|socket| TableEntry {
            listening: if socket.server { CHECK_MARK } else { " " },
            ip: socket.ip.clone(),
            port: socket.port,
            pid: socket
                .pid
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| String::from("")),
            description: PORT_TO_NAME.get(&socket.port).copied().unwrap_or(""),
        })
        .collect::<Vec<_>>();

    println!(
        "\n\n{}\n",
        Table::new(tcp_server_table)
            .with(Style::modern())
            .with(Modify::new(FirstRow).with(Format::new(|text| text.bold().to_string())))
            .with(tabled::Header("TCP Sockets"))
            .with(
                Modify::new(FirstRow)
                    .with(tabled::Alignment::center())
                    .with(Format::new(|text| text.bold().to_string()))
            )
    );
}
