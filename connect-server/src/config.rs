use std::net::{Ipv4Addr, SocketAddr};

#[derive(Debug, Clone)]
pub struct ConfiguredGameServer {
    pub id: u16,
    pub load_percentage: u8,
    pub ip_address: Ipv4Addr,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct ConnectConfig {
    pub bind_addr: SocketAddr,
    pub servers: Vec<ConfiguredGameServer>,
}
