use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct ConfiguredGameServer {
    pub id: u16,
    pub load_percentage: u8,
    pub ip_address: Ipv4Addr,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct ConnectCtx {
    pub servers: Vec<ConfiguredGameServer>,
}
