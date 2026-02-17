# mu-rust

A MU Online server implementation in Rust, built for learning and fun.

This project is a from-scratch reimplementation of a MU Online server, inspired by the amazing [OpenMU](https://github.com/MUnique/OpenMU) project (reference commit: `6f5c73a`). The goal isn't to fully replicate OpenMU, but to understand how one of the best MMORPGs from the early 2000s works under the hood while having some fun.

## Structure

```
mu-rust/
  connect-server/    # Entry point gateway - handles server discovery and redirection
  game-server/       # Game world server - handles gameplay after server selection
  crates/
    mu-protocol/     # Shared protocol definitions, packet codec, and framing logic
```

## Current Status

- Connect Server handshake and server list flow
- Game Server initial connection (login screen)

## Running

```sh
# Start the connect server (port 44405)
cargo run -p connect-server

# Start the game server (port 55901)
cargo run -p game-server
```

## References

- [OpenMU](https://github.com/MUnique/OpenMU) - The C# server that serves as the primary reference
- [OpenMU Packet Documentation](https://github.com/MUnique/OpenMU/tree/master/docs/Packets)
