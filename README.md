<div align="center">

# albatross

A composable HTTP server for Tower services built around pluggable connection acceptors.

[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/callum-hopkins-dev/albatross/build.yaml?branch=main&event=push&style=for-the-badge)](https://github.com/callum-hopkins-dev/albatross/actions/workflows/build.yaml)
[![Crates.io Version](https://img.shields.io/crates/v/albatross?style=for-the-badge)](https://crates.io/crates/albatross)
[![docs.rs](https://img.shields.io/docsrs/albatross?style=for-the-badge)](https://docs.rs/albatross/latest/albatross)
[![Crates.io Total Downloads](https://img.shields.io/crates/d/albatross?style=for-the-badge)](https://crates.io/crates/albatross)
[![GitHub License](https://img.shields.io/github/license/callum-hopkins-dev/albatross?style=for-the-badge)](https://github.com/callum-hopkins-dev/albatross/blob/main/LICENSE)

</div>

## About

**albatross** provides a small, focused API for flexible connection
handling through **pluggable acceptors**. Acceptors allow you to inspect,
transform, or wrap incoming connections before they reach your application,
without complicating the core server interface.

This makes it easy to add functionality such as TLS termination, automatic
certificate management, protocol detection, or integration with service
managers, all in a modular and composable way.

`albatross` works with any tower [`Service`](tower::Service) that matches the expected
signature. While it is generally intended for use with [axum](https://docs.rs/axum),
it can serve any compatible tower service.

## Pluggable Acceptors

An **acceptor** sits between the listener and your service. Acceptors can:

 - Wrap connections (e.g., TLS termination)  
 - Inspect or modify connection metadata  
 - Conditionally redirect or upgrade protocols  
 - Integrate with external systems

Multiple acceptors can be composed together to create the exact connection
behavior your server needs.

## Built-in Acceptors

The library provides several ready-to-use acceptors behind feature flags:

 - `systemd` — integrates with systemd notifications and watchdogs  
 - `tls` — terminates HTTPS connections  
 - `acme` — similar to `tls` but automatically obtains and renews certificates  
 - `https-upgrade` — detects plain HTTP connections and upgrades or redirects them to HTTPS

## Getting Started

Add **albatross** to your project:

```sh
cargo add albatross --features tls,https-upgrade
```

Create a server by binding a socket address and serving a `tower::Service`.
Additional connection behavior (such as TLS or redirects) can be added using acceptors.

```rust
use axum::{Router, routing::get};

#[tokio::main]
async fn main() {
    let router = Router::new()
      .route("/", get(|| async { "Hello, world!" }));

    albatross::server("0.0.0.0:443")
        .with_acceptor(albatross::tls().with_certificate("cert.pem"))
        .with_https_upgrade()
        .serve(router.into_make_service())
        .await
        .unwrap();
}
```
