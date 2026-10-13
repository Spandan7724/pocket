//! VMM backends. The only crate that knows which VMM runs a pocket.
//!
//! M1/M2 carry just what the guest integration tests need: a cold-boot launcher for Cloud
//! Hypervisor (D3) and the hybrid-vsock connect shared by every backend. The
//! `VmmBackend` trait (CONTRACTS.md §1) arrives in M3.

pub mod cloud_hypervisor;
pub mod vsock;
