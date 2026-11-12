//! petrify: turn observed application behaviour into least-privilege policy.
//!
//! A log goes through three stages:
//!
//! 1. A [`sources`] module parses one log format into normalised [`events`].
//! 2. A collector ([`cloud`], [`network`], [`workloads`] or [`syscalls`]) folds the events
//!    into the behaviour of each subject seen in the log.
//! 3. The same module describes that behaviour or writes a policy allowing
//!    exactly it.

pub mod cli;
pub mod cloud;
pub mod events;
pub mod inputs;
pub mod network;
mod prefix;
pub mod sources;
mod syscall_tables;
pub mod syscalls;
mod text;
pub mod workloads;
