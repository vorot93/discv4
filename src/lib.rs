//! Ethereum Node Discovery v4 implementation.

#![allow(clippy::type_complexity)]

mod kad;
mod message;
mod node;
mod proto;
mod util;

use primitive_types::H512;

pub type NodeId = H512;
pub use crate::node::{Node, NodeRecord};
