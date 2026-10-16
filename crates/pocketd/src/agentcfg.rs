//! Agent config copy-in and `config pull` (SECURITY.md §Agent config sync).

use std::sync::Arc;

use pocket_store::PocketRecord;

use crate::daemon::{Daemon, Meta, R};
use crate::guest::GuestConn;
use crate::inject::PocketHooks;

pub async fn copy_in(
    _d: &Arc<Daemon>,
    _guest: &GuestConn,
    _rec: &PocketRecord,
    _meta: &Meta,
    _hooks: &PocketHooks,
) -> R<()> {
    Ok(())
}
