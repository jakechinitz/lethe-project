//! `AppState` is what every route handler receives. Cheap to clone (Arc-y).

use crate::config::Config;
use sqlx::PgPool;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub cfg: Config,
}
