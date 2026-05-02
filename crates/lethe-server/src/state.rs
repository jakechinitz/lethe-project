//! `AppState` is what every route handler receives. Cheap to clone.

use crate::{config::Config, moderation::classifier::Classifier};
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub cfg: Config,
    pub classifier: Arc<dyn Classifier>,
}
