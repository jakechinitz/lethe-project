//! `AppState` is what every route handler receives. Cheap to clone.

use crate::{config::Config, federation::Identity, moderation::classifier::Classifier};
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub cfg: Config,
    pub classifier: Arc<dyn Classifier>,
    /// Persistent server identity. `None` only in unusual test
    /// configurations that bypass `build_state`; production code
    /// always populates this at startup.
    pub identity: Option<Arc<Identity>>,
}
