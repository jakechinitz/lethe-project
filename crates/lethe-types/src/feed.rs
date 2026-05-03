//! Front-page feed DTOs.

use crate::{B64, CoarseTime};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedSort {
    /// Sort by the most recent post in each thread (the "active" sort).
    #[default]
    LastComment,
    /// Sort by thread creation time (the "new" sort).
    Newest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedItem {
    pub thread_id: B64,
    pub board_id: String,
    pub title: String,
    pub created_at: CoarseTime,
    pub last_post_at: CoarseTime,
    pub post_count: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedResp {
    pub items: Vec<FeedItem>,
    /// Echo of the requested category, or `null` for the merged feed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    pub sort: FeedSort,
}
