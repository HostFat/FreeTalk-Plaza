//! Shared reason and status codes for topic/post reports and member moderation.
//!
//! Reasons are codes rather than free text so board state carries no private
//! commentary about members.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ReportReason {
    #[default]
    Spam,
    Abuse,
    OffTopic,
    Illegal,
    Other,
}

impl ReportReason {
    pub fn label(&self) -> &'static str {
        match self {
            ReportReason::Spam => "Spam",
            ReportReason::Abuse => "Abuse",
            ReportReason::OffTopic => "Off topic",
            ReportReason::Illegal => "Illegal content",
            ReportReason::Other => "Other",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ReportStatus {
    #[default]
    Open,
    Resolved,
    Dismissed,
}

impl ReportStatus {
    pub fn label(&self) -> &'static str {
        match self {
            ReportStatus::Open => "Open",
            ReportStatus::Resolved => "Resolved",
            ReportStatus::Dismissed => "Dismissed",
        }
    }
}
