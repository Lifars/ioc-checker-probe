use crate::data::{IocEntryId};
use chrono::Utc;

impl crate::data::ReportUploadRequest {
    pub fn new(found_iocs: Vec<IocEntryId>) -> Self {
        crate::data::ReportUploadRequest {
            datetime: Utc::now(),
            found_iocs
        }
    }
}
