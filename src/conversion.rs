use crate::data::{IocEntryId, IocId};
use chrono::Utc;

impl crate::hasher::HashError {
    pub(crate) fn to_ioc_error(&self, ioc_id: IocId,  ioc_entry_id: IocEntryId) -> crate::ioc_evaluator::IocEntrySearchError {
        crate::ioc_evaluator::IocEntrySearchError {
            ioc_id,
            ioc_entry_id,
            kind: self.kind.clone(),
            message: self.message.clone(),
        }
    }
}

impl crate::data::ReportUploadRequest {
    pub fn new(from: Vec<Result<crate::data::IocSearchResult, crate::data::IocSearchError>>, found_iocs: Vec<IocEntryId>) -> Self {
        let (ioc_results, ioc_errors): (Vec<Result<crate::data::IocSearchResult, crate::data::IocSearchError>>, Vec<Result<crate::data::IocSearchResult, crate::data::IocSearchError>>) =
            from.iter().map(|it| it.clone()).partition(Result::is_ok);
        let ioc_results_converted: Vec<crate::data::IocSearchResult> = ioc_results.into_iter()
            .map(Result::unwrap)
            .map(|it| crate::data::IocSearchResult::from(it))
            .collect();
        let ioc_errors_converted: Vec<crate::data::IocSearchError> = ioc_errors.into_iter()
            .map(Result::unwrap_err)
            .map(|it| crate::data::IocSearchError::from(it))
            .collect();
        crate::data::ReportUploadRequest {
            datetime: Utc::now(),
            found_iocs,
            ioc_results: ioc_results_converted,
            ioc_errors: ioc_errors_converted,
        }
    }
}
