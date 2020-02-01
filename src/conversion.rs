use crate::data::{IocEntryId, IocId};
use chrono::Utc;

//impl From<crate::data::SearchType> for crate::file_checker::SearchType {
//    fn from(from: crate::data::SearchType) -> Self {
//        match from {
//            crate::data::SearchType::Exact => crate::file_checker::SearchType::Exact,
//            crate::data::SearchType::Regex => crate::file_checker::SearchType::Regex,
//        }
//    }
//}
//
//impl From<crate::data::IocSearchError> for crate::query_result::IocSearchError {
//    fn from(from: crate::data::IocSearchError) -> Self {
//        crate::query_result::IocSearchError {
//            ioc_id: from.ioc_id,
//            kind: from.kind,
//            message: from.message,
//        }
//    }
//}

//impl From<crate::query_result::IocSearchError> for crate::data::IocSearchError {
//    fn from(from: crate::query_result::IocSearchError) -> Self {
//        crate::data::IocSearchError {
//            ioc_id: from.ioc_id,
//            kind: from.kind,
//            message: from.message,
//        }
//    }
//}
//
//impl From<crate::query_result::IocSearchResult> for crate::data::IocSearchResult {
//    fn from(from: crate::query_result::IocSearchResult) -> Self {
//        crate::data::IocSearchResult {
//            ioc_id: from.ioc_id,
//            data: from.data,
//        }
//    }
//}

//impl From<crate::data::HashType> for crate::hasher::HashType {
//    fn from(from: crate::data::HashType) -> Self {
//        match from {
//            crate::data::HashType::Md5 => crate::hasher::HashType::Md5,
//            crate::data::HashType::Sha1 => crate::hasher::HashType::Sha1,
//            crate::data::HashType::Sha256 => crate::hasher::HashType::Sha256,
//        }
//    }
//}

//impl From<crate::data::Hash> for crate::hasher::Hash {
//    fn from(from: crate::data::Hash) -> Self {
//        crate::hasher::Hash {
//            algorithm: crate::hasher::HashType::from(from.algorithm),
//            value: from.value,
//        }
//    }
//}

//impl From<crate::data::IocEntry> for crate::file_checker::FileParameters {
//    fn from(ioc_entry: crate::data::IocEntry) -> Self {
//        let file_info = ioc_entry.file_check.unwrap();
//        crate::file_checker::FileParameters {
//            ioc_id: ioc_entry.id,
//            search_type: ioc_entry.search_type,
//            file_path_or_name: file_info.name,
//            hash: file_info.hash,
//        }
//    }
//}

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
