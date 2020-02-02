use serde::{Serialize, Deserialize};
use std::cmp::Ordering;
use std::fmt::{Display, Formatter, Result};
use chrono::{DateTime, Local, Utc};

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HashType {
    Md5,
    Sha1,
    Sha256,
}

impl Display for HashType {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SearchType {
    Exact,
    Regex,
}

impl SearchType {
    pub fn default() -> SearchType { SearchType::Exact }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Hashed {
    pub algorithm: HashType,
    pub value: String,
}

impl PartialEq for Hashed{
    fn eq(&self, other: &Self) -> bool {
        if &self.algorithm != &other.algorithm{
            return false
        }
        let self_hash = self.value.to_ascii_lowercase();
        let other_hash = other.value.to_ascii_lowercase();
        self_hash == other_hash
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RegistryInfo {
    #[serde(default = "SearchType::default")]
    pub search: SearchType,
    pub key: String,
    pub value_name: String,
    pub value: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FileInfo {
    #[serde(default = "SearchType::default")]
    pub search: SearchType,
    pub name: String,
    pub hash: Option<Hashed>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvaluationPolicy {
    All,
    One,
}

impl EvaluationPolicy {
    pub fn default() -> EvaluationPolicy { EvaluationPolicy::One }
}

#[derive(Debug, Hash, Serialize, Deserialize, Clone)]
pub struct IocSearchError {
    pub ioc_id: IocId,
    pub kind: String,
    pub message: String,
}

impl Display for IocSearchError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "IocError(ioc_id: {}, kind: {}, message: {})", self.ioc_id, self.kind, self.message)
    }
}

//pub trait Resolvable<T>{
//    fn resolve(&self) -> T;
//}
//
//impl Resolvable<LogicalOperator> for Option<LogicalOperator> {
//    fn resolve(&self) -> LogicalOperator {
//        self.unwrap_or(LogicalOperator::And)
//    }
//}

//#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
//#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
//pub enum Priority {
//    AllChildren,
//    OneChildren,
//    Normal,
//    Skip,
//}
//
//impl Priority {
//    fn default() -> Option<Priority> { Some(Priority::Normal) }
//}
//

pub type IocId = u64;

#[derive(Serialize, Deserialize, Debug, Clone, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Ioc {
    pub id: IocId,
    #[serde(default)]
    pub name: Option<String>,
    pub definition: IocEntry,
}

impl PartialEq for Ioc {
    fn eq(&self, other: &Self) -> bool {
        self.id.eq(&other.id)
    }
}

impl Eq for Ioc {}

impl Ord for Ioc {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}

impl PartialOrd for Ioc {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub type IocEntryId = u64;

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IocEntry {
    #[serde(default = "EvaluationPolicy::default")]
    pub eval_policy: EvaluationPolicy,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default = "EvaluationPolicy::default")]
    pub child_eval_policy: EvaluationPolicy,
    #[serde(default)]
    pub offspring: Option<Vec<IocEntry>>,
    #[serde(default)]
    pub registry_check: Option<RegistryInfo>,
    #[serde(default)]
    pub file_check: Option<FileInfo>,
    #[serde(default)]
    pub mutex_check: Option<MutexInfo>,
    #[serde(default)]
    pub process_check: Option<ProcessInfo>,
    #[serde(default)]
    pub dns_check: Option<DnsInfo>,
    #[serde(default)]
    pub conns_check: Option<ConnectionsInfo>,
    #[serde(default)]
    pub certs_check: Option<CertsInfo>
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash)]
#[serde(rename_all = "camelCase")]
pub struct GetIocResponse
{
    #[serde(default)]
    pub release_datetime: Option<DateTime<Utc>>,
    pub iocs: Vec<Ioc>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash)]
#[serde(rename_all = "camelCase")]
pub struct ReportUploadRequest {
    pub datetime: DateTime<Utc>,
    pub found_iocs: Vec<IocId>,
    pub ioc_results: Vec<IocSearchResult>,
    pub ioc_errors: Vec<IocSearchError>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash)]
#[serde(rename_all = "camelCase")]
pub struct IocSearchResult {
    pub ioc_id: IocId,
    pub data: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DnsInfo {
    pub data: Vec<String>
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CertSearchType {
    Domain,
    Issuer
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CertsInfo {
    pub search: CertSearchType,
    pub data: Vec<String>
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MutexInfo {
    pub data: Vec<String>
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConnSearchType {
    Ip,
    Exact,
    Regex
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionsInfo {
    pub search: ConnSearchType,
    pub data: Vec<String>
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProcessInfo {
    #[serde(default = "SearchType::default")]
    pub search: SearchType,
    #[serde(default)]
    pub hash: Option<Hashed>,
    #[serde(default)]
    pub data: Option<Vec<String>>
}



//#[cfg(test)]
//mod ioc_test {
//    use super::*;
//    use test::NamePadding::PadOnRight;
//
//    fn testing_ioc() -> Ioc {
//        Ioc {
//            id: 1,
//            priority: Some(Priority::OneChildren),
//            logical_operator: LogicalOperator::And,
//            search: SearchType::Exact,
//            data: "Something, something, something dark side".to_string(),
//            name: "DarthVader".to_string(),
//            children: Some(vec![
//                Ioc {
//                    id: 2,
//                    priority: Some(Priority::Normal),
//                    logical_operator: LogicalOperator::And,
//                    search: SearchType::Exact,
//                    data: "I am his father".to_string(),
//                    name: "LukeSkywalker".to_string(),
//                    children: None,
//                    registry_check: None,
//                    file_check: None,
//                },
//                Ioc {
//                    id: 3,
//                    index: 2,
//                    found: true,
//                    priority: THRESHOLD_PRIORITY - 5,
//                    logical_operator: LogicalOperator::And,
//                    search: SearchType::Exact,
//                    data: "I am also her father".to_string(),
//                    name: "LeiaOrgana".to_string(),
//                    children: None,
//                    additional_data: None,
//                    registry_check: None,
//                    file_check: None,
//                }
//            ]),
//            additional_data: None,
//            registry_check: None,
//            file_check: None,
//        }
//    }
//
//    #[test]
//    fn evaluate_threshold_priority() {
//        let ioc = testing_ioc(THRESHOLD_PRIORITY);
//        assert!(!ioc.evaluate());
//    }
//
//    #[test]
//    fn evaluate_low_priority() {
//        let ioc = testing_ioc(THRESHOLD_PRIORITY - 5);
//        assert!(ioc.evaluate());
//    }
//
//    #[test]
//    fn evaluate_high_priority() {
//        let ioc = testing_ioc(THRESHOLD_PRIORITY + 1);
//        assert!(ioc.evaluate());
//    }
//
//    #[test]
//    fn print_test_ioc() {
//        let ioc = testing_ioc(THRESHOLD_PRIORITY);
//        let json = serde_json::to_string_pretty(&ioc);
//        assert!(json.is_ok());
//        println!("{}", json.unwrap())
//    }
//}