use serde::{Serialize, Deserialize};
use std::cmp::Ordering;
use std::fmt::{Display, Formatter, Result};
use chrono::{DateTime, Utc};

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
    pub name: Option<String>,
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
    pub kind: String,
    pub message: String,
}

impl Display for IocSearchError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "IocError(kind: {}, message: {})", self.kind, self.message)
    }
}

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
    pub name: String
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CertsInfo {
    pub name: String
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MutexInfo {
    pub name: String
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionsInfo {
    pub search: SearchType,
    pub name: String
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProcessInfo {
    #[serde(default = "SearchType::default")]
    pub search: SearchType,
    #[serde(default)]
    pub hash: Option<Hashed>,
    #[serde(default)]
    pub name: Option<String>
}