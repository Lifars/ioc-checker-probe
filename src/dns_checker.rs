use crate::data::{IocEntryId, SearchType, Hashed, IocId};
use crate::ioc_evaluator::{IocEntrySearchResult, IocEntrySearchError};
use std::process::Command;
use log::logger;

pub struct DnsParameters {
    pub ioc_id: IocId,
    pub ioc_entry_id: IocEntryId,
    pub name: String,
}

#[cfg(windows)]
pub fn check_dns(search_parameters: &Vec<DnsParameters>) -> Vec<Result<IocEntrySearchResult, IocEntrySearchError>> {
    let output = Command::new("ipconfig")
        .args(&["/displaydns"])
        .output()
        .expect("failed to execute process");
    let output_str = std::str::from_utf8(&output.stdout);
    if output_str.is_err() {
        error!("Cannot read DNS entries due to {}", output_str.err().unwrap());
        return vec![];
    }
    let output_str = output_str.unwrap();
    let lines: Vec<&str> = output_str.lines().collect();

    let dns_names: Vec<&str> = lines.iter().enumerate()
        .filter(|(_, line)| line.trim().starts_with("----------"))
        .map(|(i, _)| lines[i - 1].trim()).collect();

    search_parameters.iter()
        .filter(|search_param| dns_names.iter().any(|dns| *dns == search_param.name.as_str()))
        .map(|search_param| Ok(IocEntrySearchResult {
            ioc_id: search_param.ioc_id,
            ioc_entry_id: search_param.ioc_entry_id,
            data: vec![search_param.name.clone()],
        })).collect()
}

#[cfg(not(windows))]
pub fn check_dns(search_parameters: &Vec<DnsParameters>) -> Vec<Result<IocEntrySearchResult, IocEntrySearchError>> {
    vec![]
}
