use crate::data::{IocEntryId, IocId};
use crate::ioc_evaluator::IocEntrySearchResult;
use std::process::Command;

pub struct DnsParameters {
    pub ioc_id: IocId,
    pub ioc_entry_id: IocEntryId,
    pub name: String,
}

#[cfg(windows)]
pub fn check_dns(search_parameters: Vec<DnsParameters>) -> Vec<IocEntrySearchResult> {
    if search_parameters.is_empty() {
        return vec![];
    }
    info!("DNS search: Searching IOCs using open DNS search.");
    let output = Command::new("ipconfig")
        .args(&["/displaydns"])
        .output()
        .expect("failed to execute process");
    let output_str = std::str::from_utf8(&output.stdout);
    if output_str.is_err() {
        error!("DNS search: {}", output_str.err().unwrap());
        return vec![];
    }
    let output_str = output_str.unwrap();
    let lines: Vec<&str> = output_str.lines().collect();

    let dns_names: Vec<&str> = lines.iter().enumerate()
        .filter(|(_, line)| line.trim().starts_with("----------"))
        .map(|(i, _)| lines[i - 1].trim()).collect();

    search_parameters.iter()
        .filter(|search_param| dns_names.iter().any(|dns| *dns == search_param.name.as_str()))
        .map(|search_param| {
            let message = format!("DNS search: Found DNS {} for IOC {}",
                  search_param.name.clone(),
                  search_param.ioc_id
            );
            info!("{}", message);
            IocEntrySearchResult {
                ioc_id: search_param.ioc_id,
                ioc_entry_id: search_param.ioc_entry_id,
                description: message
            }
        }).collect()
}

#[cfg(not(windows))]
pub fn check_dns(search_parameters: Vec<DnsParameters>) -> Vec<IocEntrySearchResult> {
    vec![]
}
