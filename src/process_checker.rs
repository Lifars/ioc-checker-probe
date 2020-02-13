use crate::data::{IocEntryId, SearchType, Hashed, IocId, HashType};
use crate::ioc_evaluator::{IocEntrySearchResult, IocEntrySearchError};
use sysinfo::{ProcessExt, SystemExt};
use regex::Regex;
use std::path::Path;
use crate::hasher::{Hasher};

pub struct ProcessParameters {
    pub ioc_id: IocId,
    pub ioc_entry_id: IocEntryId,
    pub search: SearchType,
    pub name: Option<String>,
    pub hash: Option<Hashed>,
}

struct ProcessParametersRegexed {
    proc_param: ProcessParameters,
    regex: Option<Regex>,
}

#[cfg(windows)]
pub fn check_processes(search_parameters: Vec<ProcessParameters>) -> Vec<Result<IocEntrySearchResult, IocEntrySearchError>> {
    if search_parameters.is_empty() {
        return vec![];
    }
    info!("Searching IOCs using open process search.");
    let mut result: Vec<Result<IocEntrySearchResult, IocEntrySearchError>> = Vec::new();
    let search_parameters: Vec<ProcessParametersRegexed> = search_parameters.into_iter().filter_map(|sp| {
        match &sp.hash {
            Some(_) => Some(ProcessParametersRegexed { proc_param: sp, regex: None }),
            None => {
                match &sp.search {
                    SearchType::Exact => Some(ProcessParametersRegexed { proc_param: sp, regex: None }),
                    SearchType::Regex => match &sp.name {
                        None => None,
                        Some(searched_name) => match Regex::new(searched_name) {
                            Ok(regex) => Some(ProcessParametersRegexed { proc_param: sp, regex: Some(regex) }),
                            Err(err) => {
                                error!("{}", err);
                                result.push(Err(IocEntrySearchError {
                                    kind: "Regex ERROR".to_string(),
                                    message: format!("Cannot parse \"{}\" as regex. IOC id {}. Original error: {}",
                                                     searched_name,
                                                     sp.ioc_id,
                                                     err),
                                }));
                                None
                            }
                        },
                    }
                }
            }
        }
    }).collect();

    let mut system = sysinfo::System::new_all();
    system.refresh_all();
    for (_, proc) in system.get_processes() {
        //("{}   ==   {}", proc_.name(), proc_.exe().display());
        let exe_path: &Path = proc.exe();

        let hasher_md5 = Hasher::new(HashType::Md5);
        let executable_hash_md5 = hasher_md5.hash_file_by_path(exe_path);

        let hasher_sha1 = Hasher::new(HashType::Sha1);
        let executable_hash_sha1 = hasher_sha1.hash_file_by_path(exe_path);

        let hasher_sha256 = Hasher::new(HashType::Sha256);
        let executable_hash_sha256 = hasher_sha256.hash_file_by_path(exe_path);

        search_parameters.iter().for_each(|sp| {
            match &sp.proc_param.hash {
                None => match &sp.proc_param.name {
                    None => {}
                    Some(searched_name) => {
                        let matches = match &sp.regex {
                            None => searched_name == &proc.name(),
                            Some(regex) => regex.is_match(&proc.name()),
                        };
                        if matches {
                            result.push(Ok(IocEntrySearchResult {
                                ioc_id: sp.proc_param.ioc_id,
                                ioc_entry_id: sp.proc_param.ioc_entry_id,
                                data: vec![format!("Process {}", searched_name.clone())],
                            }));
                        }
                    }
                },
                Some(hash) => {
                    let executable_hash = match hash.algorithm {
                        HashType::Md5 => &executable_hash_md5,
                        HashType::Sha1 => &executable_hash_sha1,
                        HashType::Sha256 => &executable_hash_sha256,
                    };
                    match executable_hash {
                        Ok(executable_hash) => {
                            let mut data = Vec::<String>::new();
                            match &sp.proc_param.name {
                                None => {}
                                Some(process_name) => data.push(process_name.clone()),
                            };
                            data.push(executable_hash.algorithm.to_string());
                            data.push(executable_hash.value.clone());
                            result.push(Ok(IocEntrySearchResult {
                                ioc_id: sp.proc_param.ioc_id,
                                ioc_entry_id: sp.proc_param.ioc_entry_id,
                                data,
                            }))
                        }
                        Err(err) => result.push(Err(IocEntrySearchError {
                            kind: "Hash ERROR".to_string(),
                            message: format!("Cannot compute hash of file {}. IOC id {}. Original error: {}",
                                exe_path.display(),
                                sp.proc_param.ioc_id,
                                err
                            ),
                        }))
                    }
                }
            }
        })
    }
    result
}

#[cfg(not(windows))]
pub fn check_dns(search_parameters: Vec<DnsParameters>) -> Vec<Result<IocEntrySearchResult, IocEntrySearchError>> {
    vec![]
}
