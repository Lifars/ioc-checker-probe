use crate::data::{IocEntryId, IocId, SearchType};
use crate::ioc_evaluator::IocEntrySearchResult;
#[cfg(windows)]
use crate::priv_esca::{get_privileges, drop_privileges};
#[cfg(windows)]
use winapi::um::winreg::{HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_CURRENT_USER_LOCAL_SETTINGS, HKEY_DYN_DATA, HKEY_LOCAL_MACHINE, HKEY_PERFORMANCE_DATA, HKEY_PERFORMANCE_NLSTEXT, HKEY_PERFORMANCE_TEXT, HKEY_USERS};
#[cfg(windows)]
use winreg::{HKEY, RegKey};
use std::collections::HashSet;
use regex::Regex;

pub struct RegistryParameters {
    pub ioc_id: IocId,
    pub ioc_entry_id: IocEntryId,
    pub search_type: SearchType,
    pub key: String,
    pub value_name: String,
    pub value: Option<String>,
}

#[cfg(not(windows))]
pub fn check_registry(search_parameters: Vec<RegistryParameters>) -> Vec<IocEntrySearchResult> {
    return vec![];
}

#[cfg(windows)]
pub fn check_registry(search_parameters: Vec<RegistryParameters>, deep_search_enabled: bool) -> Vec<IocEntrySearchResult> {
    if search_parameters.is_empty() {
        return vec![];
    }
    info!("Registry search: Searching IOCs using registry search.");
    unsafe {
        let gp = get_privileges(winapi::um::winnt::SE_TAKE_OWNERSHIP_NAME);
        if gp.is_err() { error!("{}", gp.unwrap_err()) }
    };
    let search_by_exact = search_parameters.iter().filter(
        |search_parameter|
            match search_parameter.search_type {
                SearchType::Exact => true,
                _ => false
            });
    let ok_results = search_by_exact.filter_map(|search_parameter| {
        let registry = open_registry(&search_parameter.key);
        match registry {
            Ok(registry) => check_by_value(
                &search_parameter,
                &registry,
            ),
            Err(err) => {
                info!("Registry search: Cannot open registry {} for IOC id {}. Original reason {}",
                       search_parameter.key,
                       search_parameter.ioc_id,
                       err);
                None
            }
        }
    });
    let results = ok_results.collect::<Vec<IocEntrySearchResult>>();
    if search_parameters.len() == results.len() {
        info!("Registry search: Found {} IOCs out of {} search parameters", results.len(), search_parameters.len());
        return results;
    }

    let found_ioc_entries = results.iter()
        .map(|ok_res| ok_res.ioc_entry_id).collect::<HashSet<IocEntryId>>();
    let regex_search_request_is_present = search_parameters
        .iter()
        .any(|it| it.search_type == SearchType::Regex);
    let deep_results = if deep_search_enabled && regex_search_request_is_present {
        info!("Registry search: Found only {} IOCs out of {} search parameters, starting deep search.", results.len(), search_parameters.len());
        let remaining_search_parameters: Vec<RegistryParameters> = search_parameters
            .into_iter()
            .filter(|fp| !found_ioc_entries.contains(&fp.ioc_entry_id))
            .collect();
        deep_search(&remaining_search_parameters)
    } else {
        info!("Registry search: Found only {} IOCs out of {} search parameters, skipping deep search.", results.len(), search_parameters.len());
        vec![]
    };

    let final_results = results.into_iter().chain(deep_results.into_iter()).collect::<Vec<IocEntrySearchResult>>();
    unsafe {
        let gp = drop_privileges(winapi::um::winnt::SE_TAKE_OWNERSHIP_NAME);
        if gp.is_err() { error!("Registry search: {}", gp.unwrap_err()) }
    };
    return final_results;
}

#[cfg(windows)]
fn open_registry(key: &str) -> Result<RegKey, std::io::Error> {
    let splitted_key: Vec<&str> = key.splitn(2, "\\").collect();
    if splitted_key.len() == 1 {
        let root = splitted_key[0];
        let hkey = predef_key_by_name(&root);
        if hkey.is_none() {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("Registry search: Cannot open {}", root)));
        }
        Ok(winreg::RegKey::predef(hkey.unwrap()))
    } else {
        let root = splitted_key[0];
        let path = splitted_key[1];
        let hkey = predef_key_by_name(&root);
        if hkey.is_none() {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("Registry search: Cannot open {}", root)));
        }
        let registry_root = winreg::RegKey::predef(hkey.unwrap());
        registry_root.open_subkey(path)
    }
}

#[cfg(windows)]
fn predef_key_by_name(name: &str) -> Option<HKEY> {
    match name {
        "HKEY_CLASSES_ROOT" => Some(HKEY_CLASSES_ROOT),
        "HKEY_CURRENT_CONFIG" => Some(HKEY_CURRENT_CONFIG),
        "HKEY_CURRENT_USER" => Some(HKEY_CURRENT_USER),
        "HKEY_CURRENT_USER_LOCAL_SETTINGS" => Some(HKEY_CURRENT_USER_LOCAL_SETTINGS),
        "HKEY_DYN_DATA" => Some(HKEY_DYN_DATA),
        "HKEY_LOCAL_MACHINE" => Some(HKEY_LOCAL_MACHINE),
        "HKEY_PERFORMANCE_DATA" => Some(HKEY_PERFORMANCE_DATA),
        "HKEY_PERFORMANCE_NLSTEXT" => Some(HKEY_PERFORMANCE_NLSTEXT),
        "HKEY_PERFORMANCE_TEXT" => Some(HKEY_PERFORMANCE_TEXT),
        "HKEY_USERS" => Some(HKEY_USERS),

        "HKCR" => Some(HKEY_CLASSES_ROOT),
        "HKCC" => Some(HKEY_CURRENT_CONFIG),
        "HKCU" => Some(HKEY_CURRENT_USER),
        "HKLM" => Some(HKEY_LOCAL_MACHINE),
        "HKU" => Some(HKEY_USERS),
        _ => None
    }
}

#[cfg(windows)]
fn handle_key_rec(
    key: &RegKey,
    full_key_path: &str,
    search_parameters: &[RegistryParameters],
    results: &mut Vec<IocEntrySearchResult>,
    found_search_parameters: &mut HashSet<usize>,
) {
    for sub_key_name in key.enum_keys() {
        match sub_key_name {
            Ok(sub_key_name) => {
                let sub_key = key.open_subkey(&sub_key_name);
                match sub_key {
                    Ok(sub_key) => {
                        let full_sub_key_path = format!("{}\\{}", full_key_path, sub_key_name);
                        search_parameters.iter().enumerate().for_each(|(i, sp)| {
                            if !found_search_parameters.contains(&i) {
                                let maybe_match = match sp.search_type {
                                    SearchType::Exact => check_by_name(sp, &sub_key, &sub_key_name),
                                    SearchType::Regex => check_by_name_regex(sp, &sub_key, &full_sub_key_path),
                                };
                                if maybe_match.is_some() {
                                    results.push(maybe_match.unwrap());
                                    found_search_parameters.insert(i);
                                }
                                handle_key_rec(&sub_key, &full_sub_key_path, search_parameters, results, found_search_parameters);
                            }
                        });
                    }
                    Err(err) => {
                        error!("Registry search: {}", err);
                    }
                }
            }
            Err(err) => {
                error!("Registry search: {}", err);
            }
        }
    }
}

#[cfg(windows)]
fn deep_search(search_parameters: &[RegistryParameters]) -> Vec<IocEntrySearchResult> {
    let hkeys = [(HKEY_CURRENT_USER, "HKEY_CURRENT_USER".to_string()),
        (HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE".to_string()),
        (HKEY_CLASSES_ROOT, "HKEY_CLASSES_ROOT".to_string()),
        (HKEY_CURRENT_CONFIG, "HKEY_CURRENT_CONFIG".to_string()),
        (HKEY_CURRENT_USER_LOCAL_SETTINGS, "HKEY_CURRENT_USER_LOCAL_SETTINGS".to_string()),
        (HKEY_DYN_DATA, "HKEY_DYN_DATA".to_string()),
        (HKEY_PERFORMANCE_DATA, "HKEY_PERFORMANCE_DATA".to_string()),
        (HKEY_PERFORMANCE_TEXT, "HKEY_PERFORMANCE_TEST".to_string()),
        (HKEY_PERFORMANCE_NLSTEXT, "HKEY_PERFORMANCE_NLSTEXT".to_string()),
        (HKEY_USERS, "HKEY_USERS".to_string())
    ];

    let mut found_file_parameters = HashSet::<usize>::new();
    let mut result = Vec::<IocEntrySearchResult>::new();

    for (hkey, hkey_name) in hkeys.iter() {
        if found_file_parameters.len() == search_parameters.len() {
            return result;
        }
        debug!("Registry search: Beginning deep search for {}", hkey_name);
        handle_key_rec(&RegKey::predef(*hkey), hkey_name, search_parameters, &mut result, &mut found_file_parameters);
    }

    result
}

#[cfg(windows)]
fn check_by_value(search_parameter: &RegistryParameters, reg_entry: &winreg::RegKey) -> Option<IocEntrySearchResult> {
    let reg_value_str: Result<String, std::io::Error> = reg_entry.get_value(&search_parameter.value_name);
    let reg_value: String = match reg_value_str {
        Ok(reg_value_str) => reg_value_str,

        Err(_) => {
            let reg_value_u32: Result<u32, std::io::Error> = reg_entry.get_value(&search_parameter.value_name);
            match reg_value_u32 {
                Ok(reg_value_u32) => reg_value_u32.to_string(),

                Err(_) => {
                    let reg_value_u64: Result<u64, std::io::Error> = reg_entry.get_value(&search_parameter.value_name);
                    match reg_value_u64 {
                        Ok(reg_value_u64) => reg_value_u64.to_string(),
                        Err(err) => {
                            error!("Registry search: {}", err);
                            "".to_string()
                        }
                    }
                }
            }
        }
    };

    return match &search_parameter.value {
        None => {
            let message = format!("Registry search: Found reg key {}\\{} for IOC {}",
                  search_parameter.key,
                  search_parameter.value_name,
                  search_parameter.ioc_id
            );
            info!("{}", message);
            Some(IocEntrySearchResult {
                ioc_id: search_parameter.ioc_id,
                ioc_entry_id: search_parameter.ioc_entry_id,
                description: message
            })
        }
        Some(search_value) => {
            if search_value == &reg_value {
                let message = format!("Registry search: Found reg key {}\\{} = {} for IOC {}",
                      search_parameter.key,
                      search_parameter.value_name,
                      search_value,
                      search_parameter.ioc_id
                );
                info!("{}", message);
                Some(IocEntrySearchResult {
                    ioc_id: search_parameter.ioc_id,
                    ioc_entry_id: search_parameter.ioc_entry_id,
                    description: message
                })
            } else {
                None
            }
        }
    };
}

#[cfg(windows)]
fn check_by_name(
    search_parameter: &RegistryParameters,
    reg_entry: &RegKey,
    reg_entry_name: &str,
) -> Option<IocEntrySearchResult> {
    debug!("Checking registry keys {} and {} by match", search_parameter.key, reg_entry_name);
    if search_parameter.key.ends_with(reg_entry_name) {
        return check_by_value(search_parameter, reg_entry);
    }
    None
}


#[cfg(windows)]
fn check_by_name_regex(
    search_parameter: &RegistryParameters,
    reg_entry: &RegKey,
    reg_entry_full_path: &str,
) -> Option<IocEntrySearchResult> {
    debug!("Checking registry keys {} and {} by regex", search_parameter.key, reg_entry_full_path);
    let regex_path = Regex::new(reg_entry_full_path);
    if regex_path.is_err() {
        let err = format!("Cannot parse registry {} as regex: {}", reg_entry_full_path, regex_path.unwrap_err());
        error!("{}", err);
        return None;
    }
    let regex_path = regex_path.unwrap();

    if regex_path.is_match(&search_parameter.key) {
        return check_by_value(search_parameter, reg_entry);
    }
    None
}