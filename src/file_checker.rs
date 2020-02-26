use crate::hasher::Hasher;
use std::ffi::CString;
use std::path::{Path, PathBuf};
use walkdir::{WalkDir, DirEntry};
use regex::Regex;
use std::collections::HashSet;
use crate::data::{SearchType, Hashed, IocEntryId, IocId};
use crate::ioc_evaluator::IocEntrySearchResult;
use crate::dir_resolver;


#[derive(Clone)]
pub struct FileParameters {
    pub ioc_id: IocId,
    pub ioc_entry_id: IocEntryId,
    pub search_type: SearchType,
    pub file_path_or_name: Option<String>,
    pub hash: Option<Hashed>,
}

pub fn check_files(search_parameters: Vec<FileParameters>, deep_search_enabled: bool) -> Vec<IocEntrySearchResult> {
    if search_parameters.is_empty() {
        return vec![];
    }
    info!("File search: Searching IOCs using file search.");
    let search_parameters = search_parameters.into_iter()
        .map(|sp| match &sp.search_type {
            SearchType::Exact => FileParameters {
                ioc_id: sp.ioc_id,
                ioc_entry_id: sp.ioc_entry_id,
                search_type: sp.search_type,
                file_path_or_name: match sp.file_path_or_name {
                    Some(file_path_or_name) => Some(dir_resolver::resolve(
                        PathBuf::from(file_path_or_name)).to_string_lossy().to_string()
                    ),
                    None => None
                },
                hash: sp.hash,
            },
            SearchType::Regex => sp
        }
        ).collect::<Vec<FileParameters>>();

    let search_by_exact = search_parameters.iter().filter(
        |search_parameter|
            match search_parameter.search_type {
                SearchType::Exact => true,
                _ => false
            }).filter(|search_parameter| !search_parameter.file_path_or_name.clone().unwrap_or("".to_string()).is_empty());
    let ok_results = search_by_exact.filter_map(|search_parameter| {
        check_file_by_hash(
            &search_parameter.hash,
            Path::new(search_parameter.file_path_or_name.clone().unwrap_or("".to_string()).as_str()),
            search_parameter.ioc_id,
            search_parameter.ioc_entry_id,
        )
    });
    let results = ok_results.collect::<Vec<IocEntrySearchResult>>();
    if search_parameters.len() == results.len() {
        info!("File search: Found all IOCs");
        return results;
    }
    if !deep_search_enabled {
        info!("File search: Found {} IOCs out of {} search parameters, skipping deep search", results.len(), search_parameters.len());
        return results;
    }
    info!("File search: Found only {} IOCs out of {} search parameters, starting deep search.", results.len(), search_parameters.len());
    let roots = all_drives();
    let found_ioc_entries = results.iter()
        .map(|ok_res| ok_res.ioc_entry_id).collect::<HashSet<IocEntryId>>();
    let remaining_search_parameters: Vec<FileParameters> = search_parameters
        .into_iter()
        .filter(|fp| !found_ioc_entries.contains(&fp.ioc_entry_id))
        .collect();
    let deep_results = roots.iter()
        .flat_map(|root| deep_search(
            root,
            &remaining_search_parameters,
        ));

    let final_results = results.into_iter().chain(deep_results.into_iter()).collect::<Vec<IocEntrySearchResult>>();
    return final_results;
}

fn deep_search(path: &Path, search_parameters: &[FileParameters]) -> Vec<IocEntrySearchResult> {
    debug!("File search: Searching files in {}", path.display());

    let walker = WalkDir::new(path);
    let walker_iter = walker.into_iter();
    let ok_entries = walker_iter.filter_map(Result::ok);
    let files = ok_entries.filter(|entry| entry.file_type().is_file());

    let mut found_file_parameters = HashSet::<usize>::new();
    let mut result = Vec::<IocEntrySearchResult>::new();
    for file_entry in files {
        if found_file_parameters.len() == search_parameters.len() {
            return result;
        }
        debug!("File search: Checking file {}", file_entry.path().display());
        for (i, search_parameter) in search_parameters.iter().enumerate() {
            if !found_file_parameters.contains(&i) {
                let maybe_query_result = match search_parameter.search_type {
                    SearchType::Exact => { check_file_by_name(search_parameter, &file_entry) }
                    SearchType::Regex => { check_file_by_regex(search_parameter, &file_entry) }
                };
                match maybe_query_result {
                    None => {}
                    Some(query_result) => {
                        info!("File search: Found {} for IOC {}",
                              file_entry.path().display(),
                              query_result.ioc_id
                        );
                        found_file_parameters.insert(i);
                        result.push(query_result)
                    }
                }
            }
        }
    }
    result
}


fn check_file_by_name(search_parameter: &FileParameters, file_entry: &DirEntry) -> Option<IocEntrySearchResult> {
    let empty_str = "".to_string();
    let searched_path = Path::new(search_parameter.file_path_or_name.as_ref().unwrap_or(&empty_str).as_str());
    let file_entry_path = file_entry.path();
    debug!("File search: Checking file paths {} and {} by exact match", searched_path.display(), file_entry_path.display());

    if searched_path.as_os_str().is_empty() {
        return check_file_by_hash(
            &search_parameter.hash,
            file_entry_path,
            search_parameter.ioc_id,
            search_parameter.ioc_entry_id,
        );
    }

    let searched_path_parent = searched_path.parent().unwrap_or(Path::new(""));
    let searched_filename = searched_path.file_name().unwrap_or_default();
    let file_entry_parent = file_entry_path.parent().unwrap_or(Path::new(""));

    if !searched_path_parent.as_os_str().is_empty() && file_entry_parent != searched_path_parent {
        return None;
    }
    if file_entry.file_name() != searched_filename {
        return None;
    }
    check_file_by_hash(
        &search_parameter.hash,
        file_entry_path,
        search_parameter.ioc_id,
        search_parameter.ioc_entry_id,
    )
}

fn check_file_by_regex(
    search_parameter: &FileParameters,
    file_entry: &DirEntry,
) -> Option<IocEntrySearchResult> {
    let empty_str = "".to_string();
    let searched_path = search_parameter.file_path_or_name.as_ref().unwrap_or(&empty_str).as_str();
    debug!("File search: Checking file paths {} and {} by regex", searched_path, file_entry.path().display());
    let regex_path = Regex::new(searched_path);
    if regex_path.is_err() {
        let err = format!("File search: Cannot parse file path {} as regex: {}", searched_path, regex_path.unwrap_err());
        error!("{}", err);
        return None;
    }
    let regex_path = regex_path.unwrap();

    let file_path_matched = regex_path.is_match(file_entry.path().to_str().unwrap_or_default());
    let file_path_empty = searched_path.is_empty();
    let file_name_matched = regex_path.is_match(file_entry.file_name().to_str().unwrap_or_default());

    debug!("File search: Regex match by file paths {} and {} successful: {}", searched_path, file_entry.path().display(), file_path_matched);
    debug!("File search: Regex match by file name {} and {:?} successful: {}", searched_path, file_entry.file_name(), file_name_matched);

    if !file_name_matched && !file_path_empty && !file_name_matched { None } else {
        check_file_by_hash(
            &search_parameter.hash,
            file_entry.path(),
            search_parameter.ioc_id,
            search_parameter.ioc_entry_id,
        )
    }
}

fn check_file_by_hash(
    searched_hash: &Option<Hashed>,
    file_path: &Path,
    ioc_id: IocId,
    ioc_entry_id: IocEntryId,
) -> Option<IocEntrySearchResult> {
    debug!("File search: Checking if file {} is IOC by hash", file_path.display());
    match searched_hash {
        None => {
            debug!("File search: No hash for file {} specified, considering it as IOC", file_path.display());
            Some(
                IocEntrySearchResult {
                    ioc_id,
                    ioc_entry_id,
                }
            )
        }
        Some(searched_hash) => {
            debug!("File search: Compare specified {} hash of {} with file {}",
                   searched_hash.algorithm,
                   searched_hash.value,
                   file_path.display()
            );
            let file_hash = Hasher::new(searched_hash.algorithm.clone()).hash_file_by_path(file_path);
            match file_hash {
                Ok(file_hash) => {
                    if file_hash == *searched_hash {
                        Some(IocEntrySearchResult {
                            ioc_id,
                            ioc_entry_id,
                        })
                    } else {
                        debug!("File search: Hashes does not match. Expected {} != {} found", searched_hash.value, file_hash.value);
                        None
                    }
                }
                Err(error) => {
                    let err = format!("File search: Cannot compute {} hash of \"{}\": {}",
                                      searched_hash.algorithm,
                                      file_path.display(),
                                      error
                    );
                    error!("{}", err);
                    None
                }
            }
        }
    }
}

/// Source: https://stackoverflow.com/questions/33654653/efficient-approach-to-get-all-logical-drive-letters-of-hdd-and-collect-root-dirs
#[cfg(windows)]
fn all_drives() -> Vec<PathBuf> {
    let mut logical_drives = Vec::<PathBuf>::new();
    let mut bitfield = unsafe { winapi::um::fileapi::GetLogicalDrives() };
    let mut drive = 'A';

    while bitfield != 0 {
        if bitfield & 1 == 1 {
            let strfulldl = drive.to_string() + ":\\";
            let cstrfulldl = CString::new(strfulldl.clone()).unwrap();

            let x = unsafe { winapi::um::fileapi::GetDriveTypeA(cstrfulldl.as_ptr()) };
            if x == 3 // || x ==2 // 3 - fixed drive (HDD, USB, ...); 2 - removable drive (Memory Card, Floppy) // see https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypea
            {
                logical_drives.push(PathBuf::from(strfulldl));
                // println!("drive {0} is {1}", strfdl, x);
            }
        }
        drive = std::char::from_u32((drive as u32) + 1).unwrap();
        bitfield >>= 1;
    }
    logical_drives
}

#[cfg(not(windows))]
fn all_drives() -> Vec<PathBuf> {
    vec![]
}


#[cfg(test)]
mod tests {
    use crate::file_checker::all_drives;

    #[test]
    fn test_all_drives() {
        let drives = all_drives();
        drives.iter().for_each(|drive| println!("[Test] Found drive {}", drive.display()))
    }
}