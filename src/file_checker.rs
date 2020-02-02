use crate::hasher::Hasher;
use std::ffi::CString;
use std::path::{Path, PathBuf};
use walkdir::{WalkDir, DirEntry};
use regex::Regex;
use std::collections::HashSet;
use crate::data::{SearchType, Hashed, IocEntryId, IocId};
use crate::ioc_evaluator::{IocEntrySearchResult, IocEntrySearchError};


//#[derive(Clone)]
pub struct FileParameters {
    pub ioc_id: IocId,
    pub ioc_entry_id: IocEntryId,
    pub search_type: SearchType,
    pub file_path_or_name: String,
    pub hash: Option<Hashed>,
}

pub fn check_files(search_parameters: &Vec<FileParameters>) -> Vec<Result<IocEntrySearchResult, IocEntrySearchError>> {
    info!("Searching IOCs using file search.");
    let search_by_exact = search_parameters.iter().filter(
        |search_parameter|
            match search_parameter.search_type {
                SearchType::Exact => true,
                _ => false
            });
    let ok_results = search_by_exact.filter_map(|search_parameter| {
        check_file_by_hash(
            &search_parameter.hash,
            Path::new(search_parameter.file_path_or_name.as_str()),
            search_parameter.ioc_id,
            search_parameter.ioc_entry_id,
        )
    });
    let results = ok_results.collect::<Vec<Result<IocEntrySearchResult, IocEntrySearchError>>>();
    if search_parameters.len() == results.len() {
        info!("Found {} IOCs out of {} search parameters", results.len(), search_parameters.len());
        return results;
    }
    info!("Found only {} IOCs out of {} search parameters, starting deep search.", results.len(), search_parameters.len());
    let roots = all_drives();
    let deep_results = roots.iter()
        .flat_map(|root| find_files(root, search_parameters));

    let final_results = results.into_iter().chain(deep_results.into_iter()).collect::<Vec<Result<IocEntrySearchResult, IocEntrySearchError>>>();
    return final_results;
}

fn find_files(path: &Path, search_parameters: &[FileParameters]) -> Vec<Result<IocEntrySearchResult, IocEntrySearchError>> {
    debug!("Searching files in {}", path.display());

    let walker = WalkDir::new(path);
    let walker_iter = walker.into_iter();
    let ok_entries = walker_iter.filter_map(Result::ok);
    let files = ok_entries.filter(|entry| entry.file_type().is_file());

    let mut found_file_parameters = HashSet::<usize>::new();
    let mut result = Vec::<Result<IocEntrySearchResult, IocEntrySearchError>>::new();
    for file_entry in files {
        for (i, search_parameter) in search_parameters.iter().enumerate() {
            if !found_file_parameters.contains(&i) {
                let maybe_query_result = match search_parameter.search_type {
                    SearchType::Exact => { check_file_by_name(search_parameter, &file_entry) }
                    SearchType::Regex => { check_file_by_regex(search_parameter, &file_entry) }
                };
                match maybe_query_result {
                    None => {}
                    Some(query_result) => {
                        found_file_parameters.insert(i);
                        result.push(query_result)
                    }
                }
            }
        }
    }
    result
}


fn check_file_by_name(search_parameter: &FileParameters, file_entry: &DirEntry) -> Option<Result<IocEntrySearchResult, IocEntrySearchError>> {
    let searched_path = Path::new(search_parameter.file_path_or_name.as_str());
    let file_entry_path = file_entry.path();
    debug!("Checking file paths {} and {} by match", searched_path.display(), file_entry_path.display());

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
        search_parameter.ioc_entry_id
    )
}

fn check_file_by_regex(
    search_parameter: &FileParameters,
    file_entry: &DirEntry,
) -> Option<Result<IocEntrySearchResult, IocEntrySearchError>> {
    let searched_path = search_parameter.file_path_or_name.as_str();
    debug!("Checking file paths {} and {} by regex", searched_path, file_entry.path().display());
    let regex_path = Regex::new(searched_path);
    if regex_path.is_err() {
        error!("Cannot parse file path {} as regex: {}", searched_path, regex_path.unwrap_err());
        return None;
    }
    let regex_path = regex_path.unwrap();

    let file_path_matched = regex_path.is_match(file_entry.path().to_str().unwrap_or_default());
    let file_path_empty = searched_path.is_empty();
    let file_name_matched = regex_path.is_match(file_entry.file_name().to_str().unwrap_or_default());

    debug!("Regex match by file paths {} and {} successful: {}", searched_path, file_entry.path().display(), file_path_matched);
    debug!("Regex match by file name {} and {:?} successful: {}", searched_path, file_entry.file_name(), file_name_matched);

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
) -> Option<Result<IocEntrySearchResult, IocEntrySearchError>> {
    debug!("Checking if file {} is IOC by hash", file_path.display());
    match searched_hash {
        None => {
            debug!("No hash for file {} specified, considering it as IOC", file_path.display());
            let ioc_data = String::from(file_path.to_string_lossy());
            Some(Ok(
                IocEntrySearchResult {
                    ioc_id,
                    ioc_entry_id,
                    data: vec![ioc_data],
                }
            ))
        }
        Some(searched_hash) => {
            debug!("Compare specified {} hash of {} with file {}",
                   searched_hash.algorithm,
                   searched_hash.value,
                   file_path.display()
            );
            let file_hash = Hasher::new(searched_hash.algorithm.clone()).hash_file_by_path(file_path);
            match file_hash {
                Ok(file_hash) => {
                    if file_hash == *searched_hash {
                        Some(Ok(
                            IocEntrySearchResult {
                                ioc_id,
                                ioc_entry_id,
                                data: vec![
                                    String::from(file_path.to_string_lossy()),
                                    file_hash.value
                                ],
                            }
                        ))
                    } else {
                        debug!("Hashes does not match. Expected {} != {} found", searched_hash.value, file_hash.value);
                        None
                    }
                }
                Err(error) => {
                    error!("Cannot compute {} hash of \"{}\": {}",
                           searched_hash.algorithm,
                           file_path.display(),
                           error
                    );
                    Some(Err(error.to_ioc_error(ioc_id, ioc_entry_id)))
                }
            }
        }
    }
}

/// Source: https://stackoverflow.com/questions/33654653/efficient-approach-to-get-all-logical-drive-letters-of-hdd-and-collect-root-dirs
#[cfg(windows)]
fn all_drives() -> Vec<PathBuf> {
    let mut logical_drives = Vec::<PathBuf>::new();
    let mut bitfield = unsafe { kernel32::GetLogicalDrives() };
    let mut drive = 'A';

    while bitfield != 0 {
        if bitfield & 1 == 1 {
            let strfulldl = drive.to_string() + ":\\";
            let cstrfulldl = CString::new(strfulldl.clone()).unwrap();

            let x = unsafe { kernel32::GetDriveTypeA(cstrfulldl.as_ptr()) };
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