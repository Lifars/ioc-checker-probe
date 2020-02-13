extern crate dirs;

use std::env;
use std::path::PathBuf;

//#[cfg(windows)]
//pub fn resolve(path: String, path_is_regex: bool = false) -> String {
//    let maybe_resolved = resolve_one(
//        path,
//        "%APPDATA%",
//        &dirs::data_dir()
//    );
//    let maybe_resolved = resolve_one(
//        maybe_resolved,
//        "%AppData%",
//        &dirs::data_dir()
//    );
//    let maybe_resolved = resolve_one(
//        maybe_resolved,
//        "%ALLUSERSPROFILE%",
//        &Some(PathBuf::from("C:/ProgramData".to_string()))
//    );
//    let maybe_resolved = resolve_one(
//        maybe_resolved,
//        "%AllUsersProfile%",
//        &Some(PathBuf::from("C:/ProgramData".to_string()))
//    );
//    let maybe_resolved = resolve_one(
//        maybe_resolved,
//        "%COMMONPROGRAMFILES%",
//        &Some(PathBuf::from("C:/Program Files/Common Files".to_string()))
//    );
//    let maybe_resolved = resolve_one(
//        maybe_resolved,
//        "%COMMONPROGRAMFILES(x86)%",
//        &Some(PathBuf::from("C:/Program Files (x86)/Common Files".to_string()))
//    );
//    let maybe_resolved = resolve_one(
//        maybe_resolved,
//        "%LOCALAPPDATA%",
//        &dirs::data_local_dir()
//    );
//    let maybe_resolved = resolve_one(
//        maybe_resolved,
//        "%LocalAppData%",
//        &dirs::data_local_dir()
//    );
//    let maybe_resolved = resolve_one(
//        maybe_resolved,
//        "%PROGRAMFILES%",
//        &Some(PathBuf::from("C:/Program Files".to_string()))
//    );
//    let maybe_resolved = resolve_one(
//        maybe_resolved,
//        "%PROGRAMFILES(x86)%",
//        &Some(PathBuf::from("C:/Program Files (x86)".to_string()))
//    );
//    let maybe_resolved = resolve_one(
//        maybe_resolved,
//        "%ProgramFiles%",
//        &Some(PathBuf::from("C:/Program Files".to_string()))
//    );
//    let maybe_resolved = resolve_one(
//        maybe_resolved,
//        "%ProgramFiles(x86)%",
//        &Some(PathBuf::from("C:/Program Files (x86)".to_string()))
//    );
//    let maybe_resolved = resolve_one(
//        maybe_resolved,
//        "%ProgramData%",
//        &Some(PathBuf::from("C:/ProgramData".to_string()))
//    );
//    let maybe_resolved = resolve_one(
//        maybe_resolved,
//        "%PROGRAMDATA%",
//        &Some(PathBuf::from("C:/ProgramData".to_string()))
//    );
//    let maybe_resolved = resolve_one(
//        maybe_resolved,
//        "%Public%",
//        &Some(PathBuf::from("C:/ProgramData".to_string()))
//    );
//    let maybe_resolved = resolve_one(
//        maybe_resolved,
//        "%PUBLIC%",
//        &Some(PathBuf::from("C:/Users/Public".to_string()))
//    );
//    let maybe_resolved = resolve_one(
//        maybe_resolved,
//        "%HomeDrive%",
//        &Some(PathBuf::from("C:".to_string()))
//    );
//    let maybe_resolved = resolve_one(
//        maybe_resolved,
//        "%HOMEDRIVE%",
//        &Some(PathBuf::from("C:".to_string()))
//    );
//    let maybe_resolved = resolve_one(
//        maybe_resolved,
//        "%SystemDrive%",
//        &Some(PathBuf::from("C:".to_string()))
//    );
//    let maybe_resolved = resolve_one(
//        maybe_resolved,
//        "%SYSTEMDRIVE%",
//        &Some(PathBuf::from("C:".to_string()))
//    );
//    let maybe_resolved = resolve_one(
//        maybe_resolved,
//        "%SystemRoot%",
//        &Some(PathBuf::from("C:/Windows".to_string()))
//    );
//    let maybe_resolved = resolve_one(
//        maybe_resolved,
//        "%SYSTEMROOT%",
//        &Some(PathBuf::from("C:/Windows".to_string()))
//    );
//    let maybe_resolved = resolve_one(
//        maybe_resolved,
//        "%UserProfile%",
//        &dirs::home_dir()
//    );
//    let maybe_resolved = resolve_one(
//        maybe_resolved,
//        "%USERPROFILE%",
//        &dirs::home_dir()
//    );
//    let maybe_resolved = resolve_one(
//        maybe_resolved,
//        "%Temp%",
//        &Some(env::temp_dir())
//    );
//    let maybe_resolved = resolve_one(
//        maybe_resolved,
//        "%TEMP%",
//        &Some(env::temp_dir())
//    );
//    maybe_resolved
//}
//
//#[cfg(not(windows))]
//pub fn resolve(path: PathBuf) -> PathBuf {
//    path
//}
//
//fn resolve_one(
//    path: String,
//    prefix: &str,
//    prefix_resolved: Option<String>,
//    path_is_regex: bool
//) -> String {
//    if !path.starts_with(prefix) {
//        return path
//    }
//    match prefix_resolved {
//        None => path,
//        Some(prefix_resolved) => {
//            let prefix_resolved = if path_is_regex {
//                prefix_resolved.replace("\\", "\\\\");
//            }else {
//                prefix_resolved
//            };
//            path.replace(prefix, prefix_resolved.)
//        }
//    }
//}

#[cfg(windows)]
pub fn resolve(path: PathBuf) -> PathBuf {
    let maybe_resolved = resolve_one(
        path,
        "%APPDATA%",
        &dirs::data_dir()
    );
    let maybe_resolved = resolve_one(
        maybe_resolved,
        "%AppData%",
        &dirs::data_dir()
    );
    let maybe_resolved = resolve_one(
        maybe_resolved,
        "%ALLUSERSPROFILE%",
        &Some(PathBuf::from("C:/ProgramData".to_string()))
    );
    let maybe_resolved = resolve_one(
        maybe_resolved,
        "%AllUsersProfile%",
        &Some(PathBuf::from("C:/ProgramData".to_string()))
    );
    let maybe_resolved = resolve_one(
        maybe_resolved,
        "%COMMONPROGRAMFILES%",
        &Some(PathBuf::from("C:/Program Files/Common Files".to_string()))
    );
    let maybe_resolved = resolve_one(
        maybe_resolved,
        "%COMMONPROGRAMFILES(x86)%",
        &Some(PathBuf::from("C:/Program Files (x86)/Common Files".to_string()))
    );
    let maybe_resolved = resolve_one(
        maybe_resolved,
        "%LOCALAPPDATA%",
        &dirs::data_local_dir()
    );
    let maybe_resolved = resolve_one(
        maybe_resolved,
        "%LocalAppData%",
        &dirs::data_local_dir()
    );
    let maybe_resolved = resolve_one(
        maybe_resolved,
        "%PROGRAMFILES%",
        &Some(PathBuf::from("C:/Program Files".to_string()))
    );
    let maybe_resolved = resolve_one(
        maybe_resolved,
        "%PROGRAMFILES(x86)%",
        &Some(PathBuf::from("C:/Program Files (x86)".to_string()))
    );
    let maybe_resolved = resolve_one(
        maybe_resolved,
        "%ProgramFiles%",
        &Some(PathBuf::from("C:/Program Files".to_string()))
    );
    let maybe_resolved = resolve_one(
        maybe_resolved,
        "%ProgramFiles(x86)%",
        &Some(PathBuf::from("C:/Program Files (x86)".to_string()))
    );
    let maybe_resolved = resolve_one(
        maybe_resolved,
        "%ProgramData%",
        &Some(PathBuf::from("C:/ProgramData".to_string()))
    );
    let maybe_resolved = resolve_one(
        maybe_resolved,
        "%PROGRAMDATA%",
        &Some(PathBuf::from("C:/ProgramData".to_string()))
    );
    let maybe_resolved = resolve_one(
        maybe_resolved,
        "%Public%",
        &Some(PathBuf::from("C:/ProgramData".to_string()))
    );
    let maybe_resolved = resolve_one(
        maybe_resolved,
        "%PUBLIC%",
        &Some(PathBuf::from("C:/Users/Public".to_string()))
    );
    let maybe_resolved = resolve_one(
        maybe_resolved,
        "%HomeDrive%",
        &Some(PathBuf::from("C:".to_string()))
    );
    let maybe_resolved = resolve_one(
        maybe_resolved,
        "%HOMEDRIVE%",
        &Some(PathBuf::from("C:".to_string()))
    );
    let maybe_resolved = resolve_one(
        maybe_resolved,
        "%SystemDrive%",
        &Some(PathBuf::from("C:".to_string()))
    );
    let maybe_resolved = resolve_one(
        maybe_resolved,
        "%SYSTEMDRIVE%",
        &Some(PathBuf::from("C:".to_string()))
    );
    let maybe_resolved = resolve_one(
        maybe_resolved,
        "%SystemRoot%",
        &Some(PathBuf::from("C:/Windows".to_string()))
    );
    let maybe_resolved = resolve_one(
        maybe_resolved,
        "%SYSTEMROOT%",
        &Some(PathBuf::from("C:/Windows".to_string()))
    );
    let maybe_resolved = resolve_one(
        maybe_resolved,
        "%UserProfile%",
        &dirs::home_dir()
    );
    let maybe_resolved = resolve_one(
        maybe_resolved,
        "%USERPROFILE%",
        &dirs::home_dir()
    );
    let maybe_resolved = resolve_one(
        maybe_resolved,
        "%Temp%",
        &Some(env::temp_dir())
    );
    let maybe_resolved = resolve_one(
        maybe_resolved,
        "%TEMP%",
        &Some(env::temp_dir())
    );
    maybe_resolved
//    let unix_path = maybe_resolved.to_string_lossy().replace("\\", "/");
//    PathBuf::from(unix_path)
}

#[cfg(not(windows))]
pub fn resolve(path: PathBuf) -> PathBuf {
    path
}

fn resolve_one(path: PathBuf, prefix: &str, prefix_resolved: &Option<PathBuf>) -> PathBuf {
    if !path.starts_with(prefix) {
        return path
    }
    match prefix_resolved {
        None => path,
        Some(prefix_resolved) => prefix_resolved.join(path.strip_prefix(prefix).unwrap())
    }
}
