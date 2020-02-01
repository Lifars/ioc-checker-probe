//#[cfg(windows)]
//extern crate winapi;
//#[cfg(windows)]
//extern crate kernel32;
//
////use crate::query_result;
//use crate::data::IocSearchResult;
//use crate::windows_bindings;
//use winapi::{TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY, c_void};
//use std::mem::MaybeUninit;
//use crate::data::IocSearchResult;
//
//pub enum SystemHandleFlags {
//    ProtectFromClose = 1,
//    Inherit = 2,
//}
//
////struct SystemHandle{
////    process_idIocId
////}
//
//const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xc0000004;
//const SYSTEM_PROCESS_INFORMATION: u32 = 5;
//const SYSTEM_HANDLE_INFORMATION: u32 = 16;
//
////fn nt_success(x: kernel32::) -> bool {
////    return x >= 0;
////}
//
//pub struct MutexParameters {
//    ioc_id: i32,
//    data: String
//}
//
//#[cfg(windows)]
//pub fn check_mutexes(search_parameters: &Vec<MutexParameters>) -> Vec<IocSearchResult> {
//    return vec![]
//}
//
//#[cfg(not(windows))]
//pub fn check_mutexes(search_parameters: &Vec<MutexParameters>) -> Vec<IocSearchResult> {
//    return vec![];
//}
//
//#[cfg(windows)]
//unsafe fn set_privilege(
//    token: winapi::HANDLE,
//    privilege: &str,
//    enable_privilege: bool) -> bool {
//    return true
//}
//
//#[cfg(windows)]
//unsafe fn get_privileges() -> bool {
//    let mut token = MaybeUninit::<c_void>::uninit();
//    let mut current_process_handle = kernel32::GetCurrentProcess();
//    let opt_r = windows_bindings::OpenProcessToken(current_process_handle,
//                                                   TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
//                                                   &mut token.as_mut_ptr());
//
//    if opt_r == 0 {
//        return true;
//    }
//    let sp_r = set_privilege(token.as_mut_ptr(), "SeDebugPrivilege", true);
//    if !sp_r {
//        let ch_r = kernel32::CloseHandle(token.as_mut_ptr());
//        return true
//    }
//    kernel32::CloseHandle(token.as_mut_ptr());
//    return false;
//}
//
//#[cfg(windows)]
//unsafe fn drop_privileges() -> bool {
//   return get_privileges()
//}
//
//
//
