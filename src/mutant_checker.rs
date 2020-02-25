#[cfg(windows)]
extern crate winapi;

//use crate::query_result;
use crate::data::{IocEntryId, IocId};
use std::ffi::CString;
use std::ptr;
#[cfg(windows)]
use winapi::ctypes::c_void;
use crate::ioc_evaluator::{IocEntrySearchResult, IocEntrySearchError};
#[cfg(windows)]
use crate::windows_bindings::PoolType;
#[cfg(windows)]
use crate::priv_esca::{drop_privileges, get_privileges};

#[cfg(windows)]
#[repr(C)]
struct SystemHandle {
    process_id: winapi::shared::minwindef::ULONG,
    object_type_number: winapi::shared::minwindef::BYTE,
    flags: winapi::shared::minwindef::BYTE,
    handle: winapi::shared::minwindef::USHORT,
    object: winapi::shared::ntdef::PVOID,
    access_mask: winapi::um::winnt::ACCESS_MASK,
}

#[cfg(windows)]
#[repr(C)]
struct SystemHandleInformation {
    number_of_handles: winapi::shared::minwindef::ULONG,
    handles: [SystemHandle; 1], // [SystemHandle; 1]
}

#[cfg(windows)]
#[allow(dead_code)]
struct ObjectTypeInformation {
    name: winapi::shared::ntdef::UNICODE_STRING,

    objects_total_count: winapi::shared::minwindef::ULONG,
    handles_total_count: winapi::shared::minwindef::ULONG,
    paged_pool_usage_total_count: winapi::shared::minwindef::ULONG,
    non_paged_pool_usage_total_count: winapi::shared::minwindef::ULONG,
    name_pool_usage_total_count: winapi::shared::minwindef::ULONG,
    handle_table_usage_total_count: winapi::shared::minwindef::ULONG,

    objects_high_water_count: winapi::shared::minwindef::ULONG,
    handles_high_water_count: winapi::shared::minwindef::ULONG,
    paged_pool_usage_high_water_count: winapi::shared::minwindef::ULONG,
    non_paged_pool_usage_high_water_count: winapi::shared::minwindef::ULONG,
    name_pool_usage_high_water_count: winapi::shared::minwindef::ULONG,
    handle_table_usage_high_water_count: winapi::shared::minwindef::ULONG,

    invalid_attributes: winapi::shared::minwindef::ULONG,
    generic_mapping: winapi::um::winnt::GENERIC_MAPPING,
    valid_access: winapi::shared::minwindef::ULONG,
    security_required: winapi::shared::minwindef::BOOL,
    maintain_handle_count: winapi::shared::minwindef::INT,
    maintain_type_list: winapi::shared::minwindef::INT,
    pool_type: PoolType,
    paged_pool_usage: winapi::shared::minwindef::ULONG,
    non_paged_pool_usage: winapi::shared::minwindef::ULONG,
}

#[cfg(windows)]
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xc0000004;
#[cfg(windows)]
const SYSTEM_HANDLE_INFORMATION: u32 = 16;


#[cfg(windows)]
type NtQuerySystemInformation = Option<extern "system" fn(
    system_information_flags: winapi::shared::minwindef::ULONG,
    system_information: winapi::shared::ntdef::PVOID,
    system_information_length: winapi::shared::minwindef::ULONG,
    return_length: winapi::shared::minwindef::PULONG,
) -> winapi::shared::ntdef::NTSTATUS>; // or extern "sdtcall"

#[cfg(windows)]
#[allow(dead_code)]
enum ObjectInformationClass {
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectAllInformation,
    ObjectDataInformation,
}

#[cfg(windows)]
type NtQueryObject = Option<extern "system" fn(
    handle: winapi::shared::ntdef::HANDLE,
    object_information_class: ObjectInformationClass,
    object_information: winapi::shared::ntdef::PVOID,
    object_information_length: winapi::shared::minwindef::ULONG,
    return_length: winapi::shared::minwindef::PULONG,
) -> winapi::shared::ntdef::NTSTATUS>; // or extern "sdtcall"

#[cfg(windows)]
type NtDuplicateObject = Option<extern "system" fn(
    source_process_handle: winapi::shared::ntdef::HANDLE,
    source_handle: winapi::shared::ntdef::HANDLE,
    target_process_handle: winapi::shared::ntdef::HANDLE,
    target_handle: winapi::shared::ntdef::HANDLE,
    desired_access: winapi::um::winnt::ACCESS_MASK,
    attributes: winapi::shared::minwindef::ULONG,
    options: winapi::shared::minwindef::ULONG,
) -> winapi::shared::ntdef::NTSTATUS>; // or extern "sdtcall"

pub struct MutexParameters {
    pub ioc_entry_id: IocEntryId,
    pub ioc_id: IocId,
    pub data: String,
}

#[cfg(windows)]
pub fn check_mutexes(search_parameters: Vec<MutexParameters>) -> Vec<Result<IocEntrySearchResult, IocEntrySearchError>> {
    if search_parameters.is_empty() { return vec![] }
    info!("Searching IOCs using open mutex search.");
    let mut ioc_results = Vec::<Result<IocEntrySearchResult, IocEntrySearchError>>::new();
    let mut errors = Vec::<String>::new();
    unsafe {
        let ntdll_name = CString::new("ntdll.dll").unwrap();
        let ntdll = winapi::um::libloaderapi::GetModuleHandleA(ntdll_name.as_ptr());

        let function_name = CString::new("NtQuerySystemInformation").unwrap();
        let farproc = winapi::um::libloaderapi::GetProcAddress(ntdll, function_name.as_ptr());
        let query_system_information_fn = std::mem::transmute::<winapi::shared::minwindef::FARPROC, NtQuerySystemInformation>(farproc);
        if query_system_information_fn.is_none() {
            let err = format!("Cannot load function NtQuerySystemInformation");
            error!("{}", err);
            errors.push(err);
            return process_results(&search_parameters, ioc_results, errors);
        }
        let query_system_information_fn = query_system_information_fn.unwrap();

        let function_name = CString::new("NtQueryObject").unwrap();
        let farproc = winapi::um::libloaderapi::GetProcAddress(ntdll, function_name.as_ptr());
        let query_object_fn = std::mem::transmute::<winapi::shared::minwindef::FARPROC, NtQueryObject>(farproc);
        if query_object_fn.is_none() {
            let err = format!("Cannot load function NtQueryObject");
            error!("{}", err);
            errors.push(err);
            return process_results(&search_parameters, ioc_results, errors);
        }
        let query_object_fn = query_object_fn.unwrap();

        let function_name = CString::new("NtDuplicateObject").unwrap();
        let farproc = winapi::um::libloaderapi::GetProcAddress(ntdll, function_name.as_ptr());
        let duplicate_object_fn = std::mem::transmute::<winapi::shared::minwindef::FARPROC, NtDuplicateObject>(farproc);
        if duplicate_object_fn.is_none() {
            let err = format!("Cannot load function NtDuplicateObject");
            error!("{}", err);
            errors.push(err);
            return process_results(&search_parameters, ioc_results, errors);
        }
        let duplicate_object_fn = duplicate_object_fn.unwrap();

        let gp = get_privileges(winapi::um::winnt::SE_DEBUG_NAME);
        if gp.is_err() { error!("{}", gp.unwrap_err()) }

        let mut buffer_length = 1000usize;

        let mut shi = winapi::um::memoryapi::VirtualAlloc(
            ptr::null_mut(),
            buffer_length,
            winapi::um::winnt::MEM_COMMIT | winapi::um::winnt::MEM_RESERVE,
            winapi::um::winnt::PAGE_READWRITE,
        ) as *mut SystemHandleInformation;
        let mut return_length = 1000u32;
//        let mut ntstatus = MaybeUninit::<winapi::shared::ntdef::VOID>::uninit();

        while (query_system_information_fn(
            SYSTEM_HANDLE_INFORMATION,
            shi as winapi::shared::ntdef::HANDLE,
            buffer_length as u32,
            &mut return_length,
        ) as u32) == STATUS_INFO_LENGTH_MISMATCH {
            winapi::um::memoryapi::VirtualFree(
                shi as winapi::shared::ntdef::HANDLE,
                0,
                winapi::um::winnt::MEM_FREE,
            );
            buffer_length *= 2;
            shi = winapi::um::memoryapi::VirtualAlloc(
                ptr::null_mut(),
                buffer_length,
                winapi::um::winnt::MEM_COMMIT | winapi::um::winnt::MEM_RESERVE,
                winapi::um::winnt::PAGE_READWRITE,
            ) as *mut SystemHandleInformation;
        }
        for i in 0..((*shi).number_of_handles as usize) {
            let handle: *mut SystemHandle = (*shi).handles.as_mut_ptr().add(i);
            let handle_val = (*handle).handle;
            let pid = (*handle).process_id;
            let process_handle = winapi::um::processthreadsapi::OpenProcess(
                winapi::um::winnt::PROCESS_DUP_HANDLE,
                0, // false
                pid,
            );
            if process_handle.is_null() {
                continue;
            }
            let dup_handle: winapi::shared::ntdef::HANDLE = ptr::null_mut();
            let dup_result = duplicate_object_fn(
                process_handle,
                handle_val as *mut c_void,
                winapi::um::processthreadsapi::GetCurrentProcess(),
                dup_handle,
                0,
                0,
                0,
            );
            if dup_result != 0 {
                winapi::um::handleapi::CloseHandle(process_handle);
                continue;
            }

            return_length = 0u32;
            query_object_fn(
                dup_handle,
                ObjectInformationClass::ObjectTypeInformation,
                ptr::null_mut(),
                0,
                &mut return_length,
            );

            let object_type_info = winapi::um::memoryapi::VirtualAlloc(
                ptr::null_mut(),
                return_length as usize,
                winapi::um::winnt::MEM_COMMIT | winapi::um::winnt::MEM_RESERVE,
                winapi::um::winnt::PAGE_READWRITE,
            ) as *mut ObjectTypeInformation;

            let mut ret = 0u32;
            if query_object_fn(dup_handle,
                               ObjectInformationClass::ObjectTypeInformation,
                               object_type_info as *mut c_void,
                               return_length,
                               &mut ret) != 0 {
                let err = format!("NtQueryObject failed, error code {}", winapi::um::errhandlingapi::GetLastError());
                error!("{}", err);
                errors.push(err);
                winapi::um::handleapi::CloseHandle(dup_handle);
                winapi::um::handleapi::CloseHandle(process_handle);
            }

            let ws = widestring::WideString::from_ptr(
                (*object_type_info).name.Buffer,
                (*object_type_info).name.Length as usize,
            );
            if ws != widestring::WideString::from("Mutant".to_string()) {
                winapi::um::memoryapi::VirtualFree(
                    object_type_info as *mut c_void,
                    0,
                    winapi::um::winnt::MEM_RELEASE,
                );
                winapi::um::handleapi::CloseHandle(dup_handle);
                winapi::um::handleapi::CloseHandle(process_handle);
                continue;
            }

            query_object_fn(
                dup_handle,
                ObjectInformationClass::ObjectTypeInformation,
                ptr::null_mut(),
                0,
                &mut return_length,
            );

            let object_name_info = winapi::um::memoryapi::VirtualAlloc(
                ptr::null_mut(),
                return_length as usize,
                winapi::um::winnt::MEM_COMMIT | winapi::um::winnt::MEM_RESERVE,
                winapi::um::winnt::PAGE_READWRITE,
            );

            if query_object_fn(
                dup_handle,
                ObjectInformationClass::ObjectNameInformation,
                object_name_info,
                return_length,
                ptr::null_mut(),
            ) != 0 {
                let err = format!("Fetch name failed");
                error!("{}", err);
                errors.push(err);
                winapi::um::memoryapi::VirtualFree(
                    object_name_info,
                    0,
                    winapi::um::winnt::MEM_RELEASE,
                );
                winapi::um::handleapi::CloseHandle(dup_handle);
                winapi::um::handleapi::CloseHandle(process_handle);
            }

            let name = object_name_info as winapi::shared::ntdef::PUNICODE_STRING;
            if (*name).Length != 0 {
                let wss = widestring::WideString::from_ptr((*name).Buffer, (*name).Length as usize);
                let ss = wss.to_string_lossy(); // Beware possible data loss.
                search_parameters.iter()
                    .filter(|search_parameter| {
                        ss.contains(&search_parameter.data)
                    }).for_each(|search_parameter| ioc_results.push(Ok(IocEntrySearchResult {
                    ioc_id: search_parameter.ioc_id,
                    ioc_entry_id: search_parameter.ioc_entry_id,
                    data: vec![format!("Mutex {}", ss)],
                })));
            }
            winapi::um::memoryapi::VirtualFree(
                object_type_info as *mut c_void,
                0,
                winapi::um::winnt::MEM_RELEASE,
            );
            winapi::um::memoryapi::VirtualFree(
                object_name_info,
                0,
                winapi::um::winnt::MEM_RELEASE,
            );
            winapi::um::handleapi::CloseHandle(dup_handle);
            winapi::um::handleapi::CloseHandle(process_handle);
        }
        winapi::um::memoryapi::VirtualFree(
            shi as *mut c_void,
            0,
            winapi::um::winnt::MEM_RELEASE,
        );
        let gp = drop_privileges(winapi::um::winnt::SE_DEBUG_NAME);
        if gp.is_err() { error!("{}", gp.unwrap_err()) }
    }
    process_results(&search_parameters, ioc_results, errors)
}

fn process_results(search_parameters: &Vec<MutexParameters>, mut ioc_results: Vec<Result<IocEntrySearchResult, IocEntrySearchError>>, errors: Vec<String>) -> Vec<Result<IocEntrySearchResult, IocEntrySearchError>> {
    if !search_parameters.is_empty() {
        errors.into_iter().for_each(|error| ioc_results.push(Err(IocEntrySearchError {
            kind: "Win32 Error".to_string(),
            message: error,
        })));
    }
    ioc_results
}

#[cfg(not(windows))]
pub fn check_mutexes(search_parameters: Vec<MutexParameters>) -> Vec<Result<IocEntrySearchResult, IocEntrySearchError>> {
    return vec![];
}

