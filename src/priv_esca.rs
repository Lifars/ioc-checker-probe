use std::mem::MaybeUninit;
use std::{ptr, mem};
use std::io::Error;

#[cfg(windows)]
pub unsafe fn set_privilege(
    token: winapi::shared::ntdef::HANDLE,
    privilege: &str,
    enable_privilege: bool,
) -> Result<(), std::io::Error> {
    let mut luid = MaybeUninit::<winapi::shared::ntdef::LUID>::uninit();
    let privilege_c_str: &[i8] = mem::transmute(privilege.as_bytes());

    if winapi::um::winbase::LookupPrivilegeValueA(
        ptr::null(),
        privilege_c_str.as_ptr(),
        luid.as_mut_ptr(),
    ) == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other,
                                       format!(
                                           "Cannot acquire {}. privilege lookup failed. System error code: {}",
                                           privilege,
                                           winapi::um::errhandlingapi::GetLastError()),));
    }
    let luid = luid.assume_init();
    let mut tp = winapi::um::winnt::TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [
            winapi::um::winnt::LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: 0,
            }
        ],
    };

    let mut tp_previous = MaybeUninit::<winapi::um::winnt::TOKEN_PRIVILEGES>::uninit();
    let mut cb_previous = std::mem::size_of::<winapi::um::winnt::TOKEN_PRIVILEGES>() as u32;
    winapi::um::securitybaseapi::AdjustTokenPrivileges(
        token,
        0, // false
        &mut tp,
        std::mem::size_of::<winapi::um::winnt::TOKEN_PRIVILEGES>() as u32,
        tp_previous.as_mut_ptr(),
        &mut cb_previous,
    );

    if winapi::um::errhandlingapi::GetLastError() != winapi::shared::winerror::ERROR_SUCCESS {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Cannot adjust user privileges in pass 1/2"));
    }

    let mut tp_previous = tp_previous.assume_init();
    tp_previous.PrivilegeCount = 1;
    tp_previous.Privileges[0].Luid = luid;

    if enable_privilege {
        tp_previous.Privileges[0].Attributes |= winapi::um::winnt::SE_PRIVILEGE_ENABLED
    } else {
        tp_previous.Privileges[0].Attributes ^=
            (winapi::um::winnt::SE_PRIVILEGE_ENABLED & tp_previous.Privileges[0].Attributes)
    }

    winapi::um::securitybaseapi::AdjustTokenPrivileges(
        token,
        0, // false
        &mut tp_previous,
        cb_previous,
        ptr::null_mut(),
        ptr::null_mut(),
    );

    if winapi::um::errhandlingapi::GetLastError() != winapi::shared::winerror::ERROR_SUCCESS {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Cannot adjust user privileges in pass 2/2"));
    }
    Ok(())
}

#[cfg(windows)]
pub unsafe fn get_privileges(privilege: &str) -> Result<(), std::io::Error> {
    let mut token = MaybeUninit::<winapi::shared::ntdef::VOID>::uninit();
    let mut current_process_handle = winapi::um::processthreadsapi::GetCurrentProcess();
    let opt_r = winapi::um::processthreadsapi::OpenProcessToken(current_process_handle,
                                                                winapi::um::winnt::TOKEN_ADJUST_PRIVILEGES | winapi::um::winnt::TOKEN_QUERY,
                                                                &mut token.as_mut_ptr());

    if opt_r == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Cannot open process token"));
    }
    let sp_r = set_privilege(token.as_mut_ptr(), privilege, true);
    winapi::um::handleapi::CloseHandle(token.as_mut_ptr());
    return sp_r;
}

#[cfg(windows)]
pub unsafe fn drop_privileges(privilege: &str) -> Result<(), std::io::Error> {
    let mut token = MaybeUninit::<winapi::shared::ntdef::VOID>::uninit();
    let mut current_process_handle = winapi::um::processthreadsapi::GetCurrentProcess();
    let opt_r = winapi::um::processthreadsapi::OpenProcessToken(current_process_handle,
                                                                winapi::um::winnt::TOKEN_ADJUST_PRIVILEGES | winapi::um::winnt::TOKEN_QUERY,
                                                                &mut token.as_mut_ptr());

    if opt_r == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Cannot open process token"));
    }
    let sp_r = set_privilege(token.as_mut_ptr(), privilege, false);
    winapi::um::handleapi::CloseHandle(token.as_mut_ptr());
    return sp_r;
}
