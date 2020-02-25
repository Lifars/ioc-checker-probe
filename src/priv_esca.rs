use std::mem::MaybeUninit;
use std::ptr;
use std::ffi::CString;

#[cfg(windows)]
pub unsafe fn set_privilege(
    token: winapi::shared::ntdef::HANDLE,
    privilege: &str,
    enable_privilege: bool,
) -> Result<(), std::io::Error> {
    let mut luid = MaybeUninit::<winapi::shared::ntdef::LUID>::uninit();

    let privilege_c_str = CString::new(privilege.clone());
    if privilege_c_str.is_err() {
        return Err(std::io::Error::new(std::io::ErrorKind::Other,
                                       format!(
                                           "Cannot convert string {} to C string. {}", privilege, privilege_c_str.unwrap_err()), ));
    }
    let privilege_c_str = privilege_c_str.unwrap();
    if winapi::um::winbase::LookupPrivilegeValueA(
        ptr::null(),
        privilege_c_str.as_ptr(),
        luid.as_mut_ptr(),
    ) == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other,
                                       format!(
                                           "Cannot acquire {}. Win32 function LookupPrivilegeValueA failed. System error code {}",
                                           privilege,
                                           winapi::um::errhandlingapi::GetLastError()), ));
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

    let error_code = winapi::um::errhandlingapi::GetLastError();
    if error_code != winapi::shared::winerror::ERROR_SUCCESS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Cannot adjust user privileges in pass 1/2. System error code {}", error_code))
        );
    }

    let mut tp_previous = tp_previous.assume_init();
    tp_previous.PrivilegeCount = 1;
    tp_previous.Privileges[0].Luid = luid;

    if enable_privilege {
        tp_previous.Privileges[0].Attributes |= winapi::um::winnt::SE_PRIVILEGE_ENABLED
    } else {
        tp_previous.Privileges[0].Attributes ^=
            winapi::um::winnt::SE_PRIVILEGE_ENABLED & tp_previous.Privileges[0].Attributes
    }

    winapi::um::securitybaseapi::AdjustTokenPrivileges(
        token,
        0, // false
        &mut tp_previous,
        cb_previous,
        ptr::null_mut(),
        ptr::null_mut(),
    );

    let error_code = winapi::um::errhandlingapi::GetLastError();
    if error_code != winapi::shared::winerror::ERROR_SUCCESS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Cannot adjust user privileges in pass 1/2. System error code {}", error_code))
        );
    }
    Ok(())
}

#[cfg(windows)]
pub unsafe fn get_privileges(privilege: &str) -> Result<(), std::io::Error> {
    let mut token: winapi::shared::ntdef::HANDLE = ptr::null_mut();
    let current_process_handle = winapi::um::processthreadsapi::GetCurrentProcess();
    let opt_r = winapi::um::processthreadsapi::OpenProcessToken(current_process_handle,
                                                                winapi::um::winnt::TOKEN_ADJUST_PRIVILEGES | winapi::um::winnt::TOKEN_QUERY,
                                                                &mut token);

    if opt_r == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Cannot open process token"));
    }
    debug!("Token of this process is {}", token as i32);
    let sp_r = set_privilege(token, privilege, true);
    winapi::um::handleapi::CloseHandle(token);
    return sp_r;
}

#[cfg(windows)]
pub unsafe fn drop_privileges(privilege: &str) -> Result<(), std::io::Error> {
    let mut token: winapi::shared::ntdef::HANDLE = ptr::null_mut();
    let current_process_handle = winapi::um::processthreadsapi::GetCurrentProcess();
    let opt_r = winapi::um::processthreadsapi::OpenProcessToken(current_process_handle,
                                                                winapi::um::winnt::TOKEN_ADJUST_PRIVILEGES | winapi::um::winnt::TOKEN_QUERY,
                                                                &mut token);

    if opt_r == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Cannot open process token"));
    }
    let sp_r = set_privilege(token, privilege, false);
    winapi::um::handleapi::CloseHandle(token);
    return sp_r;
}
