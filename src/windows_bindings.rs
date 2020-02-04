//#![cfg(windows)]
//extern "system" {
//    pub fn OpenProcessToken(
//        ProcessHandle: winapi::shared::ntdef::HANDLE,
//        DesiredAccess: winapi::shared::minwindef::DWORD,
//        TokenHandle: winapi::shared::ntdef::PHANDLE
//    ) -> winapi::BOOL;
//}

#[cfg(windows)]
pub enum PoolType {
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS,
    MaxPoolType,
    NonPagedPoolSession,
    PagedPoolSession,
    NonPagedPoolMustSucceedSession,
    DontUseThisTypeSession,
    NonPagedPoolCacheAlignedSession,
    PagedPoolCacheAlignedSession,
    NonPagedPoolCacheAlignedMustSSession,
}