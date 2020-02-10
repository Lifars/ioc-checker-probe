use crate::data::{IocEntryId, IocId};
use crate::ioc_evaluator::{IocEntrySearchResult, IocEntrySearchError};
use rustls_native_certs::load_native_certs;
use rustls::RootCertStore;

pub struct CertificateParameters {
    pub ioc_id: IocId,
    pub ioc_entry_id: IocEntryId,
//    pub search_type: CertSearchType,
    pub name: String,
}

//enum CertSystemStore {
//    CurrentUserId = 1,
//    LocationMaks = 0x00FF0000,
//    LocationShift = 16,
//    Mask = 0xFFFF0000,
//    RelocateFlag = 0x80000000,
//}
//
//enum CertStoreFlag {
//    PhysicalPredefinedEnum = 0x1,
//    OpenExisting = 0x00004000,
//    ReadOnly = 0x00008000,
//    CloseCheck = 0x00000002,
//}
//
//enum CertFlag {
//    IssuerName = 0x1
//}
//
//enum CertAltNameFlag {
//    Other = 1,
//    Rfc822Name = 2,
//    Dns = 3,
//    X400 = 4,
//    Directory = 5,
//    EdiParty = 6,
//    Url = 7,
//    IpAddress = 8,
//    RegisteredId = 9,
//}
//
//const CRYPT_DECODE_NOCOPY_FLAG: usize = 0x1;

//#[cfg(not(windows))]
//pub fn check_certs(search_parameters: Vec<CertificateParameters>) -> Vec<Result<IocEntrySearchResult, IocEntrySearchError>> {
//    return vec![];
//}
//
//#[cfg(windows)]
pub fn check_certs(search_parameters: Vec<CertificateParameters>) -> Vec<Result<IocEntrySearchResult, IocEntrySearchError>> {
    if search_parameters.is_empty() {
        return vec![];
    }
    let search_parameters: Vec<CertificateParameters> = search_parameters
        .into_iter()
        .map(|sp| CertificateParameters{
            ioc_id: sp.ioc_id,
            ioc_entry_id: sp.ioc_entry_id,
//            search_type: sp.search_type,
            name: sp.name.to_ascii_lowercase()
        }).collect();
    info!("Searching IOCs using certificate search.");
    let certs = match load_native_certs() {
        Ok(ok) => ok,
        Err((maybe, err)) => {
            error!("{}", err);
            match maybe {
                None => RootCertStore::empty(),
                Some(ok) => ok,
            }
        }
    };

    certs.roots.iter().flat_map(|cert| {
        let cert = cert.to_trust_anchor();
        let cert_subject_bytes = cert.subject;
        let cert_subject = unsafe { std::str::from_utf8_unchecked(cert_subject_bytes) };
        let cert_subject = cert_subject.to_ascii_lowercase();

        search_parameters.iter()
            .filter(|sp| cert_subject.contains(&sp.name))
            .map(|sp| Ok(IocEntrySearchResult {
                ioc_id: sp.ioc_id,
                ioc_entry_id: sp.ioc_entry_id,
                data: vec![sp.name.clone()],
            })).collect::<Vec<Result<IocEntrySearchResult, IocEntrySearchError>>>()
    }).collect()
}
