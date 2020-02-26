use crate::data::{IocEntryId, IocId};
use crate::ioc_evaluator::IocEntrySearchResult;
use rustls_native_certs::load_native_certs;
use rustls::RootCertStore;

pub struct CertificateParameters {
    pub ioc_id: IocId,
    pub ioc_entry_id: IocEntryId,
    pub name: String,
}

pub fn check_certs(search_parameters: Vec<CertificateParameters>) -> Vec<IocEntrySearchResult> {
    if search_parameters.is_empty() {
        return vec![];
    }
    let search_parameters: Vec<CertificateParameters> = search_parameters
        .into_iter()
        .map(|sp| CertificateParameters {
            ioc_id: sp.ioc_id,
            ioc_entry_id: sp.ioc_entry_id,
            name: sp.name.to_ascii_lowercase(),
        }).collect();
    info!("Certificate search: Searching IOCs using certificate search.");
    let certs = match load_native_certs() {
        Ok(ok) => ok,
        Err((maybe, err)) => {
            error!("Connection search: {}", err);
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
            .map(|sp| {
                info!("Certificate search: Found certificate {} for IOC {}",
                    sp.name,
                    sp.ioc_id
                );
                IocEntrySearchResult {
                    ioc_id: sp.ioc_id,
                    ioc_entry_id: sp.ioc_entry_id,
                }
            }).collect::<Vec<IocEntrySearchResult>>()
    }).collect()
}
