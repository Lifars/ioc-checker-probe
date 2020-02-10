use crate::data::{IocEntryId, SearchType, IocId};
use crate::ioc_evaluator::{IocEntrySearchResult, IocEntrySearchError};
use self::netstat::ProtocolSocketInfo;
use regex::Regex;

extern crate netstat;

pub struct ConnectionParameters {
    pub ioc_id: IocId,
    pub ioc_entry_id: IocEntryId,
    pub search: SearchType,
    pub name: String,
}

struct ConnectionParametersRegexed {
    conn_param: ConnectionParameters,
    regex: Option<Regex>,
}

pub fn check_conns(search_parameters: Vec<ConnectionParameters>) -> Vec<Result<IocEntrySearchResult, IocEntrySearchError>> {
    if search_parameters.is_empty() {
        return vec![]
    }
    info!("Searching IOCs using open network connection search.");
    let mut result: Vec<Result<IocEntrySearchResult, IocEntrySearchError>> = Vec::new();
    let search_parameters: Vec<ConnectionParametersRegexed> = search_parameters.into_iter().filter_map(|sp| {
        match sp.search {
            SearchType::Exact => Some(ConnectionParametersRegexed { conn_param: sp, regex: None }),
            SearchType::Regex => {
                match Regex::new(&sp.name) {
                    Ok(regex) => Some(ConnectionParametersRegexed { conn_param: sp, regex: Some(regex) }),
                    Err(err) => {
                        error!("{}", err);
                        result.push(Err(IocEntrySearchError {
                            kind: "Regex ERROR".to_string(),
                            message: format!("Cannot parse \"{}\" as regex. IOC id {}. Original error: {}",
                                             sp.name,
                                             sp.ioc_id,
                                             err),
                        }));
                        None
                    }
                }
            }
        }
    }).collect();

    let af_flags = netstat::AddressFamilyFlags::IPV4 | netstat::AddressFamilyFlags::IPV6;
    let proto_flags = netstat::ProtocolFlags::TCP;

    netstat::get_sockets_info(
        af_flags,
        proto_flags,
    ).unwrap().iter().for_each(|socket| {
        match &socket.protocol_socket_info {
            ProtocolSocketInfo::Udp(_) => {}
            ProtocolSocketInfo::Tcp(socket) => {
                let local_address = &socket.local_addr;
                let remote_address = &socket.remote_addr;
                let local_address_name = dns_lookup::lookup_addr(local_address);
                let remote_address_name = dns_lookup::lookup_addr(remote_address);

                search_parameters.iter().for_each(|sp| {
                    if local_address_name.is_ok() {
                        check_item(local_address_name.as_ref().unwrap(), sp, &mut result)
                    }
                    if remote_address_name.is_ok() {
                        check_item(remote_address_name.as_ref().unwrap(), sp, &mut result)
                    }
                });
            }
        }
    });
    result
}

fn check_item(
    address_name: &String,
    sp: &ConnectionParametersRegexed,
    result: &mut Vec<Result<IocEntrySearchResult, IocEntrySearchError>>,
) {
    let matches = match &sp.regex {
        None => &sp.conn_param.name == address_name,
        Some(regex) => regex.is_match(address_name),
    };
    if matches {
        result.push(Ok(IocEntrySearchResult {
            ioc_id: sp.conn_param.ioc_id,
            ioc_entry_id: sp.conn_param.ioc_entry_id,
            data: vec![address_name.clone()],
        }));
    }
}