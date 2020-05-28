use crate::data::{IocEntryId, SearchType, IocId};
use crate::ioc_evaluator::IocEntrySearchResult;
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

pub fn check_conns(search_parameters: Vec<ConnectionParameters>) -> Vec<IocEntrySearchResult> {
    if search_parameters.is_empty() {
        return vec![]
    }
    info!("Connection search: Searching IOCs using open network connection search.");
    let mut result: Vec<IocEntrySearchResult> = Vec::new();
    let search_parameters: Vec<ConnectionParametersRegexed> = search_parameters.into_iter().filter_map(|sp| {
        match sp.search {
            SearchType::Exact => Some(ConnectionParametersRegexed { conn_param: sp, regex: None }),
            SearchType::Regex => {
                match Regex::new(&sp.name) {
                    Ok(regex) => Some(ConnectionParametersRegexed { conn_param: sp, regex: Some(regex) }),
                    Err(err) => {
                        error!("Connection search: {}", err);
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
    ).unwrap().iter()
        .filter_map(|socket|
            match &socket.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp_socket) => Some(tcp_socket),
                ProtocolSocketInfo::Udp(_) => None,
            }
        )
        .filter(|socket| !socket.remote_addr.is_loopback())
        .filter(|socket| !socket.remote_addr.is_unspecified())
        .for_each(|socket| {
                let remote_address = &socket.remote_addr;
                let remote_address_name = dns_lookup::lookup_addr(remote_address);

                search_parameters.iter().for_each(|sp| {
                    if remote_address_name.is_ok() {
                        debug!("Connection search: Checking address {} for IOC {}", remote_address_name.as_ref().unwrap(), &sp.conn_param.name);
                        check_item(remote_address_name.as_ref().unwrap(), sp, &mut result)
                    }
                });
    });
    result
}

fn check_item(
    address_name: &String,
    sp: &ConnectionParametersRegexed,
    result: &mut Vec<IocEntrySearchResult>,
) {
    let matches = match &sp.regex {
        None => &sp.conn_param.name == address_name,
        Some(regex) => regex.is_match(address_name),
    };
    if matches {
        let message =
            format!("Connection search: Found connection {} for IOC {}",
              address_name.clone(),
              sp.conn_param.ioc_id
        );
        info!("{}", message);
        result.push(IocEntrySearchResult {
            ioc_id: sp.conn_param.ioc_id,
            ioc_entry_id: sp.conn_param.ioc_entry_id,
            description: message
        });
    }
}