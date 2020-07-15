//pub use self::data::*;
#[cfg(windows)]
extern crate winapi;
#[macro_use]
extern crate log;
extern crate simplelog;
extern crate chrono;
#[cfg(windows)]
extern crate winreg;

use simplelog::*;
use std::fs::File;
use crate::data::{IocEntry, ReportUploadRequest, IocEntryId, GetIocResponse, Ioc, IocId, PrettyReport, PrettyReportList};
use crate::file_checker::FileParameters;
use crate::arg_parser::{parsed_args, ParsedArgs};
use crate::properties::Properties;
use crate::ioc_service::{FileIocService, IocService, HttpIocService};
use crate::ioc_evaluator::{IocEvaluator, IocEntryItem, IocEntrySearchResult};
use std::collections::HashMap;
use crate::dns_checker::DnsParameters;
use crate::mutant_checker::MutexParameters;
use crate::registry_checker::RegistryParameters;
use crate::conns_checker::ConnectionParameters;
use crate::process_checker::ProcessParameters;
use crate::cert_checker::CertificateParameters;
use crate::logo::print_logo;
use chrono::Local;
use std::io::Write;
use uuid::Uuid;

#[cfg(windows)]
mod windows_bindings;
#[cfg(windows)]
mod priv_esca;

mod data;
mod hasher;
mod mutant_checker;
mod file_checker;
mod properties;
mod utils;
mod conversion;
mod arg_parser;
mod ioc_service;
mod ioc_evaluator;
mod dns_checker;
mod registry_checker;
mod process_checker;
mod conns_checker;
mod cert_checker;
mod dir_resolver;
mod logo;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parsed_args();
    setup_logger(&args);
    print_logo();
    let program_properties = Properties::new();
    info!("Loaded properties");
    debug!("IOC server is at {}", program_properties.server);
    run_checker(&program_properties, &args);

    Ok(())
}


fn setup_logger(args: &ParsedArgs) {
    let mut loggers: Vec<Box<dyn SharedLogger>> = vec![
        WriteLogger::new(LevelFilter::Debug, Config::default(), File::create(format!("ioc-{}.log", Uuid::new_v4().as_u128())).unwrap()),
    ];
    if !args.raw_console_mode {
        loggers.push(TermLogger::new(LevelFilter::Debug, Config::default(), TerminalMode::Mixed).unwrap())
    }
    CombinedLogger::init(loggers).unwrap();
}

fn walk_iocs(
    args: &ParsedArgs,
    root_ioc_entries: &mut HashMap<IocId, IocEntryId>,
    iocs: &Vec<Ioc>,
    ioc_entries: &mut HashMap<IocEntryId, IocEntryItem>,
    file_parameters: &mut Vec<FileParameters>,
    dns_parameters: &mut Vec<DnsParameters>,
    mutex_parameters: &mut Vec<MutexParameters>,
    registry_parameters: &mut Vec<RegistryParameters>,
    conns_parameters: &mut Vec<ConnectionParameters>,
    process_parameters: &mut Vec<ProcessParameters>,
    cert_parameters: &mut Vec<CertificateParameters>,
) {
    let mut id_gen: u64 = 1;
    for ioc in iocs {
        id_gen = id_gen + 1;
        root_ioc_entries.insert(ioc.id.clone(), id_gen.clone());
        walk_ioc_entries(
            args,
            &ioc.definition,
            ioc.id,
            root_ioc_entries,
            ioc_entries,
            file_parameters,
            dns_parameters,
            mutex_parameters,
            registry_parameters,
            conns_parameters,
            process_parameters,
            cert_parameters,
            &mut id_gen,
        )
    }
}

// Basicaly BFS
fn walk_ioc_entries(
    args: &ParsedArgs,
    ioc_entry: &IocEntry,
    ioc_root_id: IocId,
    root_ioc_entries: &mut HashMap<IocEntryId, IocId>,
    ioc_entries: &mut HashMap<IocEntryId, IocEntryItem>,
    file_parameters: &mut Vec<FileParameters>,
    dns_parameters: &mut Vec<DnsParameters>,
    mutex_parameters: &mut Vec<MutexParameters>,
    registry_parameters: &mut Vec<RegistryParameters>,
    conns_parameters: &mut Vec<ConnectionParameters>,
    process_parameters: &mut Vec<ProcessParameters>,
    cert_parameters: &mut Vec<CertificateParameters>,
    id_gen: &mut IocEntryId,
) {
    let offspring = ioc_entry.offspring.as_ref();
    let mut checks_specified = 0u32;

    if ioc_entry.certs_check.is_some() && args.cert_check {
        checks_specified += 1;
        let cert_info = ioc_entry.certs_check.clone().unwrap();
        cert_parameters.push(CertificateParameters {
            ioc_id: ioc_root_id,
            ioc_entry_id: *id_gen,
            name: cert_info.name,
        })
    }
    if ioc_entry.file_check.is_some() && args.file_check {
        checks_specified += 1;
        let file_info = ioc_entry.file_check.clone().unwrap();
        file_parameters.push(FileParameters {
            ioc_id: ioc_root_id,
            ioc_entry_id: *id_gen,
            search_type: file_info.search,
            file_path_or_name: file_info.name,
            hash: file_info.hash,
        });
    }
    if ioc_entry.registry_check.is_some() && args.registry_check {
        checks_specified += 1;
        let registry_info = ioc_entry.registry_check.clone().unwrap();
        registry_parameters.push(RegistryParameters {
            ioc_id: ioc_root_id,
            ioc_entry_id: *id_gen,
            search_type: registry_info.search,
            key: registry_info.key,
            value_name: registry_info.value_name,
            value: registry_info.value,
        })
    }
    if ioc_entry.dns_check.is_some() && args.dns_check {
        checks_specified += 1;
        let dns_info = ioc_entry.dns_check.clone().unwrap();
        dns_parameters.push(DnsParameters {
            ioc_id: ioc_root_id,
            ioc_entry_id: *id_gen,
            name: dns_info.name,
        })
    }
    if ioc_entry.process_check.is_some() && args.process_check {
        checks_specified += 1;
        let proc_info = ioc_entry.process_check.clone().unwrap();
        process_parameters.push(ProcessParameters {
            ioc_id: ioc_root_id,
            ioc_entry_id: *id_gen,
            search: proc_info.search,
            name: proc_info.name,
            hash: proc_info.hash,
        })
    }
    if ioc_entry.mutex_check.is_some() && args.mutex_check {
        checks_specified += 1;
        let mutex_info = ioc_entry.mutex_check.clone().unwrap();
        mutex_parameters.push(MutexParameters {
            ioc_entry_id: *id_gen,
            ioc_id: ioc_root_id,
            data: mutex_info.name,
        })
    }

    if ioc_entry.conns_check.is_some() && args.conn_check {
        checks_specified += 1;
        let conns_info = ioc_entry.conns_check.clone().unwrap();
        conns_parameters.push(ConnectionParameters {
            ioc_id: ioc_root_id,
            ioc_entry_id: *id_gen,
            search: conns_info.search,
            name: conns_info.name,
        })
    }

    let entry_item = IocEntryItem {
        ioc_entry_id: *id_gen,
        ioc_id: ioc_root_id,
        eval_policy: ioc_entry.eval_policy.clone(),
        child_eval: ioc_entry.child_eval_policy.clone(),
        children: match offspring {
            None => None,
            Some(children) => Some(children.iter().map(|child| {
                *id_gen = *id_gen + 1;
                let this_child_id = id_gen.clone();
                walk_ioc_entries( // Rekurzia fuj.
                                  args,
                                  child,
                                  ioc_root_id,
                                  root_ioc_entries,
                                  ioc_entries,
                                  file_parameters,
                                  dns_parameters,
                                  mutex_parameters,
                                  registry_parameters,
                                  conns_parameters,
                                  process_parameters,
                                  cert_parameters,
                                  id_gen,
                );
                this_child_id
            }).collect()),
        },
        checks_specified,
    };
    ioc_entries.insert(entry_item.ioc_entry_id, entry_item);
}


fn run_checker(program_properties: &Properties, args: &ParsedArgs) {
    let file_ioc_service = FileIocService::new(args.ioc_definitions.to_vec());
    let http_ioc_service = HttpIocService::new(
        program_properties.server.clone(),
        program_properties.auth_probe_name.clone(),
        program_properties.auth_key.clone(),
        program_properties.max_iocs,
    );

    // Get the file ioc defs
    ////////////////////////////////////////////////////////////////////////////
    let ioc_from_file = if args.ioc_definitions.is_empty() {
        info!("No IOC definitions specified.");
        vec![]
    } else {
        info!("One or multiple IOC definitions specified.");
        let ioc_response = file_ioc_service.receive_ioc();
        ioc_response.unwrap_or(GetIocResponse { release_datetime: None, iocs: vec![], total_iocs: 0 }).iocs
    };
    info!("Loaded {} IOC definitions from file", ioc_from_file.len());

    // Get the server ioc defs
    ////////////////////////////////////////////////////////////////////////////
    let ioc_from_server = if args.local_mode {
        info!("Running in offline mode. No communication with server.");
        vec![]
    } else {
        info!("Running in online mode. Establishing communication with server.");
        let ioc_response = http_ioc_service.receive_ioc();
        match ioc_response {
            Ok(ioc_response) => ioc_response.iocs,
            Err(err) => {
                error!("Cannot download IOC definitions due to {}", err);
                vec![]
            }
        }
    };

    info!("Loaded {} IOC definitions from server", ioc_from_server.len());

    // Join them
    ////////////////////////////////////////////////////////////////////////////
    let iocs: Vec<Ioc> = ioc_from_file.into_iter().chain(ioc_from_server.into_iter()).collect();
    info!("Total loaded IOC definitions: {}", iocs.len());

    // Create checker's params
    ////////////////////////////////////////////////////////////////////////////
    let mut root_ioc_entries: HashMap<IocEntryId, IocId> = HashMap::new();
    let mut ioc_entries: HashMap<IocEntryId, IocEntryItem> = HashMap::new();
    let mut file_parameters: Vec<FileParameters> = Vec::new();
    let mut dns_parameters: Vec<DnsParameters> = Vec::new();
    let mut mutex_parameters: Vec<MutexParameters> = Vec::new();
    let mut registry_parameters: Vec<RegistryParameters> = Vec::new();
    let mut conns_parameters: Vec<ConnectionParameters> = Vec::new();
    let mut proc_parameters: Vec<ProcessParameters> = Vec::new();
    let mut cert_parameters: Vec<CertificateParameters> = Vec::new();
    walk_iocs(
        &args,
        &mut root_ioc_entries,
        &iocs,
        &mut ioc_entries,
        &mut file_parameters,
        &mut dns_parameters,
        &mut mutex_parameters,
        &mut registry_parameters,
        &mut conns_parameters,
        &mut proc_parameters,
        &mut cert_parameters,
    );

    let deep_search_enabled = program_properties.deep_search;
    // Run checkers
    ////////////////////////////////////////////////////////////////////////////

    let dns_check_results = if args.dns_check { dns_checker::check_dns(dns_parameters) } else { vec![] };
    let cert_check_results = if args.cert_check { cert_checker::check_certs(cert_parameters) } else { vec![] };
    let proc_check_results = if args.process_check { process_checker::check_processes(proc_parameters) } else { vec![] };
    let mutex_check_results = if args.mutex_check { mutant_checker::check_mutexes(mutex_parameters) } else { vec![] };
    let registry_check_results = if args.registry_check { registry_checker::check_registry(registry_parameters, deep_search_enabled) } else { vec![] };
    let conns_check_results = if args.conn_check { conns_checker::check_conns(conns_parameters) } else { vec![] };
    let file_check_results = if args.file_check { file_checker::check_files(file_parameters, deep_search_enabled) } else { vec![] };

    // Combine results
    ////////////////////////////////////////////////////////////////////////////
    let all_results: Vec<IocEntrySearchResult> =
        file_check_results.into_iter()
            .chain(dns_check_results.into_iter())
            .chain(mutex_check_results.into_iter())
            .chain(registry_check_results.into_iter())
            .chain(conns_check_results)
            .chain(proc_check_results)
            .chain(cert_check_results)
            .collect();

    // Create cached ioc defs and search results
    ////////////////////////////////////////////////////////////////////////////

    let evaluator = IocEvaluator::new(
        root_ioc_entries,
        ioc_entries,
        &all_results,
    );
    let evaluated_iocs: Vec<IocId> = evaluator.evaluate();

    let upload_request = ReportUploadRequest::new(evaluated_iocs.clone());
    info!("Found {} IOCs out of {}",
          upload_request.found_iocs.len(),
          iocs.len()
    );
    if args.local_mode && !args.raw_console_mode {
        pretty_report(&evaluated_iocs, &iocs, &all_results);
        let report_response = file_ioc_service.report_results(upload_request.clone());
        match report_response {
            Ok(_) => { info!("Report saved") }
            Err(error) => { error!("Cannot save report: {}", error) }
        }
    } else if !args.raw_console_mode {
        let report_response = http_ioc_service.report_results(upload_request);
        match report_response {
            Ok(_) => { info!("Report saved") }
            Err(error) => { error!("Cannot save report: {}", error) }
        }
    }else {
        println!("{:?}", upload_request.found_iocs);
    }
}

fn pretty_report(
    evaluated_iocs: &[IocId],
    all_iocs: &[Ioc],
    results: &[IocEntrySearchResult],
) {
    let pretty_reports: Vec<PrettyReport> = evaluated_iocs
        .iter()
        .filter_map(|ioc_id| {
            let report: Vec<String> = results
                .iter()
                .filter(|iesr| iesr.ioc_id == ioc_id.clone())
                .map(|it| {
                    it.description.clone()
                }).collect();
            if report.is_empty() {
                None
            } else {
                let ioc_mame = all_iocs
                    .iter()
                    .find(|it| it.id == ioc_id.clone())
                    .map(|it| it.name.clone())
                    .unwrap_or(None)
                    .unwrap_or("UNKNOWN".to_string());

                Some(
                    PrettyReport {
                        ioc_id: ioc_id.clone(),
                        name: ioc_mame,
                        search_reports: report,
                    }
                )
            }
        }).collect();
    let pretty_report_wrapper = PrettyReportList { found_iocs: pretty_reports };
    let json = serde_json::to_string_pretty(&pretty_report_wrapper);
    match json {
        Ok(json) => {
            let mut report_file = std::fs::File::create(format!("PrettyReport-{}.json", Local::now().format("_%Y-%m-%d_%H-%M-%S")));
            match report_file.as_mut() {
                Ok(report_file) => {
                    let res = report_file.write_all(json.as_ref());
                    match res {
                        Ok(_) => {}
                        Err(err) => {
                            error!("{}", err);
                        }
                    }
                }
                Err(err) => {
                    error!("{}", err);
                }
            }
        }
        Err(err) => {
            error!("{}", err);
        }
    }
}
