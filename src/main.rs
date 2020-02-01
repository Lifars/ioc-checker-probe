//pub use self::data::*;
#[cfg(windows)]
extern crate winapi;
#[macro_use]
extern crate log;
extern crate simplelog;
extern crate chrono;

use simplelog::*;
use std::fs::File;
use crate::data::{IocEntry, IocSearchResult, IocSearchError, ReportUploadRequest, IocEntryId, GetIocResponse, Ioc, IocId};
use crate::file_checker::FileParameters;
use crate::arg_parser::parsed_args;
use crate::properties::Properties;
use crate::ioc_service::{FileIocService, IocService, HttpIocService, IocServiceError};
use crate::ioc_evaluator::{IocEvaluator, IocEntryItem, IocEntrySearchError, IocEntrySearchResult};
use std::collections::HashMap;
use std::hash::Hash;
//use ureq::json;


//mod data;
#[cfg(windows)]
mod windows_bindings;

mod data;
mod hasher;
mod mutant_checker;
//mod query_result;
mod file_checker;
mod properties;
mod utils;
mod conversion;
mod arg_parser;
mod ioc_service;
mod ioc_evaluator;

#[cfg(not(windows))]
fn print_message(msg: &str) -> Result<(), Error> {
    println!("{}", msg);
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    setup_logger();
    let program_properties = Properties::new();
    info!("Loaded properties");
    debug!("IOC server is at {}", program_properties.server);
    run_checker(&program_properties);

    Ok(())
}


fn setup_logger() {
    CombinedLogger::init(
        vec![
            TermLogger::new(LevelFilter::Debug, Config::default(), TerminalMode::Mixed).unwrap(),
            WriteLogger::new(LevelFilter::Debug, Config::default(), File::create("ioc.log").unwrap()),
        ]
    ).unwrap();
}

fn walk_iocs(
    iocs: &Vec<Ioc>,
    ioc_entries_root_ids: &mut HashMap<IocEntryId, IocId>,
    ioc_entries: &mut HashMap<IocEntryId, IocEntryItem>,
    file_parameters: &mut Vec<FileParameters>,
) {
    let mut id_gen: u64 = 1;
    for ioc in iocs {
        walk_ioc_entries(
            &ioc.definition,
            ioc.id,
            ioc_entries_root_ids,
            ioc_entries,
            file_parameters,
            &mut id_gen
        )
    }
}

// Basicaly DFS
fn walk_ioc_entries(
    ioc_entry: &IocEntry,
    ioc_root_id: IocId,
    ioc_entries_root_ids: &mut HashMap<IocEntryId, IocId>,
    ioc_entries: &mut HashMap<IocEntryId, IocEntryItem>,
    file_parameters: &mut Vec<FileParameters>,
    id_gen: &mut IocEntryId
) {
    *id_gen = *id_gen + 1;

    ioc_entries_root_ids.insert(*id_gen, ioc_root_id.clone());
    let offspring = ioc_entry.offspring.as_ref();
    ioc_entries.insert(*id_gen, IocEntryItem {
        id: *id_gen,
        eval_policy: ioc_entry.eval_policy.clone(),
        child_eval: ioc_entry.child_eval_policy.clone(),
        children: match offspring {
            None => None,
            Some(children) => Some(children.iter().map(|child| {
                *id_gen = *id_gen + 1;
                *id_gen
            }).collect()),
        },
    });
    let file_info = &ioc_entry.file_check;
    if file_info.is_some() {
        let file_info = file_info.clone().unwrap();
        file_parameters.push(FileParameters {
            ioc_id: ioc_root_id,
            ioc_entry_id: *id_gen,
            search_type: ioc_entry.search_type.clone(),
            file_path_or_name: file_info.name,
            hash: file_info.hash,
        });
    }

    match offspring {
        None => return,
        Some(children) => {
            for child in children {
                walk_ioc_entries( // Rekurzia fuj.
                                  child,
                                  ioc_root_id,
                                  ioc_entries_root_ids,
                                  ioc_entries,
                                  file_parameters,
                                  id_gen
                )
            }
        }
    }
}


fn run_checker(program_properties: &Properties) {
    let args = parsed_args();
    let file_ioc_service = FileIocService::new(args.ioc_definitions.to_vec());
    let http_ioc_service = HttpIocService::new(
        program_properties.server.clone(),
        program_properties.auth_probe_name.clone(),
        program_properties.auth_key.clone(),
    );

    // Get the file ioc defs
    ////////////////////////////////////////////////////////////////////////////
    let ioc_from_file = if args.ioc_definitions.is_empty() {
        info!("No IOC definitions specified.");
        vec![]
    } else {
        info!("One or multiple IOC definitions specified.");
        let ioc_response = file_ioc_service.receive_ioc();
        ioc_response.unwrap_or(GetIocResponse { release_datetime: None, iocs: vec![] }).iocs
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
    let mut ioc_entries_root_ids: HashMap<IocEntryId, IocId> = HashMap::new();
    let mut ioc_entries: HashMap<IocEntryId, IocEntryItem> = HashMap::new();
    let mut file_parameters: Vec<FileParameters> = Vec::new();

    walk_iocs(
        &iocs,
        &mut ioc_entries_root_ids,
        &mut ioc_entries,
        &mut file_parameters,
    );

    // Run checkers
    ////////////////////////////////////////////////////////////////////////////

    let file_check_results = file_checker::check_files(&file_parameters);
    // ... todo: other checkers

    // Combine results
    ////////////////////////////////////////////////////////////////////////////
    let all_results: Vec<Result<IocEntrySearchResult, IocEntrySearchError>> = file_check_results;

    // Create cached ioc defs and search results
    ////////////////////////////////////////////////////////////////////////////

    let evaluator = IocEvaluator::new(
        ioc_entries_root_ids,
        ioc_entries,
        all_results.to_vec(),
    );
    let evaluated_iocs: Vec<IocId> = evaluator.evaluate();
    let all_results_dto: Vec<Result<IocSearchResult, IocSearchError>> = all_results.into_iter()
        .map(|ioc_result| {
            match ioc_result {
                Ok(res) => {
                    Ok(
                        IocSearchResult{
                            ioc_id: res.ioc_id,
                            data: res.data
                        }
                    )
                },
                Err(err) => { Err(IocSearchError{
                    ioc_id: err.ioc_id,
                    kind: err.kind,
                    message: err.message
                })},
            }
        })
        .collect();



    let upload_request = ReportUploadRequest::new(all_results_dto, evaluated_iocs);
    match args.local_mode {
        true => {
            let report_response = file_ioc_service.report_results(upload_request);
            match report_response {
                Ok(_) => { info!("Report saved") }
                Err(error) => { error!("Cannot save report: {}", error) }
            }
        }
        false => {
            let report_response = http_ioc_service.report_results(upload_request);
            match report_response {
                Ok(_) => { info!("Report saved") }
                Err(error) => { error!("Cannot save report: {}", error) }
            }
        }
    }
}
