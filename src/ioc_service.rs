use crate::data::{GetIocResponse, ReportUploadRequest, Ioc};
use std::fmt::Display;
use serde::export::Formatter;
use std::fmt;
use std::path::Path;
use std::fs::File;
use std::io::{BufReader, Write};
use chrono::Local;
use reqwest::header;

#[derive(Debug)]
pub struct IocServiceError {
    pub kind: String,
    pub message: String,
}

impl From<std::io::Error> for IocServiceError {
    fn from(io_error: std::io::Error) -> Self {
        IocServiceError {
            kind: "File IO error".to_string(),
            message: io_error.to_string(),
        }
    }
}

impl From<serde_json::error::Error> for IocServiceError {
    fn from(error: serde_json::error::Error) -> Self {
        IocServiceError {
            kind: "Json parsing error".to_string(),
            message: error.to_string(),
        }
    }
}

impl Display for IocServiceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "IocServiceError(kind: {}, message: {})", self.kind, self.message)
    }
}

pub trait IocService {
    fn receive_ioc(&self) -> Result<GetIocResponse, IocServiceError>;
    fn report_results(&self, request: ReportUploadRequest) -> Result<(), IocServiceError>;
}

pub struct FileIocService<T: AsRef<str> + AsRef<Path> + std::fmt::Display> {
    ioc_file_paths: Vec<T>
}

impl<T: AsRef<str> + AsRef<Path> + std::fmt::Display> FileIocService<T> {
    pub fn new(ioc_file_paths: Vec<T>) -> Self { FileIocService { ioc_file_paths } }
}

impl<T: AsRef<str> + AsRef<Path> + std::fmt::Display>
IocService for FileIocService<T> {
    fn receive_ioc(&self) -> Result<GetIocResponse, IocServiceError> {
        let responses = self.ioc_file_paths.iter().filter_map(|file_path| {
            let file = File::open(file_path);
            let file = file.map_err(|e| IocServiceError::from(e));
            match file {
                Ok(file) => {
                    let reader = BufReader::new(file);
                    let response: Result<GetIocResponse, serde_json::error::Error> = serde_json::de::from_reader(reader);
                    match response {
                        Ok(response) => { Some(response) }
                        Err(error) => {
                            error!("Failed to retrieve json: {}", error);
                            None
                        }
                    }
                }
                Err(error) => {
                    error!("Failed to retrieve json: {}", error);
                    None
                }
            }
        });
        let iocs: Vec<Ioc> = responses
            .flat_map(|it| it.iocs.into_iter())
            .collect();
        let total_iocs = iocs.len();
        Ok(GetIocResponse { release_datetime: None, iocs, total_iocs })
    }

    fn report_results(&self, request: ReportUploadRequest) -> Result<(), IocServiceError> {
        let json = serde_json::to_string_pretty(&request)?;
        let mut report_file = std::fs::File::create(format!("Report-{}.json", Local::now().format("_%Y-%m-%d_%H-%M-%S")))?;
        report_file.write_all(json.as_ref())?;
        Ok(())
    }
}

/////////////////////////////////////////////////////////////////////////////////////////////////////

const REALM: &'static str = "IOC Server Probes";

pub struct HttpIocService {
    url: String,
    authorization_header_value: String,
    max_iocs: isize
}

impl HttpIocService {
    pub fn new(url: String,
               probe_name: String,
               api_key: String,
               max_iocs: isize
    ) -> Self {
        let authorization_header_value = base64::encode(format!("{}:{}", probe_name, api_key).as_bytes());
        HttpIocService { url, authorization_header_value, max_iocs }
    }
}

fn http_client() -> Result<reqwest::blocking::Client, IocServiceError> {
    reqwest::blocking::Client::builder()
        // .danger_accept_invalid_certs(true) // NONO: Need to be removed after correct cert is bought
        .build()
        .map_err(|err| IocServiceError {
            kind: "HTTP Error".to_string(),
            message: format!("{}", err),
        })
}

impl IocService for HttpIocService {
    fn receive_ioc(&self) -> Result<GetIocResponse, IocServiceError> {
        let client = http_client()?;
        let mut results = Vec::<Ioc>::new();
        let mut page = 0;
        loop {
            let url = format!("{}/api/probe/auth/get/ioc/{}", self.url.as_str(), page).to_string();
            let mut response: GetIocResponse = client.get(&url)
                .header(header::AUTHORIZATION, format!("Basic {}", self.authorization_header_value.as_str()))
                .header(header::WWW_AUTHENTICATE, format!("Basic REALM=\"{}\", charset=UTF-8", REALM))
                .send()
                .map_err(|err| IocServiceError {
                    kind: "HTTP Error".to_string(),
                    message: format!("{}", err),
                })?
                .json()
                .map_err(|err| IocServiceError {
                    kind: "HTTP Error".to_string(),
                    message: format!("{}", err),
                })?;

            if response.iocs.is_empty() {
                break;
            } else {
                results.append(&mut response.iocs)
            }
            info!("Loaded {} out of {} IOCs, limit {}",
                  results.len(),
                  response.total_iocs,
                  self.max_iocs
            );
            page += 1;

            if self.max_iocs > -1 {
                if results.len() >= self.max_iocs as usize {
                    break;
                }
            }
        }
        let total_iocs = results.len();
        Ok(GetIocResponse { release_datetime: None, iocs: results, total_iocs })
    }

    fn report_results(&self, request: ReportUploadRequest) -> Result<(), IocServiceError> {
        let client = http_client()?;
        let url = format!("{}/api/probe/auth/post/ioc/result", self.url.as_str()).to_string();

        client.post(&url)
            .header(header::AUTHORIZATION, format!("Basic {}", self.authorization_header_value.as_str()))
            .header(header::WWW_AUTHENTICATE, format!("Basic REALM=\"{}\", charset=UTF-8", REALM))
            .json(&request)
            .send()
            .map_err(|err| IocServiceError {
                kind: "HTTP Error".to_string(),
                message: format!("{}", err),
            })?;
        Ok(())
    }
}