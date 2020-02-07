use crate::data::{GetIocResponse, ReportUploadRequest, Ioc};
use std::fmt::Display;
use serde::export::Formatter;
use std::fmt;
use std::path::Path;
use std::fs::File;
use std::io::{BufReader, Write};
use chrono::Local;
use minreq::{Response, Error, Request};

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

        Ok(GetIocResponse { release_datetime: None, iocs })
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
}

impl HttpIocService {
    pub fn new(url: String,
               probe_name: String,
               api_key: String,
    ) -> Self {
        let authorization_header_value = base64::encode(format!("{}:{}", probe_name, api_key).as_bytes());
        HttpIocService { url, authorization_header_value }
    }
}

impl IocService for HttpIocService {
    fn receive_ioc(&self) -> Result<GetIocResponse, IocServiceError> {
        let hours = 24;
        let response = minreq::get(format!("{}/api/probe/auth/get/ioc/{}", self.url.as_str(), hours))
            .with_header("Authorization", format!("Basic {}", self.authorization_header_value.as_str()))
            .with_header("WWW-Authenticate", format!("Basic REALM=\"{}\", charset=UTF-8", REALM))
            .send();
        match response {
            Ok(response) => match response.status_code {
                status if status < 300 => {
                    let body = response.json::<GetIocResponse>();
                    let body = body.map_err(|error|
                        IocServiceError { kind: "JSON Error".to_string(), message: format!("Failed to retrieve json due to {}", error) }
                    );
                    body
                }
                status => Err(IocServiceError { kind: "HTTP Error".to_string(), message: format!("Cannot connect to server, response code {}", status) })
            },
            Err(err) => Err(IocServiceError { kind: "HTTP Error".to_string(), message: format!("Cannot connect to server due to {}", err) }),
        }
    }

    fn report_results(&self, request: ReportUploadRequest) -> Result<(), IocServiceError> {
        let request_body = minreq::post(format!("{}/api/probe/auth/post/ioc/result", self.url.as_str()))
            .with_header("Authorization", format!("Basic {}", self.authorization_header_value.as_str()))
            .with_header("WWW-Authenticate", format!("Basic REALM=\"{}\", charset=UTF-8", REALM))
            .with_json(&request);
        match request_body {
            Ok(request_body) => {
                let response = request_body.send();

                match response {
                    Ok(_) => Ok(()),
                    Err(error) => Err(
                        IocServiceError { kind: "HTTP Error".to_string(), message: format!("Could not connect to IOC server. {}", error) }
                    )
                }
            }
            Err(error) => Err(
                IocServiceError { kind: "JSON Error".to_string(), message: format!("Could not convert IOC scan results to JSON. {}", error) }
            )
        }
    }
}
