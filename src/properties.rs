extern crate config;

use serde::Deserialize;
use config::Config;
use std::io::{LineWriter, Write};
use std::fs::File;

const PROPERTIES_FILENAME: &str = "settings.toml";

#[derive(Debug, Deserialize)]
pub struct Properties {
    pub server: String,
    pub auth_probe_name: String,
    pub auth_key: String,
    pub deep_search: bool,
    pub max_iocs: isize
}

impl Properties {
    pub fn new() -> Self {
        let write_default_result = write_default_if_not_exists();
        match write_default_result {
            Err(e) => {
                error!("Cannot create default application properties: {}", e);
                return default_properties();
            }
            Ok(_) => {
                let mut properties_manipulator = Config::new();
                let merge_result = properties_manipulator.merge(config::File::with_name(PROPERTIES_FILENAME));
                match merge_result {
                    Err(e) => {
                        error!("Cannot load application properties: {}", e);
                        return default_properties();
                    }
                    Ok(_) => {
                        let maybe_final_properties = properties_manipulator.try_into::<Properties>();
                        match maybe_final_properties {
                            Ok(final_properties) => final_properties,
                            Err(error) => {
                                error!("Error loading properties {}", error);
                                return default_properties();
                            }
                        }
                    }
                }
            }
        }
    }
}

fn default_properties() -> Properties {
    Properties {
        server: "http://localhost:8080/".to_string(),
        auth_probe_name: "TESTING".to_string(),
        auth_key: "TESTING".to_string(),
        deep_search: false,
        max_iocs: 5000
    }
}

fn write_default_if_not_exists() -> Result<(), std::io::Error> {
    let maybe_properties_file = File::open(PROPERTIES_FILENAME);
    match maybe_properties_file {
        Ok(_) => {}
        Err(_) => {
            let maybe_new_properties_file = File::create(PROPERTIES_FILENAME);
            match maybe_new_properties_file {
                Ok(new_properties_file) => {
                    let mut writer = LineWriter::new(new_properties_file);
                    writer.write_all(b"server = \"http://localhost:8080/\"\n")?;
                    writer.write_all(b"auth_probe_name = \"TESTING\"\n")?;
                    writer.write_all(b"auth_key = \"TESTING\"\n")?;
                    writer.write_all(b"deep_search = false\n")?;
                    writer.write_all(b"max_iocs = 5000")?;
                    let write_result = writer.flush();
                    if write_result.is_err() {
                        error!("Cannot write default properties into file: {}", write_result.unwrap_err());
                    }
                }
                Err(error) => { error!("Cannot open nor create a default properties file: {}", error) }
            }
        }
    }
    Ok(())
}
