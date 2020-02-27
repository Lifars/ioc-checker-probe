#[derive(Clone)]
pub struct ParsedArgs {
    pub ioc_definitions: Vec<String>,
    pub local_mode: bool,
    pub cert_check: bool,
    pub conn_check: bool,
    pub dns_check: bool,
    pub file_check: bool,
    pub mutex_check: bool,
    pub process_check: bool,
    pub registry_check: bool,

}

const LOCAL_MODE_FLAG: &str = "--local";
const LOCAL_MODE_FLAG_S: &str = "-l";
const DIS_CERT_FLAG: &str = "--dis-cert";
const DIS_CONN_FLAG: &str = "--dis-conn";
const DIS_DNS_FLAG: &str = "--dis-dns";
const DIS_FILE_FLAG: &str = "--dis-file";
const DIS_MUTEX_FLAG: &str = "--dis-mutex";
const DIS_PROCESS_FLAG: &str = "--dis-proc";
const DIS_REGISTRY_FLAG: &str = "--dis-reg";

pub fn parsed_args() -> ParsedArgs {
    let args: Vec<String> = std::env::args().collect();
    let args = &args[1..];
    let mut ioc_definitions = Vec::<String>::new();
    let mut local_mode = false;


    let mut cert_check= true;
    let mut conn_check= true;
    let mut dns_check= true;
    let mut file_check= true;
    let mut mutex_check= true;
    let mut process_check= true;
    let mut registry_check= true;

    for arg in args {
        match arg.as_str() {
            LOCAL_MODE_FLAG => { local_mode = true }
            LOCAL_MODE_FLAG_S => { local_mode = true }
            DIS_CERT_FLAG => { cert_check = false }
            DIS_CONN_FLAG => { conn_check = false }
            DIS_DNS_FLAG => { dns_check = false }
            DIS_FILE_FLAG => { file_check = false }
            DIS_MUTEX_FLAG => { mutex_check = false }
            DIS_PROCESS_FLAG => { process_check = false }
            DIS_REGISTRY_FLAG => { registry_check = false }
            _ => ioc_definitions.push(arg.clone())
        }
    }

    ParsedArgs {
        ioc_definitions,
        local_mode,
        cert_check,
        conn_check,
        dns_check,
        file_check,
        mutex_check,
        process_check,
        registry_check
    }
}