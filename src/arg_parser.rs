#[derive(Clone)]
pub struct ParsedArgs {
    pub ioc_definitions: Vec<String>,
    pub local_mode: bool,
}

const LOCAL_MODE_FLAG: &str = "--local";
const LOCAL_MODE_FLAG_S: &str = "-l";

pub fn parsed_args() -> ParsedArgs {
    let args: Vec<String> = std::env::args().collect();
    let args = &args[1..];
    let mut ioc_definitions = Vec::<String>::new();
    let mut local_mode = false;

    for arg in args {
        match arg.as_str() {
            LOCAL_MODE_FLAG => { local_mode = true }
            LOCAL_MODE_FLAG_S => { local_mode = true }
            _ => ioc_definitions.push(arg.clone())
        }
    }

    ParsedArgs {
        ioc_definitions,
        local_mode,
    }
}