//
////const VERSION: &'static str = env!("CARGO_PKG_VERSION");
//
//
//// /// This doc string acts as a help message when the user runs '--help'
//// /// as do all doc strings on fields
////#[derive(Clap)]
////#[clap(version = "0.1.0", author = "LIFARS")]
////struct Opts {
////    #[clap(short = "l", long = "local")]
////    local: bool,
////    /// Some input. Because this isn't an Option<T> it's required to be used
////    ioc_definitions: Vec<String>,
////    /// A level of verbosity, and can be used multiple times
////    #[clap(short = "v", long = "verbose", parse(from_occurrences))]
////    verbose: i32,
//////    #[clap(subcommand)]
//////    subcmd: SubCommand,
////}
//use std::env;
//use clap::{App, Arg};
//
//const VERSION: &'static str = env!("CARGO_PKG_VERSION");
//const APP_NAME: &'static str = env!("CARGO_PKG_NAME");

#[derive(Clone)]
pub struct ParsedArgs {
    pub ioc_definitions: Vec<String>,
    pub local_mode: bool,
}

//
////
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
//
////
////
//pub fn parsed_args() -> Args {
//    let matches = App::new("Lifars IOC Checker Probe")
//        .version(VERSION)
//        .arg(Arg::with_name(LOCAL_MODE_FLAG)
//            .help("Do not (down/up)load anything from/to server.")
//            .short("l")
//            .number_of_values(1))
//        .arg(Arg::with_name("local files")
//            .long(FILES_FLAG)
//            .short("f")
//            .takes_value(true)
//            .help("Load local IOC definitions.")
//            .number_of_values(1)
//            .multiple(true))
//        .get_matches();
//
//    let local_mode = matches.is_present(LOCAL_MODE_FLAG);
//
//    let ioc_definitions = match matches.values_of(FILES_FLAG) {
//        Some(files) => files.map(|v| v.to_string()).collect(),
//        None => vec![]
//    };
//
//    Args {
//        ioc_definitions,
//        local_mode,
//    }
//}