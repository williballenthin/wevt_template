use anyhow::{Result};
use log::{error, info, debug};

extern crate anyhow;
extern crate clap;
extern crate log;

use wevt_template::{*, util};

fn _main() -> Result<()> {
    better_panic::install();

    let matches = clap::App::new("wevt_template")
        .author("Willi Ballenthin <william.ballenthin@mandiant.com>")
        .about("extract and parse WEVT_TEMPLATEs from PE files")
        .arg(
            clap::Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .multiple(true)
                .help("log verbose messages"),
        )
        .arg(
            clap::Arg::with_name("input")
                    .required(true)
                    .index(1)
                    .help("path to input PE file"),
        )
        .get_matches();

    let log_level = match matches.occurrences_of("verbose") {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        2 => log::LevelFilter::Trace,
        _ => log::LevelFilter::Trace,
    };

    fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{} [{:5}] {} {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                if log_level == log::LevelFilter::Trace {
                    record.target()
                } else {
                    ""
                },
                message
            ))
        })
        .level(log_level)
        .chain(std::io::stderr())
        .filter(|metadata| !metadata.target().starts_with("goblin::pe"))
        .apply()
        .expect("failed to configure logging");


    let buf = util::read_file(matches.value_of("input").unwrap())?;
    let pe = wevt_template::pe::load_pe(&buf)?;

    debug!("pe: memory:\n{:?}", pe.module.address_space);

    for (i, template) in get_wevt_templates(&pe)?.iter().enumerate() {
        info!("template {}:", i);
    }

    Ok(())
}

fn main() {
    if let Err(e) = _main() {
        error!("{:?}", e);
    }
}
