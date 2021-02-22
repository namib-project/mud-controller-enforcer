use crate::{error, error::Result};
use chrono::{Datelike, Local, NaiveDate, NaiveDateTime, NaiveTime};
use lazy_static::lazy_static;
use regex::Regex;
use snafu::OptionExt;
use std::net::IpAddr;

const MONTHS: &str = "JanFebMarAprMayJunJulAugSepOctNovDec";

fn parse_log_line(line: &str) -> Result<()> {
    lazy_static! {
        static ref LOG_FORMAT: Regex =
            Regex::new(r#"(\w{3})  ?(\d{1,2}) (\d\d:\d\d:\d\d) .* query\[A] (\S+) from (\S+)"#).unwrap();
    }
    let m = LOG_FORMAT.captures(line).context(error::NoneError {})?;
    let month = MONTHS.find(&m[1]).context(error::NoneError {})? / 3 + 1;
    let day_of_month: u32 = m[2].parse()?;
    // dnsmasq logs don't contain the year, so assume the current year
    let today = Local::today().naive_local();
    let mut date = NaiveDate::from_ymd_opt(today.year(), month as u32, day_of_month).context(error::NoneError {})?;
    // if the date is after today, it is likely to be from last year
    if date > today {
        date = date.with_year(today.year() - 1).context(error::NoneError {})?;
    }
    let time: NaiveTime = m[3].parse()?;
    let date_time = NaiveDateTime::new(date, time);
    let domain = &m[4];
    let ip: IpAddr = m[5].parse()?;
    info!("Received dns request: {} {} {}", date_time, ip, domain);
    Ok(())
}

pub async fn add_new_logs(_enforcer: String, logs: Vec<String>) {
    for line in &logs {
        if let Err(e) = parse_log_line(line) {
            debug!("failed to parse log line: {}", e);
        }
    }
    // TODO send logs to legacy_service
}
