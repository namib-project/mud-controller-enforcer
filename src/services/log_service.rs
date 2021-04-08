use crate::{
    db::DbConnection,
    error::{none_error, Result},
    services::{acme_service::CertId, device_service, neo4things_service},
};
use chrono::{Datelike, Local, NaiveDate, NaiveDateTime, NaiveTime};
use lazy_static::lazy_static;
use regex::Regex;
use std::net::IpAddr;

const MONTHS: &str = "JanFebMarAprMayJunJulAugSepOctNovDec";

lazy_static! {
    static ref LOG_FORMAT: Regex =
        Regex::new(r#"(\w{3})  ?(\d{1,2}) (\d\d:\d\d:\d\d) .* query\[A] (\S+) from (\S+)"#).unwrap();
}

async fn parse_log_line(line: &str, conn: &DbConnection) -> Result<()> {
    let m = match LOG_FORMAT.captures(line) {
        Some(m) => m,
        None => return Ok(()),
    };
    let month = MONTHS.find(&m[1]).ok_or_else(none_error)? / 3 + 1;
    let day_of_month: u32 = m[2].parse()?;
    // dnsmasq logs don't contain the year, so assume the current year
    let today = Local::today().naive_local();
    let mut date = NaiveDate::from_ymd_opt(today.year(), month as u32, day_of_month).ok_or_else(none_error)?;
    // if the date is after today, it is likely to be from last year
    if date > today {
        date = date.with_year(today.year() - 1).ok_or_else(none_error)?;
    }
    let time: NaiveTime = m[3].parse()?;
    let date_time = NaiveDateTime::new(date, time);
    let domain = &m[4];
    let ip: IpAddr = m[5].parse()?;
    info!("Received dns request: {} {} {}", date_time, ip, domain);
    let device = device_service::find_by_ip(&ip.to_string(), conn).await?;
    // add the device connection in the background as it may take some time
    tokio::spawn(neo4things_service::add_device_connection(device, domain.to_string()));
    Ok(())
}

pub async fn add_new_logs(_enforcer: CertId, logs: Vec<String>, conn: &DbConnection) {
    for line in &logs {
        if let Err(e) = parse_log_line(line, conn).await {
            debug!("failed to parse log line: {:?}", e);
        }
    }
}
