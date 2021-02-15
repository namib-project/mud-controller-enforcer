use crate::{db::DbConnection, error::Result, services::mud_service::*};
use chrono::Utc;

pub async fn update_outdated_profiles(db_pool: DbConnection) -> Result<()> {
    log::debug!("Update outdated profiles");
    let mut mud_data = get_all_mud_expiration(&db_pool).await?;
    let mut mud_vec = vec![];
    for mud in mud_data.iter_mut() {
        if mud.expiration < Utc::now().naive_utc() {
            mud.expiration = Utc::now().naive_utc();
            mud_vec.push(mud.clone());
        }
    }
    refresh_mud_expiration(mud_vec, &db_pool).await

    // fetchen exire updaten und dann get_mud_from_url
    // config key in enum bei ben noch nciht in master.
    // wenn ein neues Gerät hinzugefügt wird
    // funktion, die ein default MUD-Profil erzeugt.
}
