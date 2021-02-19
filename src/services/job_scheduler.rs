/*use crate::{db, db::DbConnection, error::Result};
use clokwerk::{Scheduler, TimeUnits};
use futures::{future::BoxFuture, FutureExt};
use std::{borrow::Borrow, pin::Pin, rc::Rc, sync::Arc, thread, time::Duration};
use tokio::{macros::support::Future, sync::Mutex};

pub struct JobScheduler {
    scheduler: Scheduler,
}

impl JobScheduler {
    pub fn new() -> Self {
        let mut job = JobScheduler {
            scheduler: Scheduler::new(),
        };
        loop {
            job.scheduler.run_pending();
            thread::sleep(Duration::from_secs(10));
        }
        job
    }

    pub fn add(
        &mut self,
        function: Arc<dyn Future<Output=Result<()>>+std::marker::Send+Unpin>,
        duration: clokwerk::Interval,
    ) {
        self.scheduler.every(duration).run(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("could not construct tokio runtime")
                .block_on(function.clone())
                .expect("failed running scheduler for namib_mud_controller::services::mud_service::mud_profile_service::update_outdated_profiles");
        });
    }
}*/
