use std::{ffi::OsString, result::Result, sync::mpsc, time::Duration};

use clap::Parser;
use tokio::runtime::Runtime;
use tracing::{debug, error, info, warn};
use windows_service::{
    define_windows_service,
    service::{
        PowerEventParam, ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState,
        ServiceStatus, ServiceType,
    },
    service_control_handler::{ServiceControlHandlerResult, register},
    service_dispatcher,
};

use crate::{
    config::Config,
    daemon::{DaemonError, run_server},
    service_locations::wake_reconciler,
    utils::logging_setup,
};

static SERVICE_NAME: &str = "XGuardService";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

pub fn run() -> Result<(), windows_service::Error> {
    // Register generated `ffi_service_main` with the system and start the service, blocking
    // this thread until the service is stopped.
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

define_windows_service!(ffi_service_main, service_main);

pub fn service_main(_arguments: Vec<OsString>) {
    if let Err(err) = run_service() {
        error!("Error while running the service. {err}");
        panic!("{err}");
    }
}

fn run_service() -> Result<(), DaemonError> {
    // Create a channel to be able to poll a stop event from the service worker loop.
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<u32>();
    let shutdown_tx_server = shutdown_tx.clone();

    // Define system service event handler that will be receiving service events.
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            // Notifies a service to report its current status information to the service
            // control manager. Always return NoError even if not implemented.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,

            // Handle stop
            ServiceControl::Stop => {
                let _ = shutdown_tx.send(1);
                ServiceControlHandlerResult::NoError
            }

            // Tunnels from before a suspend look alive but pass no traffic: re-check now.
            ServiceControl::PowerEvent(param) => {
                debug!("Received power event: {param:?}");
                if matches!(
                    param,
                    PowerEventParam::ResumeAutomatic | PowerEventParam::ResumeSuspend
                ) {
                    info!("Resumed from sleep, checking service locations");
                    wake_reconciler();
                }
                ServiceControlHandlerResult::NoError
            }

            // Sign-in and sign-out switch pre-logon service locations.
            ServiceControl::SessionChange(param) => {
                debug!("Received session change: {:?}", param.reason);
                wake_reconciler();
                ServiceControlHandlerResult::NoError
            }

            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    // Register system service event handler.
    // The returned status handle should be used to report service status changes to the system.
    let status_handle = register(SERVICE_NAME, event_handler)?;

    let rt = Runtime::new();

    if let Ok(runtime) = rt {
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP
                | ServiceControlAccept::POWER_EVENT
                | ServiceControlAccept::SESSION_CHANGE,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        let config: Config = Config::parse();
        let _guard = logging_setup(&config.log_dir, &config.log_level, config.log_max_files)?;

        let default_panic = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            default_panic(info);
            std::process::exit(1);
        }));

        let (grpc_shutdown_tx, grpc_shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        // Spawn the main gRPC server task
        let server_handle = runtime.spawn(async move {
            let result = run_server(config, grpc_shutdown_rx).await;

            let signal = if result.is_err() {
                error!("Server task ended with error: {:?}", result.err());
                2
            } else {
                warn!("Server task ended cleanly.");
                1
            };

            let _ = shutdown_tx_server.send(signal);
        });

        let mut exit_code = ServiceExitCode::Win32(0);
        loop {
            // Poll shutdown event.
            match shutdown_rx.recv_timeout(Duration::from_secs(1)) {
                // Break the loop upon stop or channel disconnect.
                Ok(1) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let _ = grpc_shutdown_tx.send(());
                    break;
                }
                Ok(2) => {
                    exit_code = ServiceExitCode::Win32(1);
                    break;
                }
                Ok(_) => {
                    let _ = grpc_shutdown_tx.send(());
                    break;
                }

                // Continue work if no events were received within the timeout
                Err(mpsc::RecvTimeoutError::Timeout) => (),
            }
        }

        if exit_code == ServiceExitCode::Win32(0) {
            let _ = runtime.block_on(tokio::time::timeout(Duration::from_secs(10), server_handle));
        }

        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code,
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;
    }

    Ok(())
}
