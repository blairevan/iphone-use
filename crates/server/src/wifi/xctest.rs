//! iOS 17+ XCTest orchestration over the same verified userspace Wi-Fi tunnel.

use super::dtx::Dtx;
use anyhow::{bail, Context, Result};
use idevice::{
    dvt::{
        message::AuxValue,
        xctest::{dtx_services::*, types::XCTCapabilities, TestConfig},
    },
    services::{installation_proxy::InstallationProxyClient, rsd::RsdHandshake},
    tcp::handle::AdapterHandle,
};
use plist::{Uid, Value};

/// Build a Foundation class description for the session's keyed archives.
fn class(name: &str) -> Value {
    Value::Dictionary(
        super::dict!(dict { "$classname": name, "$classes": vec![Value::String(name.into())] }),
    )
}

/// Serialize an object table with root UID 1 using Foundation's keyed archive format.
fn archive(objects: Vec<Value>) -> Result<AuxValue> {
    let value = Value::Dictionary(super::dict!(dict {
        "$archiver": "NSKeyedArchiver", "$version": 100000u64,
        "$objects": objects, "$top": super::dict!(dict { "root": Value::Uid(Uid::new(1)) }),
    }));
    let mut bytes = Vec::new();
    value.to_writer_binary(&mut bytes)?;
    Ok(AuxValue::Array(bytes))
}

/// Encode the NSUUID argument expected by testmanagerd rather than a UUID string.
fn session_uuid(uuid: uuid::Uuid) -> Result<AuxValue> {
    archive(vec![
        Value::String("$null".into()),
        Value::Dictionary(super::dict!(dict {
            "$class": Value::Uid(Uid::new(2)), "NS.uuidbytes": Value::Data(uuid.as_bytes().to_vec()),
        })),
        class("NSUUID"),
    ])
}

/// Encode XCTCapabilities with an archived NSDictionary, matching pinned idevice.
fn capabilities(caps: XCTCapabilities) -> Result<AuxValue> {
    let mut objects = vec![
        Value::String("$null".into()),
        Value::Dictionary(super::dict!(dict {
            "$class": Value::Uid(Uid::new(2)), "capabilities-dictionary": Value::Uid(Uid::new(3)),
        })),
        class("XCTCapabilities"),
        Value::String("placeholder".into()),
        class("NSDictionary"),
    ];
    let mut keys = Vec::new();
    let mut values = Vec::new();
    for (key, value) in caps.capabilities {
        keys.push(Value::Uid(Uid::new(objects.len() as u64)));
        objects.push(Value::String(key));
        values.push(Value::Uid(Uid::new(objects.len() as u64)));
        objects.push(value);
    }
    objects[3] = Value::Dictionary(super::dict!(dict {
        "$class": Value::Uid(Uid::new(4)), "NS.keys": keys, "NS.objects": values,
    }));
    archive(objects)
}

/// Resolve only a service advertised inside the authenticated device's RSD.
fn port(rsd: &RsdHandshake, name: &str) -> Result<u16> {
    Ok(rsd
        .services
        .get(name)
        .with_context(|| format!("RSD lacks {name}"))?
        .port)
}

/// Launch only the installed iphone-use runner and keep its XCTest session alive.
pub async fn run(
    handle: &mut AdapterHandle,
    rsd: &RsdHandshake,
    bundle: &str,
    token: &str,
) -> Result<()> {
    let stream = handle
        .connect(port(
            rsd,
            "com.apple.mobile.installation_proxy.shim.remote",
        )?)
        .await?;
    let mut device = idevice::Idevice::new(Box::new(stream), "iphone-use-wifi");
    device.rsd_checkin().await?;
    let mut proxy = InstallationProxyClient::new(device);
    let mut cfg = TestConfig::from_installation_proxy(&mut proxy, bundle, None).await?;
    cfg.tests_to_run = Some(vec!["RunnerTests/testServe".into()]);
    let session = uuid::Uuid::new_v4();
    let mut config = cfg.build_xctest_configuration(session, 17)?;
    config.product_module_name = cfg.config_name().into();
    let archive = config.to_archive_bytes()?;
    let ctrl = Dtx::open(
        handle.connect(port(rsd, TESTMANAGERD_RSD_SERVICE)?).await?,
        archive.clone(),
    )
    .await?;
    let mut main = Dtx::open(
        handle.connect(port(rsd, TESTMANAGERD_RSD_SERVICE)?).await?,
        archive.clone(),
    )
    .await?;
    let mut dvt = Dtx::open(
        handle
            .connect(port(rsd, "com.apple.instruments.dtservicehub")?)
            .await?,
        archive,
    )
    .await?;
    let ctrl_channel = ctrl.channel(XCTEST_PROXY_IDE_TO_DAEMON).await?;
    let main_channel = main.channel(XCTEST_PROXY_IDE_TO_DAEMON).await?;
    let process = dvt
        .channel("com.apple.instruments.server.services.processcontrol")
        .await?;
    ctrl.call(
        ctrl_channel,
        IDE_INITIATE_CTRL_SESSION_WITH_CAPABILITIES,
        vec![capabilities(XCTCapabilities::empty())?],
        true,
    )
    .await?;
    main.call(
        main_channel,
        IDE_INITIATE_SESSION_WITH_IDENTIFIER_CAPABILITIES,
        vec![
            session_uuid(session)?,
            capabilities(XCTCapabilities::ide_defaults())?,
        ],
        true,
    )
    .await?;
    eprintln!("wifi-auto: XCTest sessions initialized");
    let mut env = super::dict!(dict {
        "CA_ASSERT_MAIN_THREAD_TRANSACTIONS": "0", "CA_DEBUG_TRANSACTIONS": "0",
        "DYLD_FRAMEWORK_PATH": format!("${}/Frameworks:/System/Developer/Library/Frameworks:", cfg.runner_app_path),
        "DYLD_LIBRARY_PATH": format!("${}/Frameworks:/System/Developer/usr/lib", cfg.runner_app_path),
        "DYLD_INSERT_LIBRARIES": "/Developer/usr/lib/libMainThreadChecker.dylib",
        "MTC_CRASH_ON_REPORT": "1", "NSUnbufferedIO": "YES", "OS_ACTIVITY_DT_MODE": "YES",
        "SQLITE_ENABLE_THREAD_ASSERTIONS": "1", "XCTestConfigurationFilePath": "",
        "XCTestBundlePath": format!("{}/PlugIns/{}.xctest", cfg.runner_app_path, cfg.runner_bundle_executable.trim_end_matches("-Runner")),
        "XCTestSessionIdentifier": session.to_string().to_uppercase(), "XCTestManagerVariant": "DDI",
        "XCODE_DBG_XPC_EXCLUSIONS": "com.apple.dt.xctestSymbolicator", "IPU_RUNNER_TOKEN": token,
    });
    // Match USB setup's allowlist; never copy the worker's full environment.
    for name in [
        "IPU_DAEMON_TOKEN",
        "IPU_DAEMON_PASSWORD",
        "IPU_DAEMON_HOST",
        "IPU_RUNNER_EXIT_NOTICE",
    ] {
        if let Ok(value) = std::env::var(name) {
            env.insert(name.into(), Value::String(value));
        }
    }
    let args = vec![
        "-NSTreatUnknownArgumentsAsOpen",
        "NO",
        "-ApplePersistenceIgnoreState",
        "YES",
    ];
    let launch = vec![
        Value::String(String::new()),
        Value::String(bundle.into()),
        Value::Dictionary(env),
        Value::Array(args.into_iter().map(|s| Value::String(s.into())).collect()),
        Value::Dictionary(
            super::dict!(dict { "StartSuspendedKey": false, "ActivateSuspended": true }),
        ),
    ];
    let pid = dvt
        .call(
            process,
            "launchSuspendedProcessWithDevicePath:bundleIdentifier:environment:arguments:options:",
            launch.into_iter().map(AuxValue::archived_value).collect(),
            true,
        )
        .await?
        .and_then(|v| v.as_unsigned_integer())
        .filter(|pid| *pid > 0)
        .context("Runner launch did not return a PID")?;
    let authorized = ctrl
        .call(
            ctrl_channel,
            IDE_AUTHORIZE_TEST_SESSION,
            vec![AuxValue::archived_value(Value::Integer(pid.into()))],
            true,
        )
        .await?;
    if authorized == Some(Value::Boolean(false)) {
        bail!("wireless XCTest authorization refused");
    }
    tokio::time::timeout(std::time::Duration::from_secs(45), async {
        while main.driver.borrow().is_none() {
            main.driver.changed().await?;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    let driver = (*main.driver.borrow()).context("missing XCTest driver channel")?;
    main.call(
        driver,
        IDE_START_EXECUTING_TEST_PLAN,
        vec![AuxValue::archived_value(Value::Integer(36.into()))],
        false,
    )
    .await?;
    eprintln!("wifi-auto: wireless XCTest plan started");
    let mut ctrl = ctrl;
    tokio::select! { result = main.finished() => result, result = ctrl.finished() => result, result = dvt.finished() => result }
}
