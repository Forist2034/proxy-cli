use std::{
    borrow::Cow,
    io::{Read, Write},
    net::{SocketAddr, ToSocketAddrs},
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
        unix::process::CommandExt,
    },
    str::FromStr,
    sync::atomic::AtomicUsize,
    time::{Duration, SystemTime},
};

use anyhow::Context as _;
use chrono::Datelike;
use clap::Parser;
use proxy_core::{ConnectKind, ConnectionInfo, TcpingResult, xray};
use rand::seq::SliceRandom;
use rustix::{
    fs::{AtFlags, MemfdFlags, Mode, OFlags},
    io::Errno,
};
use serde::{Serialize, ser::SerializeSeq};
use tempfile::TempDir;

type XrayConfig<'a> = xray::OutboundConfig<'a, xray::OutboundSettings<'a>>;

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "mode", content = "config")]
enum ConnMode<'s> {
    Connect,
    HttpProxyTest { listen: &'s str },
}

fn remove_null_field(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(o) => serde_json::Value::Object(
            o.into_iter()
                .filter_map(|(k, v)| match v {
                    serde_json::Value::Null => None,
                    _ => Some((k, remove_null_field(v))),
                })
                .collect(),
        ),
        _ => v,
    }
}
fn build_config(
    server: &[ServerInfo<'_>],
    mode: ConnMode,
    cfg_file: &str,
) -> anyhow::Result<String> {
    struct ServerSer<'a>(&'a [ServerInfo<'a>]);
    impl<'a> serde::Serialize for ServerSer<'a> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut ser = serializer.serialize_seq(Some(self.0.len()))?;
            for s in self.0 {
                ser.serialize_element(&s.server)?;
            }
            ser.end()
        }
    }
    #[derive(Serialize)]
    struct Arg<'a> {
        servers: ServerSer<'a>,
        mode: ConnMode<'a>,
        access_log: &'a str,
        error_log: &'a str,
    }

    let arg_data = serde_json::to_vec_pretty(&Arg {
        servers: ServerSer(server),
        mode,
        access_log: "access.log",
        error_log: "error.log",
    })
    .unwrap();
    let fd = rustix::fs::memfd_create(c"script_config.json", MemfdFlags::empty())
        .context("failed to create script config file")?;
    let mut remain: &[u8] = arg_data.as_ref();
    while !remain.is_empty() {
        let sz = rustix::io::retry_on_intr(|| rustix::io::write(fd.as_fd(), remain))
            .context("failed to write script config")?;
        remain = remain.get(sz..).unwrap_or(&[]);
    }

    let out = std::process::Command::new("nickel")
        .args([
            "export",
            "--format",
            "json",
            "--import-path",
            "/proc/self",
            "--field",
            "config",
            cfg_file,
            "--",
        ])
        .arg(format!("args=import \"fd/{}\" as 'Json", fd.as_raw_fd()))
        .stderr(std::process::Stdio::inherit())
        .output()
        .context("failed to run nickel config")?;

    anyhow::ensure!(out.status.success(), "nickel failed");
    Ok(serde_json::to_string_pretty(&remove_null_field(
        serde_json::from_slice(&out.stdout).context("failed to deserialize exported json")?,
    ))
    .unwrap())
}

struct ServerInfo<'s> {
    url: &'s str,
    server: XrayConfig<'s>,
}

struct Connection {
    uuid: uuid::Uuid,
    timestamp: SystemTime,
    log_dir: OwnedFd,
}
impl Connection {
    fn new(log_root: BorrowedFd) -> anyhow::Result<Self> {
        let timestamp = SystemTime::now();
        let dur = timestamp.duration_since(SystemTime::UNIX_EPOCH).unwrap();
        let uuid = uuid::Uuid::new_v7(uuid::Timestamp::from_unix(
            uuid::NoContext,
            dur.as_secs(),
            dur.subsec_nanos(),
        ));
        const DATE_LEN: usize = 4 + 1 + 2;
        let mut dir_buf = [0; DATE_LEN + 1 + uuid::fmt::Hyphenated::LENGTH + 1];
        let date = chrono::DateTime::<chrono::Local>::from(timestamp);
        let _ = write!(
            &mut std::io::Cursor::new(dir_buf.as_mut_slice()),
            "{:04}-{:02}/{uuid}",
            date.year_ce().1,
            date.month()
        );
        match rustix::fs::mkdirat(
            log_root,
            std::ffi::CStr::from_bytes_with_nul(&dir_buf).unwrap(),
            Mode::from_raw_mode(0o755),
        ) {
            Ok(()) => (),
            Err(Errno::NOENT) => {
                dir_buf[DATE_LEN] = 0;
                match rustix::fs::mkdirat(
                    log_root,
                    std::ffi::CStr::from_bytes_with_nul(&dir_buf[..(DATE_LEN + 1)]).unwrap(),
                    Mode::from_raw_mode(0o755),
                ) {
                    Ok(()) | Err(Errno::EXIST) => (),
                    Err(e) => return Err(anyhow::Error::new(e).context("failed to create log dir")),
                }
                dir_buf[DATE_LEN] = b'/';
                rustix::fs::mkdirat(
                    log_root,
                    std::ffi::CStr::from_bytes_with_nul(&dir_buf).unwrap(),
                    Mode::from_raw_mode(0o755),
                )
                .context("failed to create log dir")?;
            }
            Err(e) => return Err(anyhow::Error::new(e).context("failed to create log dir")),
        }

        let log_dir = rustix::fs::openat(
            log_root,
            std::ffi::CStr::from_bytes_with_nul(&dir_buf).unwrap(),
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::all(),
        )
        .context("failed to open log dir")?;
        Ok(Self {
            uuid,
            timestamp,
            log_dir,
        })
    }
    fn write_info(
        &self,
        servers: &[ServerInfo<'_>],
        kind: ConnectKind<&[SocketAddr]>,
    ) -> anyhow::Result<()> {
        struct ServersSer<'a>(&'a [ServerInfo<'a>]);
        impl<'a> serde::Serialize for ServersSer<'a> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
                for s in self.0 {
                    seq.serialize_element(&proxy_core::ConnectionServer { url: s.url })?;
                }
                seq.end()
            }
        }

        std::fs::File::from(
            rustix::fs::openat(
                self.log_dir.as_fd(),
                c"info.json",
                OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::WRONLY,
                Mode::RUSR,
            )
            .context("failed to create info file")?,
        )
        .write_all(
            &serde_json::to_vec_pretty(&ConnectionInfo {
                id: self.uuid,
                timestamp: self.timestamp,
                servers: ServersSer(servers),
                kind,
            })
            .unwrap(),
        )
        .context("failed to write info file")
    }
}

struct XRay<'a> {
    log_dir: BorrowedFd<'a>,
    process: std::process::Child,
}
impl<'a> XRay<'a> {
    fn start(
        log_dir: BorrowedFd<'a>,
        servers: &'a [ServerInfo<'a>],
        mode: ConnMode,
        cfg_file: &str,
    ) -> anyhow::Result<Self> {
        let xray_config = build_config(servers, mode, cfg_file)?;

        std::fs::File::from(
            rustix::fs::openat(
                log_dir,
                c"config.json",
                OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::WRONLY,
                Mode::RUSR,
            )
            .context("failed to create config file")?,
        )
        .write_all(xray_config.as_bytes())
        .context("failed to write config file")?;
        let process = unsafe {
            std::process::Command::new("xray")
                .args(["run", "-config", "config.json"])
                .stdin(std::process::Stdio::null())
                .pre_exec({
                    let fd = log_dir.as_raw_fd();
                    move || rustix::process::fchdir(BorrowedFd::borrow_raw(fd)).map_err(Into::into)
                })
                .spawn()
                .context("failed to start xray")?
        };

        Ok(XRay { log_dir, process })
    }
    fn finish(&self) -> anyhow::Result<()> {
        match rustix::fs::chmodat(
            self.log_dir.as_fd(),
            c"access.log",
            Mode::RUSR,
            AtFlags::empty(),
        )
        .and_then(|_| {
            rustix::fs::chmodat(
                self.log_dir.as_fd(),
                c"error.log",
                Mode::RUSR,
                AtFlags::empty(),
            )
        }) {
            Ok(()) | Err(Errno::NOENT) => (),
            Err(e) => {
                return Err(anyhow::Error::new(e).context("failed to set log permission"));
            }
        }
        Ok(())
    }
    fn stop(mut self) -> anyhow::Result<()> {
        self.process.kill().context("failed to stop xray")?;
        self.finish()?;
        Ok(())
    }
    fn wait(mut self) -> anyhow::Result<()> {
        self.process.wait().context("failed to wait xray")?;
        self.finish()?;
        Ok(())
    }
}

struct NetContext {
    runtime: tokio::runtime::Runtime,
    tmp_dir: tempfile::TempDir,
    test_seq: AtomicUsize,
    tester: conn_tester::Tester,
    config_path: String,
    log_buf: String,
}
impl NetContext {
    fn test_server(
        &mut self,
        conn: &mut Connection,
        server: &ServerInfo<'_>,
    ) -> anyhow::Result<Result<Duration, conn_tester::TestError>> {
        let sock_path = self.tmp_dir.path().join(format!(
            "test-{}.sock",
            self.test_seq
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let sock_path_str = sock_path.to_str().context("invalid socket str")?;
        let sock_path_cstr = std::ffi::CString::new(sock_path_str).unwrap();

        let mut xray = XRay::start(
            conn.log_dir.as_fd(),
            core::slice::from_ref(server),
            ConnMode::HttpProxyTest {
                listen: sock_path_str,
            },
            &self.config_path,
        )
        .context("failed to start xray")?;

        // wait for xray to start
        while rustix::fs::access(&sock_path_cstr, rustix::fs::Access::EXISTS).is_err()
            && xray
                .process
                .try_wait()
                .context("failed to wait for xray")?
                .is_none()
        {}

        let ret = self
            .runtime
            .block_on(self.tester.test_http_proxy_unix(&sock_path));

        conn.write_info(
            core::slice::from_ref(server),
            ConnectKind::ConnectTest {
                success: ret.is_ok(),
            },
        )
        .context("failed to write info")?;

        xray.stop().context("failed to stop xray")?;

        String::clear(&mut self.log_buf);
        match rustix::fs::openat(
            conn.log_dir.as_fd(),
            c"error.log",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::all(),
        ) {
            Ok(fd) => {
                std::fs::File::from(fd)
                    .read_to_string(&mut self.log_buf)
                    .context("failed to read log file")?;
            }
            Err(Errno::NOENT) => (),
            Err(e) => return Err(anyhow::Error::new(e).context("failed to open log file")),
        }

        for l in self.log_buf.trim().lines() {
            println!("[xray {}] stdout: {l}", conn.uuid);
        }

        Ok(ret)
    }
    fn tcping(
        &self,
        conn: &mut Connection,
        server: &ServerInfo<'_>,
        _: Duration,
    ) -> anyhow::Result<std::io::Result<TcpingResult>> {
        enum Addr<T> {
            Domain(T),
            Ip(SocketAddr),
        }

        let (server_addr, r) = match &server.server.settings {
            xray::OutboundSettings::VLess(vl) => match &vl.address {
                xray::RemoteAddr::Domain(host) => match (*host, vl.port).to_socket_addrs() {
                    Ok(r) => (Addr::Domain(r), Ok(())),
                    Err(e) => (
                        Addr::Ip(SocketAddr::V4(std::net::SocketAddrV4::new(
                            std::net::Ipv4Addr::UNSPECIFIED,
                            0,
                        ))),
                        Err(e),
                    ),
                },
                xray::RemoteAddr::Ip(addr) => (Addr::Ip(SocketAddr::new(*addr, vl.port)), Ok(())),
            },
        };
        let server_addr = match &server_addr {
            Addr::Domain(d) => d.as_slice(),
            Addr::Ip(a) => std::slice::from_ref(a),
        };
        let server_addr_valid = r.is_ok();

        let result = r.and_then(|_| {
            let (first, tail) = server_addr.split_first().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "No address is resolved")
            })?;

            let mut ret = conn_tester::tcping(first);
            if ret.is_ok() {
                return ret;
            }

            for sa in tail {
                ret = conn_tester::tcping(sa);
                if ret.is_ok() {
                    break;
                }
            }
            ret
        });

        conn.write_info(
            std::slice::from_ref(server),
            ConnectKind::Tcping {
                success: result.is_ok(),
                server_addr: if server_addr_valid {
                    Some(server_addr)
                } else {
                    None
                },
                result: result.as_ref().ok().cloned(),
            },
        )
        .context("failed to write connection info")?;

        Ok(result)
    }
    fn connect_servers(
        &self,
        conn: &mut Connection,
        servers: &[ServerInfo<'_>],
    ) -> anyhow::Result<()> {
        let xray = XRay::start(
            conn.log_dir.as_fd(),
            servers,
            ConnMode::Connect,
            &self.config_path,
        )
        .context("failed to start xray")?;
        conn.write_info(servers, ConnectKind::Connect)?;
        xray.wait()
    }
}

struct Tester<'ctx> {
    test_log_dir: BorrowedFd<'ctx>,
    check_stmt: rusqlite::Statement<'ctx>,
    update_stmt: rusqlite::Statement<'ctx>,
    net: &'ctx mut NetContext,
}
impl<'ctx> Tester<'ctx> {
    fn test<'s>(&mut self, url: &'s str) -> anyhow::Result<Option<ServerInfo<'s>>> {
        use yansi::Paint;

        let s = ServerInfo {
            url,
            server: match url_parser::vless::parse_to_xray(url) {
                Ok(v) => xray::OutboundConfig {
                    name: v.name,
                    protocol: v.protocol,
                    stream: v.stream,
                    settings: xray::OutboundSettings::VLess(v.settings),
                },
                Err(_) => return Ok(None),
            },
        };

        let name = s.server.name.as_ref().map_or("<unnamed>", Cow::as_ref);
        println!("{} {name} {url:?}", "Testing".blue());

        if self
            .check_stmt
            .exists((url,))
            .context("failed to query database")?
        {
            println!("Previous test failed, skip testing");
            return Ok(None);
        }

        let mut conn = Connection::new(self.test_log_dir).context("failed to create log dir")?;
        println!("[tcping {}] start testing {name} {url:?}", conn.uuid);
        match self
            .net
            .tcping(&mut conn, &s, Duration::from_secs(2))
            .context("failed to tcping")?
        {
            Ok(r) => {
                println!(
                    "[tcping {}] test succeed, peer address: {}",
                    conn.uuid, r.peer_addr
                )
            }
            Err(e) => {
                println!(
                    "{}",
                    format_args!(
                        "[tcping {}] test failed:\n{:?}",
                        conn.uuid,
                        anyhow::Error::new(e)
                    )
                    .yellow()
                );

                self.update_stmt
                    .execute((
                        url,
                        conn.uuid,
                        conn.timestamp
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as i64,
                        "tcping",
                        false,
                    ))
                    .context("failed to update database")?;
                return Ok(None);
            }
        }

        conn = Connection::new(self.test_log_dir.as_fd())
            .context("failed to create connection dir")?;
        println!("[xray {}] start testing {name} {url:?}", conn.uuid);
        let result = self
            .net
            .test_server(&mut conn, &s)
            .context("failed to test server connection")?;
        self.update_stmt
            .execute((
                url,
                conn.uuid,
                conn.timestamp
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64,
                "connect",
                result.is_ok(),
            ))
            .context("failed to update database")?;
        match result {
            Ok(_) => {
                println!(
                    "{}",
                    format_args!("[xray {}] test succeed", conn.uuid).green()
                );
                Ok(Some(s))
            }
            Err(e) => {
                println!(
                    "{}",
                    format_args!(
                        "[xray {}] test failed:\n{:?}",
                        conn.uuid,
                        anyhow::Error::new(e)
                    )
                    .yellow()
                );
                Ok(None)
            }
        }
    }
}

struct Context {
    test_log_dir: OwnedFd,
    conn_log_dir: OwnedFd,
    db: rusqlite::Connection,
    net: NetContext,
}
impl Context {
    fn new(log_root: &str, db: &str, test_url: &str, config_path: String) -> anyhow::Result<Self> {
        let uri = http::Uri::from_str(test_url).context("invalid test url")?;
        let net = NetContext {
            runtime: tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("failed to build tokio runtime")?,
            tmp_dir: TempDir::with_prefix("proxy-cli").context("failed to create temp dir")?,
            test_seq: AtomicUsize::new(0),
            tester: conn_tester::Tester::new(uri).context("failed to create tester")?,
            config_path,
            log_buf: String::new(),
        };
        let mut path = std::path::PathBuf::from(log_root);

        path.push("test");
        fn open_dir(path: &std::path::Path) -> Result<OwnedFd, Errno> {
            match rustix::fs::open(path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty()) {
                Ok(v) => Ok(v),
                Err(Errno::NOENT) => {
                    rustix::fs::mkdir(path, Mode::all())?;
                    rustix::fs::open(path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty())
                }
                Err(e) => Err(e),
            }
        }
        let test_log_dir = open_dir(path.as_path()).context("failed to open test log dir")?;

        path.set_file_name("connect");
        let conn_log_dir = open_dir(path.as_path()).context("failed to open connection log dir")?;

        let db = rusqlite::Connection::open(db).context("failed to open database")?;
        db.execute(
            concat!(
                "create table if not exists last_test (",
                "  url text primary key not null,",
                "  uuid blob not null,",
                "  timestamp integer not null,",
                "  kind text not null,",
                "  passed integer not null",
                ") strict"
            ),
            [],
        )
        .context("failed to init database")?;
        Ok(Self {
            conn_log_dir,
            test_log_dir,
            db,
            net,
        })
    }
    fn server_tester(&mut self) -> anyhow::Result<Tester<'_>> {
        Ok(Tester {
            test_log_dir: self.test_log_dir.as_fd(),
            check_stmt: self
                .db
                .prepare("select passed from last_test where url = ?1 and passed = false")
                .context("failed to build sql statement")?,
            update_stmt: self
                .db
                .prepare(concat!(
                    "insert or replace into last_test (",
                    "  url, uuid, timestamp, kind, passed",
                    ") values (?1, ?2, ?3, ?4, ?5)"
                ))
                .context("failed to build sql statement")?,
            net: &mut self.net,
        })
    }
    fn connect_servers(&mut self, servers: &[ServerInfo<'_>]) -> anyhow::Result<()> {
        let mut conn = Connection::new(self.conn_log_dir.as_fd())
            .context("failed to create connection dir")?;
        println!(
            "{}",
            yansi::Paint::cyan(&format_args!("[xray {}] connecting to server", conn.uuid))
        );
        self.net.connect_servers(&mut conn, servers)
    }
}

#[derive(clap::Subcommand)]
enum Cmd {
    ConnectSubscription {
        #[arg(long)]
        base64: bool,
        #[arg(long)]
        tries: Option<usize>,
        file: String,
    },
}
#[derive(clap::Parser)]
struct Cli {
    #[arg(long)]
    log_dir: String,
    #[arg(long)]
    database: String,
    #[arg(long)]
    config: String,
    #[arg(long, default_value = "https://www.google.com")]
    test_url: String,
    #[command(subcommand)]
    cmd: Cmd,
}

fn connect_subscription(
    ctx: &mut Context,
    tries: usize,
    base64: bool,
    subscription_path: &str,
) -> anyhow::Result<()> {
    let sub = {
        let raw = std::fs::read(subscription_path).context("failed to read subscription file")?;
        String::from_utf8(if base64 {
            use base64::prelude::*;
            BASE64_STANDARD
                .decode(&raw)
                .context("failed to decode base64")?
        } else {
            raw
        })
        .context("failed to decode utf8")?
    };

    let mut urls = sub
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.is_empty() { None } else { Some(l) }
        })
        .collect::<Vec<_>>();
    urls.shuffle(&mut rand::rng());
    let server = {
        let mut tester = ctx.server_tester()?;
        let mut iter = urls.get(..tries).unwrap_or(urls.as_slice()).iter();
        loop {
            let url_txt = *iter.next().context("No available server found")?;
            if let Some(s) = tester.test(url_txt)? {
                break s;
            }
        }
    };
    ctx.connect_servers(std::slice::from_ref(&server))
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let mut ctx = Context::new(&cli.log_dir, &cli.database, &cli.test_url, cli.config)?;
    match cli.cmd {
        Cmd::ConnectSubscription {
            base64,
            tries,
            file,
        } => connect_subscription(&mut ctx, tries.unwrap_or(usize::MAX), base64, &file),
    }
}
