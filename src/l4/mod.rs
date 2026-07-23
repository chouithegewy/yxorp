use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::process::Command;

use thiserror::Error;
use tracing::info;

use crate::config::{L4Protocol, L4ServiceConfig, ProxyConfig};

const IPVSADM: &str = "/usr/sbin/ipvsadm";

#[derive(Debug, Error)]
pub enum L4Error {
    #[error("ipvsadm is required for l4_services but was not found or is not executable")]
    MissingIpvsadm,
    #[error("ipvsadm preflight failed; l4_services require Linux IPVS and CAP_NET_ADMIN/root")]
    Preflight,
    #[error("failed to run ipvsadm {args:?}: {source}")]
    Execute {
        args: Vec<String>,
        source: std::io::Error,
    },
    #[error("ipvsadm {args:?} failed with status {status}: {stderr}")]
    Command {
        args: Vec<String>,
        status: String,
        stderr: String,
    },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct IpvsCommand {
    args: Vec<String>,
    ignore_failure: bool,
}

impl IpvsCommand {
    fn new(args: Vec<String>) -> Self {
        Self {
            args,
            ignore_failure: false,
        }
    }

    fn delete(args: Vec<String>) -> Self {
        Self {
            args,
            ignore_failure: true,
        }
    }

    pub fn args(&self) -> &[String] {
        &self.args
    }
}

impl fmt::Display for IpvsCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(IPVSADM)?;
        for arg in &self.args {
            f.write_str(" ")?;
            write_shell_arg(f, arg)?;
        }
        if self.ignore_failure {
            f.write_str("  # ignore failure")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct L4State {
    services: Vec<L4ServiceConfig>,
}

impl L4State {
    pub fn new(config: &ProxyConfig) -> Self {
        Self {
            services: config.l4_services.clone(),
        }
    }

    pub fn services(&self) -> &[L4ServiceConfig] {
        &self.services
    }
}

#[derive(Debug, Default)]
pub struct L4Reconciler;

impl L4Reconciler {
    pub fn preflight(config: &ProxyConfig) -> Result<(), L4Error> {
        if config.l4_services.is_empty() {
            return Ok(());
        }
        let version = Command::new(IPVSADM).arg("--version").output();
        match version {
            Ok(output) if output.status.success() => {}
            Ok(_) => return Err(L4Error::MissingIpvsadm),
            Err(_) => return Err(L4Error::MissingIpvsadm),
        }
        let list = Command::new(IPVSADM).arg("-Ln").output();
        match list {
            Ok(output) if output.status.success() => Ok(()),
            Ok(_) => Err(L4Error::Preflight),
            Err(_) => Err(L4Error::MissingIpvsadm),
        }
    }

    pub fn reconcile(previous: &[L4ServiceConfig], next: &[L4ServiceConfig]) -> Vec<IpvsCommand> {
        let mut commands = Vec::new();
        let mut deleted = HashSet::new();
        for service in previous.iter().chain(next.iter()) {
            let key = service_key(service);
            if deleted.insert(key) {
                commands.push(IpvsCommand::delete(delete_service_args(service)));
            }
        }
        for service in next {
            commands.push(IpvsCommand::new(add_service_args(service)));
            for real_server in &service.real_servers {
                commands.push(IpvsCommand::new(vec![
                    "-a".to_string(),
                    service_flag(service).to_string(),
                    service_addr(service),
                    "-r".to_string(),
                    format!("{}:{}", real_server.address, real_server.port),
                    "-g".to_string(),
                    "-w".to_string(),
                    real_server.weight.to_string(),
                ]));
            }
        }
        commands
    }

    pub fn apply(previous: &[L4ServiceConfig], next: &[L4ServiceConfig]) -> Result<(), L4Error> {
        let commands = Self::reconcile(previous, next);
        for command in &commands {
            run_ipvsadm(command)?;
        }
        if !commands.is_empty() {
            info!(commands = commands.len(), "reconciled l4 ipvs services");
        }
        Ok(())
    }

    pub fn render_plan(previous: &[L4ServiceConfig], next: &[L4ServiceConfig]) -> String {
        let commands = Self::reconcile(previous, next);
        if commands.is_empty() {
            return "# no l4 ipvs changes\n".to_string();
        }
        let mut out = String::new();
        for command in commands {
            out.push_str(&command.to_string());
            out.push('\n');
        }
        out
    }
}

pub fn render_config_plan(config: &ProxyConfig) -> String {
    L4Reconciler::render_plan(&[], &config.l4_services)
}

pub fn domain_summary(config: &ProxyConfig) -> String {
    let mut lines = Vec::new();
    for service in &config.l4_services {
        let mut domains = BTreeSet::new();
        for domain in &service.domains {
            domains.insert(domain.as_str());
        }
        lines.push(format!(
            "{}: {} -> {}:{} {}",
            service.name,
            domains.into_iter().collect::<Vec<_>>().join(", "),
            service.vip,
            service.port,
            service.protocol
        ));
    }
    lines.join("\n")
}

fn run_ipvsadm(command: &IpvsCommand) -> Result<(), L4Error> {
    let output = Command::new(IPVSADM)
        .args(&command.args)
        .output()
        .map_err(|source| L4Error::Execute {
            args: command.args.clone(),
            source,
        })?;
    if output.status.success() || command.ignore_failure {
        return Ok(());
    }
    Err(L4Error::Command {
        args: command.args.clone(),
        status: output.status.to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

fn add_service_args(service: &L4ServiceConfig) -> Vec<String> {
    vec![
        "-A".to_string(),
        service_flag(service).to_string(),
        service_addr(service),
        "-s".to_string(),
        service.scheduler.to_string(),
    ]
}

fn delete_service_args(service: &L4ServiceConfig) -> Vec<String> {
    vec![
        "-D".to_string(),
        service_flag(service).to_string(),
        service_addr(service),
    ]
}

fn service_key(service: &L4ServiceConfig) -> (std::net::IpAddr, u16, L4Protocol) {
    (service.vip, service.port, service.protocol)
}

fn service_flag(service: &L4ServiceConfig) -> &'static str {
    match service.protocol {
        L4Protocol::Tcp => "-t",
        L4Protocol::Udp => "-u",
    }
}

fn service_addr(service: &L4ServiceConfig) -> String {
    format!("{}:{}", service.vip, service.port)
}

fn write_shell_arg(f: &mut fmt::Formatter<'_>, arg: &str) -> fmt::Result {
    if arg.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'_' | b'-' | b'/')
    }) {
        return f.write_str(arg);
    }
    f.write_str("'")?;
    for ch in arg.chars() {
        if ch == '\'' {
            f.write_str("'\\''")?;
        } else {
            write!(f, "{ch}")?;
        }
    }
    f.write_str("'")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{L4Mode, L4RealServerConfig, L4Scheduler};

    fn service() -> L4ServiceConfig {
        L4ServiceConfig {
            name: "edge-web".to_string(),
            domains: vec!["example.com".to_string(), "www.example.com".to_string()],
            vip: "192.0.2.10".parse().unwrap(),
            port: 443,
            protocol: L4Protocol::Tcp,
            scheduler: L4Scheduler::Wrr,
            mode: L4Mode::IpvsDsr,
            real_servers: vec![
                L4RealServerConfig {
                    address: "10.0.0.11".parse().unwrap(),
                    port: 443,
                    weight: 2,
                },
                L4RealServerConfig {
                    address: "10.0.0.12".parse().unwrap(),
                    port: 443,
                    weight: 1,
                },
            ],
            health_check: Default::default(),
        }
    }

    #[test]
    fn renders_ipvs_dsr_plan() {
        let commands = L4Reconciler::reconcile(&[], &[service()]);
        let rendered = commands.iter().map(ToString::to_string).collect::<Vec<_>>();
        assert_eq!(
            rendered,
            vec![
                "/usr/sbin/ipvsadm -D -t 192.0.2.10:443  # ignore failure",
                "/usr/sbin/ipvsadm -A -t 192.0.2.10:443 -s wrr",
                "/usr/sbin/ipvsadm -a -t 192.0.2.10:443 -r 10.0.0.11:443 -g -w 2",
                "/usr/sbin/ipvsadm -a -t 192.0.2.10:443 -r 10.0.0.12:443 -g -w 1",
            ]
        );
    }

    #[test]
    fn deletes_previous_service_on_reconcile() {
        let mut previous = service();
        previous.vip = "192.0.2.20".parse().unwrap();
        let rendered = L4Reconciler::render_plan(&[previous], &[service()]);
        assert!(rendered.contains("ipvsadm -D -t 192.0.2.20:443"));
        assert!(rendered.contains("ipvsadm -A -t 192.0.2.10:443 -s wrr"));
    }
}
