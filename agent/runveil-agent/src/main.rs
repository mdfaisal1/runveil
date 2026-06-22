use std::collections::VecDeque;
use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use clap::Parser;
use log::{debug, error, info, warn};
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

/// Runveil runtime agent v0.2
///
/// Reads a JSON file of observed packages and reports them to the Runveil API
/// as runtime evidence. Runs once by default, or continuously with `--watch`
/// (local queue + periodic flush + retry-with-backoff on failure).
///
/// Instrumentation is file-based for now (a sidecar/sample app produces the
/// packages file); the network/queue/retry plumbing around it is what this
/// agent owns.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Project slug in Runveil (e.g. "test-node-service")
    #[arg(long, value_name = "SLUG", env = "RUNVEIL_PROJECT_SLUG")]
    project_slug: String,

    /// Base URL for the Runveil API
    #[arg(
        long,
        value_name = "URL",
        env = "RUNVEIL_API_BASE",
        default_value = "http://localhost:8080"
    )]
    api_base: String,

    /// Runtime token for this project (required by the API).
    /// Provide via --runtime-token OR set RUNVEIL_RUNTIME_TOKEN.
    #[arg(long, value_name = "TOKEN", env = "RUNVEIL_RUNTIME_TOKEN")]
    runtime_token: Option<String>,

    /// JSON file with observed packages: { "packages": [ { "name", "version" } ] }
    #[arg(long, value_name = "PATH")]
    packages_file: PathBuf,

    /// Environment label attached to observations (e.g. prod, staging, dev-local)
    #[arg(
        long,
        value_name = "ENV",
        env = "RUNVEIL_ENVIRONMENT",
        default_value = "dev-local"
    )]
    environment: String,

    /// Run continuously: re-read the packages file and flush every N seconds.
    /// Omit for a single one-shot observation.
    #[arg(long, value_name = "SECONDS")]
    watch: Option<u64>,

    /// Max send attempts per flush before giving up (one-shot) or
    /// re-queueing for the next tick (watch mode).
    #[arg(long, default_value_t = 4)]
    max_retries: u32,

    /// Increase log verbosity (info -> debug). RUST_LOG overrides this.
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Deserialize)]
struct PackagesFile {
    packages: Vec<RuntimePackage>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RuntimePackage {
    name: String,
    version: String,
}

/// Matches the API's RuntimeObservationRequest. `observed_at` is left to the
/// server (defaults to now()); for the typical few-second queue delay that is
/// accurate enough, and it keeps the agent free of a date/time dependency.
#[derive(Serialize, Debug, Clone)]
struct RuntimeObservationRequest {
    packages: Vec<RuntimePackage>,
    environment: String,
}

fn init_logging(verbose: bool) {
    let default_level = if verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_level))
        .format_timestamp_secs()
        .init();
}

fn read_packages(path: &PathBuf) -> Result<Vec<RuntimePackage>, Box<dyn std::error::Error>> {
    let contents = fs::read_to_string(path)?;
    let parsed: PackagesFile = serde_json::from_str(&contents)?;
    Ok(parsed.packages)
}

/// Resolve the runtime token from the flag/env (merged by clap). Exits if absent.
fn resolve_token(args: &Args) -> String {
    match args
        .runtime_token
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        Some(t) => t.to_string(),
        None => {
            error!("missing runtime token: pass --runtime-token or set RUNVEIL_RUNTIME_TOKEN");
            std::process::exit(1);
        }
    }
}

/// POST one observation with exponential-backoff retry.
/// Retries on network errors, 5xx, and 429; gives up on other 4xx (e.g. a bad
/// token is not going to fix itself by retrying).
fn send_with_retry(
    client: &Client,
    url: &str,
    token: &str,
    body: &RuntimeObservationRequest,
    max_retries: u32,
) -> Result<(), String> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        debug!(
            "POST {} (attempt {}/{}), packages={}",
            url,
            attempt,
            max_retries,
            body.packages.len()
        );

        match client
            .post(url)
            .header("X-Runveil-Token", token)
            .json(body)
            .send()
        {
            Ok(resp) => {
                let status = resp.status();
                let text = resp.text().unwrap_or_default();
                if status.is_success() {
                    info!(
                        "flushed {} package(s) [{}] -> {}",
                        body.packages.len(),
                        body.environment,
                        status
                    );
                    debug!("response: {}", text);
                    return Ok(());
                }
                if status.is_client_error() && status != StatusCode::TOO_MANY_REQUESTS {
                    // Non-retryable (e.g. 401 invalid token, 404 unknown project).
                    return Err(format!("non-retryable {}: {}", status, text));
                }
                warn!("attempt {} failed: {} {}", attempt, status, text);
            }
            Err(e) => {
                warn!("attempt {} network error: {}", attempt, e);
            }
        }

        if attempt >= max_retries {
            return Err(format!("gave up after {} attempt(s)", attempt));
        }

        // 0.5s, 1s, 2s, 4s, ...
        let backoff = Duration::from_millis(500u64.saturating_mul(1u64 << (attempt - 1)));
        debug!("backing off {:?}", backoff);
        thread::sleep(backoff);
    }
}

/// Continuous mode: each tick re-reads the packages file, enqueues it, and
/// drains the queue oldest-first. Batches that fail (after retries) stay queued
/// and are retried on the next tick — a simple durable-ish local queue.
fn run_watch(
    client: &Client,
    url: &str,
    token: &str,
    args: &Args,
    interval: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        "watch mode: flushing {} every {}s (env={}, max_retries={})",
        args.packages_file.display(),
        interval,
        args.environment,
        args.max_retries
    );

    let mut queue: VecDeque<RuntimeObservationRequest> = VecDeque::new();
    let tick = Duration::from_secs(interval);

    loop {
        // 1) Read current packages and enqueue as a batch.
        match read_packages(&args.packages_file) {
            Ok(packages) if !packages.is_empty() => {
                queue.push_back(RuntimeObservationRequest {
                    packages,
                    environment: args.environment.clone(),
                });
                debug!("enqueued batch; queue depth = {}", queue.len());
            }
            Ok(_) => warn!("packages file empty; nothing to enqueue this tick"),
            Err(e) => error!("failed to read packages file: {}", e),
        }

        // 2) Drain oldest-first; stop on first failure and keep the remainder.
        while let Some(batch) = queue.front().cloned() {
            match send_with_retry(client, url, token, &batch, args.max_retries) {
                Ok(()) => {
                    queue.pop_front();
                }
                Err(e) => {
                    warn!(
                        "flush failed, {} batch(es) still queued: {}",
                        queue.len(),
                        e
                    );
                    break;
                }
            }
        }

        thread::sleep(tick);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    init_logging(args.verbose);

    let token = resolve_token(&args);
    let url = format!(
        "{}/v1/projects/{}/runtime/observe",
        args.api_base.trim_end_matches('/'),
        args.project_slug
    );
    let client = Client::new();

    match args.watch {
        // Continuous daemon mode.
        Some(interval) => run_watch(&client, &url, &token, &args, interval),

        // One-shot mode.
        None => {
            let packages = read_packages(&args.packages_file)?;
            if packages.is_empty() {
                error!("no packages found in {}", args.packages_file.display());
                std::process::exit(1);
            }
            let body = RuntimeObservationRequest {
                packages,
                environment: args.environment.clone(),
            };
            match send_with_retry(&client, &url, &token, &body, args.max_retries) {
                Ok(()) => Ok(()),
                Err(e) => {
                    error!("observation failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}
