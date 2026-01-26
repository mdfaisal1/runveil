use std::fs;
use std::path::PathBuf;

use clap::Parser;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

/// Simple Runveil runtime agent v0.1
///
/// Reads a JSON file containing observed packages and sends a runtime
/// observation to the Runveil API.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Project slug in Runveil (e.g. "test-node-service")
    #[arg(long, value_name = "SLUG")]
    project_slug: String,

    /// Base URL for the Runveil API
    #[arg(long, value_name = "URL", default_value = "http://localhost:8080")]
    api_base: String,

    /// Runtime token for this project (required by the API)
    ///
    /// Provide via --runtime-token OR set RUNVEIL_RUNTIME_TOKEN in your shell.
    #[arg(long, value_name = "TOKEN")]
    runtime_token: Option<String>,

    /// JSON file with observed packages
    #[arg(long, value_name = "PATH")]
    packages_file: PathBuf,
}

#[derive(Deserialize)]
struct PackagesFile {
    packages: Vec<RuntimePackage>,
}

#[derive(Serialize, Deserialize, Debug)]
struct RuntimePackage {
    name: String,
    version: String,
}

#[derive(Serialize, Debug)]
struct RuntimeObservationRequest {
    packages: Vec<RuntimePackage>,
    // You can add environment/observed_at later if you want
    // environment: Option<String>,
    // observed_at: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // 1) Read observed packages from file
    let contents = fs::read_to_string(&args.packages_file)?;
    let parsed: PackagesFile = serde_json::from_str(&contents)?;

    if parsed.packages.is_empty() {
        eprintln!("No packages found in {}", args.packages_file.display());
        std::process::exit(1);
    }

    // 2) Build the request body
    let body = RuntimeObservationRequest {
        packages: parsed.packages,
    };

    // 3) Build URL: {api_base}/v1/projects/{slug}/runtime/observe
    let url = format!(
        "{}/v1/projects/{}/runtime/observe",
        args.api_base.trim_end_matches('/'),
        args.project_slug
    );

    println!("Sending runtime observation to: {}", url);

    // Resolve token: flag overrides env var
    let token = args
        .runtime_token
        .clone()
        .or_else(|| std::env::var("RUNVEIL_RUNTIME_TOKEN").ok())
        .filter(|t| !t.trim().is_empty())
        .unwrap_or_else(|| {
            eprintln!(
                "Missing runtime token. Provide --runtime-token or set RUNVEIL_RUNTIME_TOKEN."
            );
            std::process::exit(1);
        });

    let client = Client::new();
    let resp = client
        .post(&url)
        .header("X-Runveil-Token", token)
        .json(&body)
        .send()?;

    let status = resp.status();
    let text = resp.text().unwrap_or_default();

    println!("Status: {}", status);
    println!("Response body: {}", text);

    if !status.is_success() {
        eprintln!("Request failed with status {}", status);
        if status == StatusCode::NOT_FOUND {
            eprintln!("Check that the project slug and URL are correct.");
        }
        std::process::exit(1);
    }

    Ok(())
}
