# 🧠 Keystone — The Next-Gen Runtime-Aware SCA Platform

> “Security intelligence that *understands what actually runs* — not just what’s imported.”

Keystone is a **next-generation Software Composition Analysis (SCA) platform** built to redefine how modern DevSecOps teams identify, understand, and remediate vulnerabilities.  
It merges static dependency scanning with **runtime intelligence**, **correlation graphs**, and **automated remediation**, forming a unified, cloud-native control plane for the software supply chain.

---

## 🌟 Vision

Keystone’s mission is simple yet bold —  
> Empower developers with **real, actionable security intelligence**, not noise.

Unlike legacy tools (Snyk, Dependabot, etc.) that only scan manifests, Keystone understands *runtime behavior*, *reachability*, and *impact*.  
By combining Go, Rust, and TypeScript across a distributed microservice architecture, Keystone transforms static reports into **live, contextual security insights**.

---

## 🚀 Core Architecture

## 🧠 Technologies Involved

| Layer | Technology | Purpose |
|-------|-------------|----------|
| **CLI** | Go + Cobra | Scans lockfiles, connects to OSV.dev |
| **Agent** | Rust + aya (eBPF) | Runtime reachability tracing |
| **API** | Go + Gin | REST + telemetry ingestion |
| **Orchestrator** | Go + NATS JetStream | Event router, job scheduling |
| **Policy** | Go + OPA/Rego | Evaluate org-level security policies |
| **Correlation** | Go + Neo4j | Build software graph and relationships |
| **Remediation** | Go + GitHub/GitLab APIs | Auto PRs, dependency patching |
| **Dashboard** | Next.js + TypeScript | Visualization and management |
| **Data Layer** | PostgreSQL + Neo4j | Scan findings, dependency graph |

---

## 🧩 Current Status — Phase 1 ✅ (60% Complete)

| Component | Progress | Notes |
|------------|-----------|-------|
| CLI (Go + Cobra) | ✅ Done | Lockfile parser + OSV lookup |
| Migrations (Goose + Postgres) | ✅ Done | Core schema + versioning |
| API Service (Gin) | ✅ Done | `/health` and `/v1/projects/:slug/scans/ingest` |
| Workspace Setup | ✅ Done | go.work multi-module support |
| Ingest Pipeline | ✅ Partial | Inserts scans & packages |
| JSON / Report Output | 🔜 Next | Export scan results |
| Post-scan Upload (`--post`) | 🔜 Next | CLI → API sync |
| CI Thresholds & Exit Codes | 🔜 Next | For GitHub Actions |
| Tests & Docs | 🔜 Later | Parser + integration |

---

## 💾 Local Development

### 1️⃣ Start Postgres
```bash
docker compose -f deploy/compose/docker-compose.yml up -d postgres
```

### 2️⃣ Run Migrations
```bash
cd cli
go run . migrate up
```

### 3️⃣ Start API Service
```bash
cd ../services/api
set POSTGRES_URL=postgres://keystone:keystone@localhost:5432/keystone?sslmode=disable
go run .
```

### 4️⃣ Test
```bash
curl http://localhost:8080/health
# -> {"ok":true}
```

---

## ⚔️ Why Keystone > Other

| Capability | **Other** | **Keystone** |
|-------------|-----------|---------------|
| Runtime Awareness | ❌ None | ✅ eBPF runtime tracing |
| Unified Scanning | ❌ Split tools | ✅ Single unified scan |
| Auto Remediation | ⚠️ Suggests | ✅ Creates PRs + verifies build |
| Supply Chain Detection | ⚠️ CVE-based | ✅ Anomaly & package poisoning |
| False Positive Reduction | ❌ Alerts all | ✅ Reachability-based suppression |
| Data Openness | ❌ Proprietary | ✅ OSV.dev + NVD open data |
| Developer Experience | ⚠️ Enterprise-first | ✅ CLI-first, GitOps-native |

---

## 🧩 Example Folder Structure

```
keystone/
├── agent/              # Rust (aya / eBPF)
├── cli/                # Go (Cobra)
│   ├── cmd/
│   ├── migrate.go
│   └── scan.go
├── services/
│   ├── api/            # Gin REST API
│   ├── orchestrator/
│   ├── correlation/
│   ├── policy/
│   └── remediation/
├── dashboard/          # Next.js frontend
├── deploy/
│   ├── compose/
│   ├── helm/
│   └── terraform/
└── go.work
```

---

## 🔮 Roadmap

| Phase | Goal | Key Milestones |
|-------|------|----------------|
| **1. Core CLI MVP** | ✅ Static scanning | OSV.dev + lockfile parsing |
| **2. Runtime-Aware Agent** | 🚧 Upcoming | eBPF traces + reachability map |
| **3. Unified Control Plane** | 🔜 | Orchestrator + NATS events |
| **4. Dashboard & Integrations** | 🔜 | Next.js analytics + Jira/CI |
| **5. Intelligent Automation** | 🔜 | AI remediation + anomaly detection |

---

## 🧭 Project Motto

> “Build securely — without slowing down innovation.”

---

## 🌍 License
MIT © 2025 **Mohammad Faisal**  
Keystone is open for collaboration — contributions, ideas, and feedback are welcome.

---

### 📊 View Live Diagram
🔗 [View architecture on Mermaid Live](https://mermaid.live/view#pako:eNqFVG1P2zAQ_iuWJfiy0jYUShsNpK4FNNRBl1T7sGWanOSaGNK4sx1GB_z3nZ0mTQeIL4nv5bnn7vI4jzQSMVCXLjLxJ0qZ1GTqBTkhe3vk9PSUjDMOuVbmbLyqCBPJVmnlNz5CxtPPPwKKz4-h7JxdCvKBjEUomTX9iOWKZCK6W_AMVEB_lqAJU2komIwRWp8t4hoedPtW2fM3rgqWEZazbK15tIWPEuRHqFfkmi-htC3EK5QmHQKfZhcbu8yIYVXBIY-DvDmlkEB8kPc8gldmxeivKrphn5mJ8Vmhysl53rngIUhcgHfuz-tmb2SUgtKSaSER1zQt8PwemydSFNpir0S4HRTZJWRMc5GbJW-tHeprEEe3pOw3LHgWg6wrzETGozWCy8MO7mY26niQCAL3LCtMQzXMgyXEvCJuWDsFRoUWZOYpsk9WTJu53tjxF1CKJTxPXuy3jpS816O5j4TmRa5A-1oCW75RdMI0e1HPOKvJlU4kKDu7Pfpfpw1V7pMFz2Nk3q7bLtLQm7dNncAKaSHHzdn6b7RygReo1g7eBXJwcPaEvDf-nHSUoQvokxGOideC32RdnmNSbPre5lhFb-JzyHD_Wq7ruM2YWZZ6zIYPMasizLhKieFuS_hdoOQM3CzWZNoFG3hTjmXhpmdTTUueJEZUT01Fvp9cau79vIa-yh6aSjdd2g_yWqA5_Ubh_7ub4t2N0RZNJI-pq2UBLboEuWTGpI8Ghx2mCA2oi8eYybuABvkzYlYs_y7EsoLhzU1S6i5YptAqVvglYcIZymWbYjQkxwJ_RtQ9thWo-0gfqDvsto-drnPUG5z0h8Ou06Jr6g6c9slw0DvsO71-rzt0nOcW_WsZu-1Bv-f0neM-AnqHQ-f5H8jr4uM)
