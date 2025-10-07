# Artisan Watchdog

This crate hosts an experimental watchdog that supervises the platform's
critical AIS applications while exposing operational state through a gRPC
interface bound to a Unix domain socket. The current prototype focuses on
collecting process telemetry, consolidating state snapshots, and publishing
that data for external consumers.

## Components

### Runtime Stores
- **ApplicationStatusStore** (`src/definitions.rs:205`):
  Keeps the latest `ApplicationStatus` for each application, including CPU and
  memory usage along with rolling stdout/stderr buffers (500 entries).
- **BuildStatusStore** (`src/definitions.rs:206`):
  Tracks success/failure of system builds (`BuildStatus` structs).
- **VerificationStatusStore** (`src/definitions.rs:207`):
  Stores the most recent path verification results (`VerificationEntry`).
- **SystemInformationStore** (`src/definitions.rs:208`):
  Placeholder for host-level metadata (identity, IPs, manager linkage).
- **ChildProcessArray** (`src/definitions.rs:209`):
  Supervised process handle registry used for runtime observations.

### Monitoring Pipeline
- `monitor_application_states` (`src/functions.rs:85`) fires every 5 seconds.
  It loads `AppState` snapshots from `/tmp/.{ais}.state`, merges them with live
  metrics/stdout/stderr pulled from the process store, and updates
  `ApplicationStatusStore`.
- `rolling_buffer_from_entries` (`src/definitions.rs:220`) curves state-sourced
  logs into a `RollingBuffer` to enforce the 500 line cap.

### gRPC Server
- **Proto** (`proto/watchdog.proto`) defines RPCs for listing application
  status, builds, verifications, system info, and a `CommandRequest` envelope.
- **Server bootstrap** (`src/grpc.rs:26`) binds to
  `/tmp/artisan_watchdog.sock`, removing any stale socket first.
- **Service implementation** (`src/grpc.rs:87`):
  - `ListApplications`: Orders and returns all `ApplicationStatus` entries.
  - `GetApplication`: Fetches a single entry by AIS name.
  - `ListBuilds`: Returns recorded build status summaries.
  - `ListVerifications`: Returns the persisted verification results.
  - `GetSystemInfo`: Serialises `ArtisanSystemInformation` (currently sparse).
  - `ExecuteCommand`: Accepts command payloads but only logs a warning for now.
- **State wiring** (`src/main.rs:56`): Starts the gRPC server alongside the
  monitoring task and populates the verification store after hash checks.

### Build Pipeline
- `build.rs` runs `tonic_build` to generate gRPC bindings at compile time.
- `Cargo.toml` pulls in `tonic`, `prost`, `tokio`, `tokio-stream`, and
  `artisan_middleware`.
- `cargo check` ensures the workspace builds.

## Current Status
- Monitoring loop and gRPC server both run on Tokio tasks.
- Unix-socket endpoint is live but command execution RPCs are stubs.
- System info store is initialised but not yet populated with identity/IP data.
- Rolling stdout/stderr buffers propagate to the API.

## Next Tasks (Good Reentry Points)
1. **Populate System Information**
   - Load `/opt/artisan/identity` (via `artisan_middleware::identity`) and store
     the resulting `Identifier`.
   - Gather non-loopback IPv4 addresses.
   - Toggle `manager_linked` when the manager process announces itself.

2. **Implement Command Handling**
   - Map `CommandRequest` to existing control mechanisms (spawning, stopping,
     rebuilding) while enforcing validation and permissions.
   - Return structured responses via `CommandResponse`.

3. **Client/Integration Harness**
   - Create a simple CLI or test harness to connect to the Unix socket using
     tonic and verify responses.
   - Exercise `ListApplications`, `ListBuilds`, etc., to validate data shapes.

4. **State Persistence Enhancements**
   - Persist verification/build data beyond in-memory stores if required.
   - Add guard rails for missing or stale `/tmp/.{ais}.state` files.

5. **Testing & Tooling**
   - Add unit/integration tests around conversions in `src/grpc.rs` and the
     monitoring pipeline.
   - Consider logging/tracing improvements to surface gRPC access patterns.

Happy hacking!
