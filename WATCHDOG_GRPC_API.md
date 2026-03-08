# Watchdog gRPC API Reference

This document describes the gRPC API exposed by the watchdog service, based on:

- `proto/watchdog.proto`
- `src/grpc.rs` (server behavior/defaults)
- `cmd/ais/main.go` (real client usage patterns)

It is intended for building an API server/gateway that talks to watchdog reliably.

## Transport And Endpoint

- Protocol: unary gRPC (no streaming RPCs)
- Service: `artisan.watchdog.Watchdog`
- Default Unix Domain Socket: `/tmp/artisan_watchdog.sock`
- Full RPC method paths:
  - `/artisan.watchdog.Watchdog/ListApplications`
  - `/artisan.watchdog.Watchdog/GetApplication`
  - `/artisan.watchdog.Watchdog/GetCurrentLogs`
  - `/artisan.watchdog.Watchdog/QueryHistoricalLogs`
  - `/artisan.watchdog.Watchdog/ListBuilds`
  - `/artisan.watchdog.Watchdog/ListVerifications`
  - `/artisan.watchdog.Watchdog/GetSystemInfo`
  - `/artisan.watchdog.Watchdog/GetSecurityTripStatus`
  - `/artisan.watchdog.Watchdog/GetVersionInfo`
  - `/artisan.watchdog.Watchdog/ExecuteCommand`
  - `/artisan.watchdog.Watchdog/QueryUsage`

## Proto Source Of Truth

Use `proto/watchdog.proto` as the canonical contract.

Core messages:

- `ApplicationStatusMessage`
- `CurrentLogsResponse`
- `HistoricalLogsResponse`
- `UsageQueryResponse`
- `SystemInfo`
- `SecurityTripStatus`
- `VersionInfo`
- `CommandRequest` / `CommandResponse`

## Timestamp And Units

- Timestamps are Unix epoch seconds (`uint64`).
- Memory values are MB (`double`).
- CPU is percent (`float`/`double`).
- Network values are bytes (`uint64`).

## RPC Behavior Details

### 1) `ListApplications(Empty) -> ApplicationStatusList`

- Returns combined system + client app statuses.
- Server sorts by app name.
- Includes stdout/stderr rolling buffer snapshots and optional network usage.

### 2) `GetApplication(ApplicationStatusRequest) -> ApplicationStatusResponse`

- Request:
  - `name` required logically (empty just yields `found=false` unless an empty-key app exists, which normally does not).
- Response:
  - `found=true` and `status` populated when present.
  - `found=false` and `status` unset when missing.

### 3) `GetCurrentLogs(CurrentLogsRequest) -> CurrentLogsResponse`

- Request:
  - `application` is required.
  - `limit` optional.
- Validation:
  - Empty `application` returns gRPC `INVALID_ARGUMENT`.
- Defaults:
  - `limit=0` means `200`.
- Response:
  - `found=false` with empty arrays if app not found.
  - `found=true` includes most recent stdout/stderr lines (tail by `limit`) and `last_updated`.

### 4) `QueryHistoricalLogs(HistoricalLogsRequest) -> HistoricalLogsResponse`

- Request:
  - `application` required.
  - `start`, `end`, `stream`, `limit`, `cursor` optional.
- Validation:
  - Empty `application` returns gRPC `INVALID_ARGUMENT`.
- Defaults/normalization:
  - `end=0` => current timestamp.
  - `start=0` => `end - 86400` (last 24h).
  - If `end < start`, server swaps them.
  - `stream=UNSPECIFIED` is treated as `BOTH`.
- Pagination:
  - Cursor-based via `cursor`, `next_cursor`, `has_more`.
- Response:
  - `found` is `true` when at least one entry is returned.

### 5) `ListBuilds(Empty) -> BuildStatusList`

- Returns build statuses sorted by app name.
- `BuildStatusMessage.result` maps to:
  - `BUILD_RESULT_SUCCESS`
  - `BUILD_RESULT_FAILURE`

### 6) `ListVerifications(Empty) -> VerificationEntryList`

- Returns integrity verification entries sorted by `name`.

### 7) `GetSystemInfo(Empty) -> SystemInfo`

Returns:

- `identity`
- `system_apps_initialized`
- `ip_addresses`
- `manager_linked`
- `security_tripped`
- `security_trip_detected_at`
- `security_trip_summary`

### 8) `GetSecurityTripStatus(Empty) -> SecurityTripStatus`

Returns the security/tamper subset only:

- `tripped`
- `detected_at`
- `summary`

### 9) `GetVersionInfo(Empty) -> VersionInfo`

Returns:

- `watchdog_version` (`CARGO_PKG_VERSION`)
- `artisan_middleware_version` (build-time env, fallback `"unknown"`)

### 10) `QueryUsage(UsageQueryRequest) -> UsageQueryResponse`

- Request:
  - `application` required.
  - `start`, `end` optional.
- Validation:
  - Empty `application` returns gRPC `INVALID_ARGUMENT`.
- Defaults/normalization:
  - `end=0` => current timestamp.
  - `start=0` => `end - 86400`.
  - If `end < start`, server swaps them.
- Response:
  - If no data: `found=false` and zeroed metrics.
  - If data exists: `found=true` with averages/peaks/network totals and sample count.

### 11) `ExecuteCommand(CommandRequest) -> CommandResponse`

`CommandRequest` is a `oneof payload`:

- `start`
- `stop`
- `reload`
- `rebuild`
- `status`
- `info`
- `set`
- `get`

General response:

- `accepted` indicates command acceptance/result.
- `message` contains human-readable details.

Current server behavior by command:

- `start`:
  - Resolves requested app against allowed inventories before spawn.
  - System app names accepted as canonical or AIS-prefixed.
  - Client apps must be in the safe client runner list.
- `stop`:
  - Sends `SIGUSR1` to tracked process (graceful shutdown path).
- `reload`:
  - Sends `SIGHUP` to tracked process.
- `rebuild`:
  - Queues async rebuild work and returns immediately with `accepted=true` for queueing.
  - Use `ListBuilds` to get final outcome.
- `status`:
  - Returns summary text for a single app.
- `info`:
  - Returns summary text for system info.
- `set` and `get`:
  - Currently return `accepted=false`, message `"Not implemented"`.

`get` field values (from `GetConfigField`):

- `GET_CONFIG_FIELD_BUILD_COMMAND`
- `GET_CONFIG_FIELD_RUN_COMMAND`
- `GET_CONFIG_FIELD_DEPENDENCIES_COMMAND`
- `GET_CONFIG_FIELD_LOG_LEVEL`
- `GET_CONFIG_FIELD_MEMORY_CAP`
- `GET_CONFIG_FIELD_CPU_CAP`
- `GET_CONFIG_FIELD_MONITOR_DIRECTORY`
- `GET_CONFIG_FIELD_WORKING_DIRECTORY`
- `GET_CONFIG_FIELD_CHANGES_NEEDED`
- `GET_CONFIG_FIELD_DIR_SCAN_INTERVAL`

`set` value schema (`SetConfigValue.oneof value`):

- `build_command: string`
- `run_command: string`
- `dependencies_command: string`
- `log_level: string`
- `memory_cap: uint32`
- `cpu_cap: uint32`
- `monitor_directory: string`
- `working_directory: string`
- `changes_needed: uint32`
- `dir_scan_interval: uint32`

If payload is missing, response is:

- `accepted=false`
- `message="Command payload missing"`

## CLI Mapping (For Gateway Parity)

From `cmd/ais/main.go`:

- `ais list` -> `ListApplications`
- `ais info` -> `GetSystemInfo` + `GetVersionInfo`
- `ais status <app>` -> `GetApplication`
- `ais usage <app> [start] [end]` -> `QueryUsage`
- `ais logs-current <app> [limit]` -> `GetCurrentLogs`
- `ais logs-history <app> [stream] [start] [end] [limit] [cursor]` -> `QueryHistoricalLogs`
- `ais start|stop|reload|rebuild <app>` -> `ExecuteCommand` (matching payload)
- `ais get <app> <field>` -> `ExecuteCommand.get`
- `ais set <app> <field> <value>` -> `ExecuteCommand.set`

## Notes For API Server Implementers

- Use a Unix-socket-capable gRPC dialer (not plain TCP).
- Treat `found=false` responses as valid empty/missing data, not transport errors.
- For windowed APIs (`QueryUsage`, `QueryHistoricalLogs`), you can safely send `0` values and let watchdog apply defaults.
- For `QueryHistoricalLogs`, pass back `next_cursor` until `has_more=false`.
- For `ExecuteCommand.rebuild`, implement async UX: request accepted now, final result from `ListBuilds`.
- Do not assume `set/get` are operational yet.

## Minimal Request Examples (Conceptual)

- Start app:
  - `CommandRequest { start: { application: "ais_manager" } }`
- Stop app:
  - `CommandRequest { stop: { application: "ais_manager" } }`
- Query last-24h usage:
  - `UsageQueryRequest { application: "ais_manager", start: 0, end: 0 }`
- Query historical stderr only:
  - `HistoricalLogsRequest { application: "ais_manager", stream: LOG_STREAM_STDERR, start: 0, end: 0, limit: 300, cursor: 0 }`
