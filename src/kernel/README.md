# Artisan Watchdog Kernel Components

This directory contains the Linux kernel pieces that back the Artisan watchdog
runtime. The kernel module exposes a character device that user space uses to
register a monitored process and deliver signed heartbeat messages. When the
heartbeats stop or fail validation, the module escalates to a user-mode helper
and, ultimately, a system reboot.

## Directory Layout

- `driver/` – Out-of-tree kernel module sources (`awdog.c`, `awdog.h`,
  `Makefile`).
- `init.sh` – Convenience script for inserting/removing the module on dev
  systems.

## Build and Install

```
make -C driver          # build awdog.ko against the running kernel
sudo insmod driver/awdog.ko
sudo rmmod awdog        # unload when finished
```

The module registers `/dev/awdog` and requires `CAP_SYS_ADMIN` to access.

## Module Behaviour

* State lives in a single global context (`struct awdog_ctx`). Registration
  locks a mutex, copies the caller-provided key/session data, seeds the timers,
  and opens the watchdog window.
* Heartbeats are fixed-size blobs (`struct awdog_hb`) written to the character
  device. Each heartbeat:
  - Must carry a strictly-increasing monotonic nonce.
  - Is authenticated with HMAC-SHA256 (`crypto_shash`).
  - Includes a monotonic and real-time timestamp so we can log latency
    information.
* On timeout or verification failure the module uses deferred work items to
  transition out of atomic context:
  - `awdog_queue_soscall()` captures the reason string and schedules a worker
    that invokes `/usr/bin/logger` via `call_usermodehelper()`.
  - `awdog_queue_reboot()` schedules a companion worker that eventually calls
    `emergency_restart()`.
  The queuing path avoids taking the module mutex in the timer callback, so we
  never sleep while the timer runs.
* Registration/unregistration and module exit flush the outstanding work items
  with `cancel_work_sync()` to guarantee user-mode helper invocations finish
  before teardown.

## User-Space Contract

`awdog.h` doubles as the UAPI header. User programs are expected to:

1. Open `/dev/awdog` with `O_WRONLY` (must be `CAP_SYS_ADMIN`).
2. Issue `AWDOG_IOCTL_REGISTER` with a populated `struct awdog_register` that
   includes:
   - Target PID and executable fingerprint (monitored binary identity).
   - Shared secret (`key`) for HMAC.
   - Heartbeat period/timeout (milliseconds).
   - Session identifier and protocol version.
3. Periodically write heartbeats (exactly `sizeof(struct awdog_hb)`) containing
   the updated nonce, timestamps, and computed HMAC.
4. On shutdown, send `AWDOG_IOCTL_UNREG` and close the file descriptor.

If the heartbeat stream stops or fails integrity checks, the module logs the
reason, attempts the configured user-mode helper, and triggers an emergency
restart. Any consumer that wants to observe or override these actions should
hook into the user-mode binaries referenced in `awdog_run_soscall()` or adjust
them during integration.

