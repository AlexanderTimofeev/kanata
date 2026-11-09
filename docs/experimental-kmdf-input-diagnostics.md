# Experimental KMDF input diagnostics — implementation specification

Status: EXPERIMENTAL; isolated branch `experiment/kmdf-input-diagnostics-20261109`. Revert/delete this branch when investigation is complete. This is NOT a driver change.

## Goal
Determine whether unexpected doubled letters originate before Kanata receives raw driver events, in Kanata's queue/engine, during output injection, or downstream in Windows/Punto Switcher. Preserve pre-incident context without recording unbounded logs.

## Controls
Windows `--features kmdf_driver` builds accept:
- `--input-diag off|anomalies|full` (default off).
- `--input-diag-dir PATH` (default `%LOCALAPPDATA%\Kanata\diagnostics`, fallback `%TEMP%\Kanata\diagnostics`).
The same flags apply to GUI/tray and CLI builds. Mode is selected on launch; restart the app to change it (no recompile). No registry changes or driver update.

Example **after compiling this branch**, with a writable directory and existing Kanata configuration:

```powershell
.\kanata-kmdf-diag-experimental.exe --cfg "D:\Projects\Keyboard\kanata\kanata.kbd" --input-diag=full --input-diag-dir="D:\Projects\Keyboard\Logs"
```

The config path above is only an illustration; use the actual config path from your current launcher. Only run one Kanata instance at a time. A running application cannot retroactively pick up an argument: restart Kanata for the chosen mode. Once an incident occurs, note the wall-clock time, keep the application running for another 5 seconds to capture the post-incident window, and copy the log files for analysis. Use `full` for a brief controlled experiment because the output may be duplicated downstream of Kanata without any anomaly detected in-process; use `anomalies` for longer-term observation.

## Capture
- Instrument `READ_EVENTS` reception, per-source queue enqueue/dequeue, mapping decisions, and KMDF injection attempts/results, including pass-through and ignored/repeated input.
- Every raw input event has a process-local monotonic sequence ID, device-interface identifier, source key code and up/down flags, and monotonic elapsed time. This ID follows the event through driver-read and Kanata input queue and the engine-queue submission; the present processing channel carries only KeyEvent, so ENGINE_PROCESS and asynchronous output events cannot yet be linked to the same sequence reliably.
- Preserve source timestamps (in process) for latency and first-order correlation.
- `DUP_DOWN`: repeated key down on the same source without an intervening up. `OUTPUT_DUP_DOWN` similarly flags repeat down on the outgoing KMDF stream. Both may be normal typematic repeat; label *suspect*, not a proven bug.
- `FAST_REPRESS`: up->down within 15ms (investigation hint, not error).
- `QUEUE_LAG`: queue residence exceeds 25ms.
- Log reader exits, IOCTL failures, and output errors.
- Output events are annotated with selected session/path, code/flags, and success/error of the IOCTL call; `OUTPUT_ATTEMPT` is recorded before the call. The reported IOCTL success does not prove that an application received exactly one character. Correlation to a single raw input is not always possible: tap-hold/macro/timer output can be delayed. Do not fabricate causality.
- The diagnostic sees only Kanata boundaries; Windows application text output and other remappers are outside scope. Mark them as unknown.

## Safe writing
- Non-blocking bounded `sync_channel(8192)` from the hot path, `try_send` only; dropped diagnostic records counted.
- Dedicated writer; no per-keystroke synchronous disk I/O on input or output threads.
- `full`: stream all stages; `anomalies`: keep at most the last 10 seconds and 8192 stage records in memory and write a window triggered by anomaly, extending five seconds after its last trigger. Since `anomalies` can only recognize patterns visible within Kanata, it cannot automatically detect duplicate text inserted by external programs or Windows when all Kanata outputs were normal.
- Rotation of at most five 10 MiB files in the diagnostic directory across runs (oldest files are deleted as new ones arrive). Each run uses unique `input-diag-*.log` names; files are never overwritten in place. Copy out incident logs promptly if retention matters.
- On I/O errors report to existing application logger, disable diagnostic file output, never fail key handling.
- No typed Unicode text, clipboard, or window titles. Physical scancode and modifier sequences, device paths, and inter-event timings are recorded in the selected diagnostic mode. Nonetheless scancodes can reconstruct sensitive text: logs must remain local and be reviewed/redacted before sharing.
- Fail-safe off default; no input filtering or suppression added.

## Verification and limits
- Build GUI and console Windows with `--features kmdf_driver` on a Windows machine with Rust toolchain (unavailable on Companion host).
- Smoke test flags, directory ACL failures, 10 MiB rotation, queue saturation, start/stop, keyboard hotplug, multiple physical keyboards, blocked writer, and existing tap-hold/layers.
- Test output from macros and SendInput; checks for missing key-up and double press.
- Compare diagnostic records around an incident with `kbdtest stats` on old installed driver (32-byte diagnostic protocol is compatible).
- No claim that duplicates are fixed until reproducible evidence pinpoints cause.

## Deferred
- Tray toggle, keyboard-wide correlation IDs for timer-driven events, Windows independent observer, extra DLL hooks, and updated driver counters. First iteration uses launch-time flags.
