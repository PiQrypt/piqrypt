# Telemetry System

**Version:** 1.10.0
**Date:** 2026-10-25
**Status:** Current

---

## Overview

PiQrypt sends a small anonymous usage event to the PiQrypt Trust Server. Telemetry is **enabled by default** and you can turn it off at any time. It lets the project see which versions, operating systems and features are in use.

A notice is printed the first time the `piqrypt` command line tool runs. A program that only imports the library (`import aiss` or `import piqrypt`) does not see that notice, but telemetry is on for it as well. For servers, containers and CI, set `PIQRYPT_TELEMETRY=0` (see below).

---

## Turn it off or on

```bash
piqrypt telemetry disable     # turn off
piqrypt telemetry enable      # turn on again
piqrypt telemetry status      # show the current state
```

Environment variable (an "off" value always wins over the configuration file):

```bash
export PIQRYPT_TELEMETRY=0    # also accepted: false, no, off (any case)
```

When telemetry is off, nothing is written to the local event log and nothing is sent. A random installation ID file (`~/.piqrypt/installation_id`) is still created on your machine; it is only transmitted while telemetry is on, and you can delete it. The only exception is the `piqrypt trial start` command: it sends this installation ID to the Trust Server to issue the trial, whatever the telemetry setting.

---

## What is sent

Each event is one HTTPS POST with exactly this body:

```json
{
  "installation_id": "3f2b8c1e-5a47-4d0e-9b61-0c7d2e8f4a19",
  "version": "1.10.0",
  "event": "identity_created",
  "system": { "os": "Linux", "arch": "x86_64", "is_server": false }
}
```

| Field | Meaning |
|---|---|
| `installation_id` | Random UUID created on first use and stored in `~/.piqrypt/installation_id`. It is not derived from your machine, your agents or your keys. |
| `version` | PiQrypt version. |
| `event` | Event name, for example `install`, `identity_created`, `event_signed`. |
| `system.os` | `Linux`, `Windows` or `Darwin`. |
| `system.arch` | CPU architecture, for example `x86_64` or `ARM64`. |
| `system.is_server` | `true` when standard output is not a terminal. |

## What is not sent

Agent IDs, event payloads, keys and passphrases, key store contents, signatures, file paths, host names, license keys, and the properties attached to events in your code. Those properties are written only to the local log described below.

## Local log

While telemetry is on, each event is also appended to `~/.piqrypt/telemetry.log` as one JSON line (event name, UTC timestamp, installation ID, version and the local-only properties). Read it to see what happened on your machine. Only the fields listed above leave it.

---

## What the server does with it

The Trust Server (`/api/telemetry`) checks that the three required fields are present, uses the installation ID only for that check and does not store it, derives a country code from the IP address of the request with a local GeoIP database (the code is `XX` when GeoIP is unavailable), discards the IP address, and increments counters grouped by event name, version, operating system, architecture, server or desktop, and country. The application keeps no record per installation and stores no IP address. The hosting provider's own infrastructure logs are outside the application's control.

## How it is sent

- HTTPS POST to `https://trust-server-ucjb.onrender.com/api/telemetry`.
- Synchronous, at the moment of the event, with a 3 second timeout. No retry, no queue. An unreachable server can therefore delay an event by up to 3 seconds.
- Every error is ignored: telemetry never raises an exception into your program, and PiQrypt works offline.
- To capture the requests on your own listener, or to send them to your own server, set `PIQRYPT_TELEMETRY_ENDPOINT` (for example `http://127.0.0.1:8000/api/telemetry`) before PiQrypt is first imported.

---

## Trial request

Only when you run `piqrypt trial start`, PiQrypt sends one HTTPS POST to `https://trust-server-ucjb.onrender.com/api/trial/start` with this body: `{"installation_id": "...", "client_version": "..."}`. The server answers with a signed license token valid for 30 days. To refuse a second trial on the same installation, it keeps, on a best-effort basis, a SHA-256 hash of the installation ID, the start and end dates and the client version. The application does not store the IP address; the hosting provider's own logs are outside its control. This request is sent whatever the telemetry setting, because you asked for the trial. To send it to your own server, set `PIQRYPT_TRIAL_ENDPOINT`.

---

## For organizations

Disable it centrally with the environment variable, for example in a service unit, a container image or a CI configuration:

```bash
# Ansible
- name: Disable PiQrypt telemetry
  lineinfile:
    path: /etc/environment
    line: 'PIQRYPT_TELEMETRY=0'
```

The installation ID is a random, persistent identifier. It is not linked to a person in PiQrypt's own systems, but your organization may still need to assess it under its own privacy rules (for example GDPR). This page describes behavior; it is not legal advice.

---

## FAQ

**Is telemetry enabled by default?** Yes. A notice is shown on the first run of the `piqrypt` command and the setting is written to `~/.piqrypt/telemetry.json`. If that file already exists, your earlier choice is kept.

**Can I see what is sent?** Yes. The full body is shown above, the local log records each event, and `PIQRYPT_TELEMETRY_ENDPOINT` lets you capture the requests on your own listener. The code is in `aiss/telemetry.py`.

**Can I use PiQrypt offline?** Yes. Failed sends are ignored.

**Can I host my own server?** Yes, with `PIQRYPT_TELEMETRY_ENDPOINT`. The body format is the one shown above.

---

**Last Updated:** 2026-10-25
**Version:** 1.10.0

---

**Intellectual Property Notice**

Core protocol concepts described in this document were deposited
via e-Soleau with the French National Institute of Industrial Property (INPI):

Primary deposit:  DSO2026006483 — 19 February 2026
Addendum:         DSO2026009143 — 12 March 2026

These deposits establish proof of authorship and prior art
for the PCP protocol specification and PiQrypt reference implementation.

PCP (Proof of Continuity Protocol) is an open protocol specification.
It may be implemented independently by any compliant system.
PiQrypt is the reference implementation.

© 2026 PiQrypt — contact@piqrypt.com
