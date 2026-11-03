# Security policy

Security fixes target the maintained release. Check versions without automatic execution, then independently verify a fixed signed offline release or review/build its source before installation.

## Reporting a vulnerability

Please email leeguoooo@gmail.com with the affected version, platform, reproduction steps and expected impact. Do not put credentials, pairing records, private phone data or exploit details in a public issue. Share a minimal reproduction using synthetic data where possible.

We will assess reports and coordinate a fix and disclosure with the reporter. There is no guaranteed response time or bounty program.

## Security boundaries

The installed daemon listens on loopback by default with authentication; an explicitly credential-free local development process is not a remotely deployable configuration. Remote access requires explicit opt-in, distinct human/agent credentials and a configured verified HTTPS entry point; changing the bind address alone does not permit remote plaintext HTTP. Runner requests use per-launch signing credentials. Remote access should use an authenticated HTTPS proxy or VPN; do not expose device control ports directly to the internet. The default IPU_RUNNER_TRANSPORT=auto off-cable path uses the encrypted CoreDevice Wi-Fi tunnel. Explicitly setting IPU_RUNNER_ALLOW_LAN=1 additionally permits an unencrypted plain LAN relay, including the legacy iOS 15/16 fallback; use that only on a trusted, isolated network.

Control of an unlocked phone can expose personal data and perform actions in installed apps. Keep pairing records, signing keys and daemon credentials private. See [the security guide](docs/guide.md#security) and [privacy policy](docs/privacy.md).

## Hardened update and control boundaries

Unattended jobs are notification-only. The installer persistently disables the legacy auto-upgrade
job, and `upgrade` never downloads or executes an installer or refreshes plugins/skills. The separate
confirmed offline installer verifies a complete signed snapshot against an independently imported
trust root. Neither the download channel’s checksum nor a locally generated test key grants publisher
trust. See [signed releases](docs/security/signed-releases.md).

Authenticated identities, not owner labels, control task ownership and confirmation. Device and agent
revocation is durable; old prompts cannot authorize a different action. Registry content cannot grant
itself persistent flow approval. HTTPS relays are trusted terminators, not an end-to-end encryption
guarantee. Deployment prerequisites and migration instructions are in
[remote access](docs/security/remote-access.md).

Operational tracing omits raw messages, screen/input text, provider bodies and credentials. Timing
and run JSONL logs retain bounded statistics and per-process pseudonyms, not raw owner/run names.
Explicit user-requested task results, exported artifacts and diagnostic reports may still contain
phone data and must be handled as private. A process already running as the same OS user remains
outside the protection offered by file ownership and mode checks.
