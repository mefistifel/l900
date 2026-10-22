# KITAI-CHIP AntiSpam updates

Public delivery channel for the KITAI-CHIP AntiSpam bot.

`release.json` identifies the approved version and SHA-256 of `bot.py`. The Windows server checks every 10 minutes while the installing Windows user is logged on and Docker Desktop is running. Update publication and server installation are separate operations.

Publish the source first and the manifest last. Never commit `.env`, bot tokens, VPN profiles, private keys, databases, backups, or runtime configuration. Releases update bot code only; VPN profile switching is managed independently by the installed VPN failover agent.

The initial release is version 1.8. Future changes require updating VERSION and release.json together. Keep release versions increasing; never change code under an already published version.
