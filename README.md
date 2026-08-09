# keystork

<img width="512px" alt="keystork logo" src="https://github.com/user-attachments/assets/83dbe9d5-a388-404c-8c8d-2eb77220670b" />

This started off as a "keystore2-over-ip" tool (hence the name), but it's scope-crept into a more general headless-device-puppeteering swiss-army-knife,
including reimplementing some `adb` functionality (useful when adbd isn't running as root, or isn't running at all).

The tool assumes you have unrestricted root access on a device with a locked bootloader and stock AVB keys.
This is relatively uncommon, but I'll soon be publishing tools to make it easier.

There are two main components, the `keystorkd` service that runs on the target device, and a Python client library that runs on the host.
The library also comes with a CLI tool.

An incomplete list of features:

- Play Integrity token minting.
- Unrestricted KeyStore access (including Android Key Attestation)
- Remote file read (like `adb pull`).
- Remote execve (like `adb shell`, but also scriptable via Python API).

## How We Sidestep Play Integrity Attestation

Despite what the marketing copy wants you to think, Play Integrity does not at all attest the integrity of an app.
In practice, it only attests the integrity of the early boot chain. 
If you have any exploit that kicks in after that point (e.g. root LPE), the world is your oyster.

Keystork's token extraction feature works by hooking the zygote app spawn, and substituting our own class .dex instead
of whatever classes the app originally wanted to load.
Our custom .dex ships a copy of the Play Integrity SDK, calls it, and hands the returned token back to the keystork daemon.
This blocks any of the app's original code from executing, so there's absolutely nothing the app can do to mitigate it.

## How We Sidestep Android Key Attestation

Access to KeyStore is gated only by the uid of the caller, so producing arbitrary """integrity""" attestations is trivial.
Just setuid to that of the target app, and ask nicely.

## Impacts

My use of the word "sidestep" instead of "break" is deliberate.
It would be misleading to say that this *completely* breaks Play Integrity and Android Key Attestation,
since you still need a genuine physical device in your posession to mint the tokens on.
We aren't pulling them out of thin air.
However, for many (most?) use cases it completely defeats the purpose.

Perhaps those who've been begging app developers to add GrapheneOS's AVB keys to their Android Key Attestation allowlist
should instead consider asking them to remove the attestation entirely (thus enabling support for GrapheneOS, *and* all other 3rd party OSes),
citing this repo as proof of its uselessness. If that doesn't work, open a PR adding their app to the `examples/` directory.
