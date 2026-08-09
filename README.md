# keystork

<img width="512px" alt="keystork logo" src="https://github.com/user-attachments/assets/83dbe9d5-a388-404c-8c8d-2eb77220670b" />

This started off as a "keystore2-over-ip" tool (hence the name), but it's scope-creeped into a more general headless-device-puppeteering swiss-army-knife, including reimplementing some `adb` functionality. This is useful when running a real `adb` is not possible.

There are two main components, `keystorkd` that runs on the target device, and a Python client library that runs on the host. The library also comes with a CLI tool.

An incomplete list of features:

- KeyStore access, with caller identity impersonation (e.g. assume the identity of any app).
- Remote file read (like `adb pull`).
- Remote exec (like `adb shell`)
- Play Integrity token extraction (TODO).
