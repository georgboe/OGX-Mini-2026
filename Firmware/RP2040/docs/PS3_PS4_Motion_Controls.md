# PS3 / PS4 motion controls

**PS3** and **PS4** modes can forward **tilt / motion** from compatible input controllers into the emulated report (Sixaxis on PS3, accelerometer on PS4). **Switch** output mode does **not** pass through motion for now.

## PS4 mode and authentication

PS4 mode enumerates a DualShock 4–style USB gadget and passes buttons + motion. It can authenticate directly to a PS4 when a compatible, user-supplied key bundle has been installed through the WebApp. The firmware does not ship or generate authentication keys. Without an installed compatible bundle, use PS4 mode for PC testing or with an external licensed authentication adapter.

To install a key bundle, connect the device to the WebApp while it is in WebApp mode, select the GP2040-CE-compatible JSON bundle, and choose **Install keys**. Then reboot/switch to PS4 output mode. Keep key material private; the WebApp sends it directly over the USB serial connection to the adapter.

| | |
|--|--|
| **Select PS3 mode** | **Start + D-pad Left** (~3 s) |
| **Select PS4 mode** | **Start + Left Bumper + D-pad Left** (~3 s) |
| **Supported input (BT — Pico W / Pico 2 W)** | DualShock 4, DualSense, Switch Pro, **Wii Remote** (accelerometer) |
| **Supported input (wired USB host)** | DualShock 4, DualSense, Switch 1 Pro, Switch 2 Pro |
| **Wii Remote** | Point the **IR end at the TV**; motion is enabled automatically when motion output is active |
| **Play on a real PS3** | OGX-Mini → **USB authentication dongle** → console. **Tested with [Brook Wingman XE 2 Converter](https://www.brookaccessories.com/products/wingman-xe2).** |
| **Play on a real PS4** | Install a compatible key bundle through WebApp and connect directly, or use an external authentication adapter. |
| **PC testing (PS3/PS4)** | No Brook required — use PS3/PS4 mode on a PC/emulator to verify tilt |

**Typical chain for a PS3 motion game (e.g. *Flower*):**

```text
Wii Remote or DualSense (Bluetooth) → OGX-Mini (Pico W) → USB → Brook Wingman XE 2 → PS3
```

**Typical chain for PS4 motion (when using an external auth adapter):**

```text
Input pad → OGX-Mini (PS4 mode) → USB → licensed auth dongle (e.g. Brook) → PS4
```

Technical detail: [IMPROVEMENTS.md — motion passthrough](IMPROVEMENTS.md#ps3--ps4-output--motion-passthrough).
