# Getting started with Crepe

This guide takes a new macOS or Linux installation through preparation,
installation and a first analysis. Run commands in Terminal. After installation,
you use **`crepe`**; Cargo is needed only for source builds and Cargo-managed updates.

## Install a ready-made release (recommended)

Download [Crepe v1.2.3](https://github.com/cnc24/crepe/releases/tag/v1.2.3).
Choose the asset for your operating system and CPU. **Rust, Cargo and compiler
installation are not required for these binaries.**

| System | Download |
| --- | --- |
| macOS Apple Silicon (arm64) | `crepe-1.2.3-darwin-arm64.tar.gz` and its `.sha256` file |
| Ubuntu/Debian x86-64 | `crepe_1.2.3_amd64.deb` and its `.sha256` file |
| Fedora x86-64 | `crepe-1.2.3-1.x86_64.rpm` and its `.sha256` file |
| Other compatible Linux x86-64 | `crepe-1.2.3-linux-x86_64.tar.gz` and its `.sha256` file |

The Linux binaries need libpcap and compatible system libraries. Native package
managers check dependencies; the generic archive is not a statically linked,
universal Linux binary. No Windows, Intel Mac or Linux ARM64 binary is currently
provided. Use the source route below for a supported platform without a matching
binary. The macOS executable declares a minimum deployment target of macOS 11;
validation was performed on current macOS CI and locally on macOS 27, not every
older macOS release. It is not Apple Developer ID-notarized; if macOS requests
approval, use its normal Privacy & Security flow for downloaded software you trust.

### Apple Silicon Mac

Download the macOS archive and checksum into Downloads, then run:

```sh
cd "$HOME/Downloads"
shasum -a 256 -c crepe-1.2.3-darwin-arm64.tar.gz.sha256
mkdir -p crepe-1.2.3
tar -xzf crepe-1.2.3-darwin-arm64.tar.gz -C crepe-1.2.3
mkdir -p "$HOME/.local/bin"
install -m 755 crepe-1.2.3/crepe "$HOME/.local/bin/crepe"
export PATH="$HOME/.local/bin:$PATH"
crepe --version
crepe chocolate
```

The archive also includes the English manual and license notices. Keep them
with any copy you redistribute. Add the PATH line once to `~/.zshrc` to keep the
command available in new terminals. If another installation is selected, check
`command -v crepe` or invoke `"$HOME/.local/bin/crepe"` explicitly.

### Ubuntu/Debian or Fedora x86-64

From the directory containing the downloaded package and checksum, use the
commands for your distribution:

```sh
# Ubuntu/Debian
sha256sum -c crepe_1.2.3_amd64.deb.sha256
sudo apt install ./crepe_1.2.3_amd64.deb

# Fedora: use these instead
sha256sum -c crepe-1.2.3-1.x86_64.rpm.sha256
sudo dnf install ./crepe-1.2.3-1.x86_64.rpm
```

Then run `crepe --version` and `crepe chocolate`. These packages also contain a
Linux service definition; configuring and starting a background sensor is a
separate step described in the operations manual.

For the generic Linux archive, verify with `sha256sum -c`, extract the `.tar.gz`,
and install its `crepe` executable in `~/.local/bin` as in the Mac example. Obtain
libpcap from your distribution. Use a native package or a source build if the
binary reports an incompatible GLIBC or missing shared library.

You can now proceed to **Live traffic** below. The bundled sample-capture
examples require the source checkout (`git clone https://github.com/cnc24/crepe.git`
and `cd crepe`), but building the source is unnecessary when using a release binary.
You can also select one of your own PCAP/PCAPNG files in the interactive menu.

The remaining preparation/build steps are **only for installation from source**.
Do not assume an unrelated `brew install crepe`, `apt install crepe` registry
package is this project.

## 1. Prepare your computer

You need an internet connection for the initial download, Git, a native C/C++
build toolchain, libpcap development files, and Rust 1.96 or newer. Allow tens of
GB of free disk space for a full build and dependencies; the first build can
take a while. This is a build-space recommendation, not the size of the installed
program. Lower-memory machines can build with one job (see troubleshooting).
Windows is not a supported target for these instructions.

### macOS

Install Apple's Command Line Tools if they are not already installed:

```sh
xcode-select --install
```

Complete the installer dialog before continuing. If the tools are already
installed, no reinstall is needed. Check the installation:

```sh
xcode-select -p
git --version
clang --version
```

macOS supplies libpcap. Homebrew and the full Xcode application are not required
for this route. The project is tested on Apple Silicon macOS; an Intel Mac needs
a native build and is not covered by the current macOS CI runner.

### Ubuntu or Debian Linux

```sh
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libpcap-dev git curl ca-certificates
```

### Fedora Linux

```sh
sudo dnf install -y gcc gcc-c++ make pkgconf-pkg-config libpcap-devel git curl ca-certificates
```

The Linux package commands need administrator rights. Building Crepe itself
should run as your normal user. Other distributions need equivalent packages.

### Install Rust (both operating systems)

If `rustc --version` already reports 1.96 or newer and `cargo --version` works,
skip this step. Otherwise use the official Rust installer:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
rustc --version
cargo --version
```

Select the default stable installation when prompted. This command downloads
and executes the official rustup installer. If rustup is already installed but
your Rust is too old, run `rustup update stable` instead.

Official references: [Rust installation](https://doc.rust-lang.org/book/ch01-01-installation.html)
and [Apple Command Line Tools](https://developer.apple.com/documentation/xcode/installing-the-command-line-tools).

## 2. Download, build and install Crepe

Choose a working directory, then run:

```sh
git clone https://github.com/cnc24/crepe.git
cd crepe
cargo build --release --all-features --locked
mkdir -p "$HOME/.local/bin"
install -m 755 target/release/crepe "$HOME/.local/bin/crepe"
export PATH="$HOME/.local/bin:$PATH"
crepe --version
crepe --help
```

`--all-features` includes live capture and component plugins. Keep the downloaded
repository for its manual, examples and future updates. Run the file examples
below from this repository directory so the relative fixture paths work.

To keep `crepe` available after closing Terminal, add this line **once** to your
shell's startup file: `~/.zshrc` for the default macOS shell, or `~/.bashrc` for
interactive Bash on Linux. Open a new terminal afterwards.

```sh
export PATH="$HOME/.local/bin:$PATH"
```

Check `command -v crepe`: it should select the executable you installed. If an
older installation appears first, use `"$HOME/.local/bin/crepe"` explicitly or
correct the PATH ordering. You do not need Rust or Cargo to run the installed
executable. Keep libpcap installed for this full-feature build.

## 3. First analysis: no administrator rights needed

The repository includes synthetic captures, so no live network or router is
required to try Crepe:

```sh
crepe read example.pcap 'dst.port == 443'
crepe profiles
crepe chocolate fixtures/protocols.pcap
```

The first command should display two TCP packets addressed to port 443, one IPv4
and one IPv6. `chocolate` performs the deeper protocol analysis. In an interactive
terminal, `crepe chocolate` alone opens the file/interface source menu. Scripts
should pass a file or interface explicitly.

To save observations and query them later:

```sh
DEMO_STORE=$(mktemp -d /tmp/crepe-demo.XXXXXX)
crepe suzette fixtures/dns.pcap --store "$DEMO_STORE"
crepe query "$DEMO_STORE" 'event.type == dns.response | select event.id,flow.id,payload'
```

The store needs write permission and disk space. The temporary path above is for
a demo; choose a lasting directory for real data. Importing the same capture into
the same store twice is deliberately rejected.

## 4. Live traffic: choose an interface and check permissions

```sh
crepe interfaces
```

Choose an interface from this output. `lo0` is macOS loopback and `lo` is Linux
loopback; they show traffic generated locally on your computer. For normal
network traffic choose the Wi-Fi/Ethernet interface shown on your system; names
vary between machines. Capturing on your computer does not automatically show
all traffic elsewhere on your network.

For a small local test, run the command for your operating system in terminal 1:

```sh
# macOS
crepe chocolate -i lo0 --duration 10
# Linux: use this instead
crepe chocolate -i lo --duration 10
```

While it is running, generate loopback traffic in terminal 2:

```sh
ping -c 3 127.0.0.1
```

If capture fails with a permission error, repeat the capture command with
administrator privileges and the explicit installed executable path:

```sh
# macOS; substitute lo on Linux
sudo "$HOME/.local/bin/crepe" chocolate -i lo0 --duration 10
```

Your password is entered in Terminal and is not echoed. Elevated privileges are
needed only when your OS does not already grant capture access. File analysis
and historical queries do not need them. Avoid using `sudo` with an ordinary
user-owned store: newly created data may become root-owned. For persistent
Linux capture, use the dedicated [service setup](OPERATIONS.md#service-operation-and-metrics).
No permission changes to device files or globally privileged Crepe executable
are required by this guide. An empty result on an idle interface is normal.

## 5. Optional: receive NetFlow or IPFIX

This requires a router or other exporter configured to send supported UDP flow
records to this computer. Replace the example address with this computer's actual
LAN address before running:

```sh
crepe banane --listen YOUR_LAN_IP:2055 --duration 30
```

Configure the exporter with that same destination address and port. Permit
incoming UDP 2055 from the exporter in your firewall if needed. Without an
exporter sending data, the collector produces no flow records. The default
loopback listener accepts only local traffic. This step is not needed for PCAP
files or live packet analysis.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| `crepe: command not found` | Add `~/.local/bin` to PATH; try `"$HOME/.local/bin/crepe" --version`. |
| `cargo: command not found` | Complete Rust installation and run `. "$HOME/.cargo/env"`, or open a new terminal. |
| Rust version too old | Run `rustup update stable`; build with `cargo +stable build --release --all-features --locked`. |
| Missing compiler/linker or `pcap.h` / `-lpcap` | Finish the OS preparation steps and install the development packages, not only the libpcap runtime. |
| Build killed or out of memory | Close other memory-heavy applications and retry with `cargo build --release --all-features --locked -j 1`. |
| Capture command absent | Rebuild with `--all-features` and check `command -v crepe` for an older executable. |
| Permission denied during capture | Use the explicit-path `sudo` example above or your administrator's capture-permission setup. |
| Capture file not found | Run the examples from the cloned `crepe` directory, or give an absolute file path. |
| Unexpected configuration/interface | Run `crepe config`; see the [configuration layers](OPERATIONS.md#configuration-precedence-and-presentation). |
| No live observations | Check the selected interface, generate traffic and wait for the bounded capture to finish. |

## Update or uninstall

For a release installation, download and verify a newer matching asset, stop
Crepe, and repeat the binary/package installation steps. Remove a native Linux
package with `sudo apt remove crepe` or `sudo dnf remove crepe`; data and local
configuration may remain. Stop any configured sensor service before removal.


For a source installation, stop running Crepe processes, return to your cloned repository and
run the following. Back up persistent stores before an upgrade; consult the
[upgrade instructions](OPERATIONS.md#upgrades-and-public-contracts).

```sh
git pull --ff-only
cargo build --release --all-features --locked
install -m 755 target/release/crepe "$HOME/.local/bin/crepe"
crepe --version
```

To uninstall this user-local executable:

```sh
rm "$HOME/.local/bin/crepe"
```

This does not delete captures, stores, configuration or the source checkout.
For everyday commands, profiles, limits and services, continue with the
[English operations manual](OPERATIONS.md). Licensing is explained in
[LICENSING.md](LICENSING.md).

## Updating an existing installation

Starting with 1.2.3, archive installations can run `crepe update --check` and
`crepe update`. Versions before 1.2.3 must first install a current download.
DEB/RPM/Homebrew users should use their package installer; Cargo users should
reinstall with their chosen features. See the [update reference](OPERATIONS.md#updating-123-and-later)
for prerequisites, permissions, verification and standalone `--output` installs.
