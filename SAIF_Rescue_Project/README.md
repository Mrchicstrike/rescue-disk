# HIKMA Rescue Engine

HIKMA is a file-checking tool for Windows and Linux. It calculates each file's SHA-256 fingerprint and compares it with a list of known malware fingerprints. You can run it from a desktop window or a terminal, and keep using its saved signature list without internet access.

## In plain language

Think of HIKMA as a quick lookup tool: it checks whether a file's fingerprint is already in its database. It can't recognize brand-new threats unless their fingerprints are added, and a "clean" result does not guarantee a file is safe.

HIKMA can also check whether it can read a Windows registry hive and request SMART drive-health information where supported. Those are checks, not automatic repairs. The browser dashboard's sample workflow scans a temporary folder created for that workflow; use the desktop folder picker or the command line to scan your own files.

## What you can do

- Choose a folder and compare its files against the local signature database.
- Keep scanning offline, or refresh the database from MalwareBazaar when connected.
- Review detections and, when you choose a quarantining scan, move matching files to the quarantine folder.
- Run it through the desktop app, command line, or browser dashboard.
- Set it up in an Ubuntu virtual machine or on a persistent Ubuntu USB installation.

The online feed contains recent MalwareBazaar sample hashes. HIKMA downloads hashes only; it does not upload scanned files. Feed use is subject to [MalwareBazaar's terms](https://bazaar.abuse.ch/faq/#tos).

## Run it on Windows

Use the project's Python environment and launch the desktop app with:

```powershell
.\.venv\Scripts\python.exe main.py
```

To scan a folder without moving any files:

```powershell
.\.venv\Scripts\python.exe main.py --scan "C:\path\to\folder" --no-quarantine
```

## Run it on Ubuntu or Debian

From the project folder, install the Linux requirements:

```bash
bash setup_linux.sh
```

Start the desktop app with `./linux_run.sh`. Scan a folder with `./linux_run.sh --scan /path/to/folder --no-quarantine`. Files larger than 250 MB are skipped by default; add `--max-size-mb 0` to include all accessible file sizes.

Refresh signatures while online with `./linux_run.sh --update-signatures`. Normal scans use the saved local database, so network access is not required. If the update fails, HIKMA keeps using the local database.

To scan completed downloads as they appear and rescan the folder every six hours, keep this command running:

```powershell
py -3 main.py --watch-dir "$env:USERPROFILE\Downloads" --rescan-hours 6 --no-quarantine
```

On Ubuntu or Debian, use:

```bash
bash linux_run.sh --watch-dir "$HOME/Downloads" --rescan-hours 6 --no-quarantine
```

The watcher waits until a file's size and modification time stay unchanged for 10 seconds and ignores common download-in-progress suffixes. Keep the USB connected and the command window open. Add `--no-quarantine` to report detections without moving files; without it, matches are moved to the app's quarantine folder. HIKMA checks known hashes only, so a clean result does not prove a file is safe.

## Use it in VirtualBox

An Ubuntu Desktop guest is a convenient way to try HIKMA without installing Linux on your PC. Start with 2 CPUs, 4 GB of RAM, a 30 GB virtual disk, and NAT networking. NAT lets Ubuntu reach the internet for updates while keeping the browser dashboard on the guest by default.

Install Ubuntu in the VM, copy the project into the guest's home folder, then run `bash setup_linux.sh` followed by `./linux_run.sh`. Copying the project into the guest is preferable to running it directly from a shared folder, especially because the Windows Python environment cannot run on Linux.

A VM cannot see the host's whole C: drive automatically. To scan selected host files, share only the folder you need in VirtualBox, set the share to **read-only**, and scan its Linux mount path. For example:

```bash
./linux_run.sh --scan /media/sf_shared --max-size-mb 0 --no-quarantine
```

The scan can only examine files Linux can access. Locked files, permissions, filesystem errors, and large or unusual files may affect coverage.

## Use it from a USB drive

To carry the HIKMA app between Windows and Ubuntu, copy the project files to a USB drive formatted as exFAT. Do not copy the `.venv` or `.venv-linux` folders; virtual environments are specific to an operating system and computer. On Windows, install Python 3, run `setup_windows.bat` once, then launch `run_gui.bat`. On Ubuntu or Debian, run `bash setup_linux.sh` once, then launch with `bash linux_run.sh`. Each computer needs its own Python dependencies installed; after setup, HIKMA can scan offline. The USB holds the shared project files, not a portable copy of both operating systems' Python environments.

The provided ISO writer makes an Ubuntu installer; it does not copy HIKMA onto the USB. On Windows, use Rufus or balenaEtcher to write the Ubuntu ISO to an installer USB. For a persistent portable system, use a second USB drive (32 GB or larger) as the Ubuntu installation target. Choose **Install Ubuntu**, select that target USB for the installation and bootloader, and double-check the drive: installation erases it. Disconnect other external drives during setup to reduce the chance of selecting the wrong disk.

After Ubuntu boots from the installed USB, copy HIKMA onto it, run `bash setup_linux.sh`, then start `./linux_run.sh`. To scan an accessible Windows partition, use a read-only mount and the command above. Make sure Windows was fully shut down rather than hibernated; never force-write a partition Linux reports as unsafe.

The optional Linux ISO writer requires a whole, unmounted disk and an explicit `FLASH` confirmation:

```bash
sudo ./flash_usb.sh --iso /path/to/ubuntu.iso --device /dev/sdX
```

Writing an image erases the selected disk. Confirm the device name carefully before proceeding.