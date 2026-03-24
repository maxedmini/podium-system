# Podium SD Card Installer

This installer flow is designed for preparing Raspberry Pi SD cards from a Mac.

## Goal

Flash Raspberry Pi OS with Raspberry Pi Imager, then run one Mac command to make the card self-install the podium system on first boot.

The same base image can be reused for all three displays. Each card is customized by writing a different `DISPLAY_ID`.

## Pi Imager Checklist

Use the same Raspberry Pi Imager settings every time unless noted below.

### Required settings

- OS: `Raspberry Pi OS with desktop`
- Username: `event`
- Password: choose one fixed password and use it on all cards
- Configure Wi-Fi: `On`
- Wi-Fi SSID/password: set these if the Pi needs Wi-Fi on first boot
- Locale/timezone/keyboard: set as normal for your event setup

### Recommended settings

- Enable SSH: `On` if you want remote access later
- Hostname:
  - display 1 card: `podium-1`
  - display 2 card: `podium-2`
  - display 3 card: `podium-3`

### Important notes

- The first-boot installer assumes the Pi user already exists.
- That means the username must be created in Raspberry Pi Imager.
- If you change the username from `event`, you must enter the same username when running the SD card prep script or app.
- The Pi needs working network on first boot so it can pull the repo from GitHub and install packages.

## Recommended Values Per Card

Use these values when preparing cards:

### Display 1

- Pi Imager hostname: `podium-1`
- SD prep display number: `1`
- SD prep Pi username: `event`
- SD prep Pi hostname: `podium-1`
- SD prep server hostname: `podium-1.local`

### Display 2

- Pi Imager hostname: `podium-2`
- SD prep display number: `2`
- SD prep Pi username: `event`
- SD prep Pi hostname: `podium-2`
- SD prep server hostname: `podium-1.local`

### Display 3

- Pi Imager hostname: `podium-3`
- SD prep display number: `3`
- SD prep Pi username: `event`
- SD prep Pi hostname: `podium-3`
- SD prep server hostname: `podium-1.local`

## Prepare a Card From macOS

After flashing the card and letting the boot partition mount:

```bash
cd installer
./prepare_sd_card.sh --display 1 --pi-username event --hostname podium-1 --eject
```

Examples:

```bash
./prepare_sd_card.sh --display 1 --pi-username event --hostname podium-1 --server-host podium-1.local --eject
./prepare_sd_card.sh --display 2 --pi-username event --hostname podium-2 --server-host podium-1.local --eject
./prepare_sd_card.sh --display 3 --pi-username event --hostname podium-3 --server-host podium-1.local --eject
```

What this script writes to the SD card boot partition:

- `firstrun.sh`
- `podium-firstboot.sh`
- `podium.env`

On first boot, Raspberry Pi OS runs `firstrun.sh`, which runs the podium bootstrap installer.

## Clickable macOS App

If you want a click-to-run Mac app instead of Terminal:

```bash
cd installer
./build_prepare_sd_card_app.sh
```

That creates:

- `installer/Prepare Podium SD Card.app`

Double-click the app and it will prompt for:

- display number
- Pi hostname
- Pi username
- server hostname

Then it runs the same SD prep logic and ejects the card when complete.

## What First Boot Does

The first-boot bootstrap:

- reads `podium.env` from the boot partition
- optionally sets the hostname
- installs `git`
- clones this repo from GitHub
- writes `/etc/default/podium-kiosk`
- runs `installer/install.sh`
- reboots once when complete

## Per-Display Config

See [`podium.env.example`](./boot/podium.env.example).

Important values:

- `DISPLAY_ID=1|2|3`
- `PI_USERNAME=event`
- `PI_HOSTNAME=podium-1`
- `SERVER_HOST=podium-1.local`
- `SERVER_URL=http://podium-1.local:5001/display/1`

Display 1 installs both kiosk and server. Displays 2 and 3 install kiosk only.
