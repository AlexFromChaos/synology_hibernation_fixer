# Synology DSM HDD hibernation fixer script

This script allows to fix multiple issues which prevent Synology NAS to have working HDD hibernation.

It is especially useful if you setup Docker containers on an NVMe partition - by default Synology NASes have a flaw which prevents HDD disks to hibernate when there is an ongoing NVMe activity.

The script integrates changes I've described [here](https://www.reddit.com/r/synology/comments/10cpbqd/making_disk_hibernation_work_on_synology_dsm_7/) and [here](https://www.reddit.com/r/synology/comments/129lzjg/fixing_hdd_hibernation_when_you_have_docker_on/)

## Features

- synocrond tasks control
- interactive mode to specify what to do with synocrond tasks to adjust to your NAS usage scenario
- applying in-memory patches for DSM binaries which prevent HDD hibernation to function normally when there is an NVMe activity (allows for eg. to setup noisy Docker containers on an NVMe partition and have working HDD hibernation)
- automatic remounting of rootfs as `noatime` to avoid random wake ups
- setting `noatime` for disk volumes
- **persists after DSM upgrades**. No need to reapply the script after DSM updates (as long as Synology doesn't break something)

The script should support all x86-based NAS models running DSM 7. Supported versions are 7.0, 7.1 and 7.2RC.

Some of the fixes might be usable on DSM 6 as well, but I don't have a NAS with DSM 6 to test.

## How it works

Upon installation, the script creates a **Task Scheduler** task which is triggered to execute after a boot up. The task is self-contained - it has everything to execute within its body, so there is no need to keep the script `.py`-file anywhere on your NAS after installing.

As this kind of scheduled tasks is preserved by DSM during a DSM upgrade, this approach allows to safely persist between DSM updates. Internally DSM keeps these tasks inside a database which has other user-added tasks.

When invoked, the task verifies synocrond tasks configuration, changes their settings if necessary (like after a DSM update), applies other fixes and then exits - nothing left executing in the background.

The script logs its execution in the `/var/log/hibernation_fixer.log` file.

## Usage

- login into your NAS via ssh
- (optionally) switch to **root** via `sudo -i`
- copy `hiber_fixer.py` (or just paste it via ssh) to any place on your NAS
- run `sudo python3 hiber_fixer.py --install`
- (optionally) reboot your NAS

The script enumerates all synocrond tasks, prints their short descriptions and allows user to specify new triggering interval for every task (or delete them). The choices are saved inside the script before installing.

### Uninstalling the script

You can simply delete the **HDD Hibernation Fixer task** task in DSM's **Task Scheduler**.

or, run

```bash
sudo python3 hiber_fixer.py --uninstall
```
