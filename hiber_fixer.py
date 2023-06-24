#!/usr/bin/env python3
import sys, os, fnmatch, shutil, platform, time
import re
import struct
import subprocess
import signal
import logging as log
import json
import lzma
import base64
from ctypes import *
from collections import namedtuple

TASK_SCHEDULER_TASKNAME = "HDD Hibernation Fixer task"

LOGFILE = "/var/log/hibernation_fixer.log"
LOGLEVEL = log.DEBUG

BACKUP_DIR = "/var/synobackup"
SCEMD_PATH = "/usr/syno/bin/scemd"
SYNOSTORAGED_PATH = "/usr/syno/sbin/synostoraged"
SYNOWEBAPI_PATH = "/usr/syno/bin/synowebapi"
SYNOCROND_CONFIG_PATH = "/usr/syno/etc/synocrond.config"
SPACE_TABLE_PATH = "/var/lib/space/space_table"
VOLUME_CONF_PATH = "/usr/syno/etc/volume.conf"
SYNOINFO_CONF_PATH = "/etc/synoinfo.conf"
SYNOCACHED_CONF_DIRPATH = "/usr/syno/etc/synocached"


# patches is a list of tuples (orig_pattern, new_pattern, description)
BinaryPatchSet = namedtuple("BinaryPatchSet",
                            ["process_name", "binary_path", "patches"])

scemd_patchset = BinaryPatchSet("scemd", SCEMD_PATH, [
    (b'\x48\x89\xDE\xBF\x01\x00\x00\x00\x48\x89\x04\\x24\xE8(....)\x48\x89\xDE\xBF\x02\x00\x00\x00\x89\xC5\xE8(....)\x48\x89\xDE\xBF\x07\x00\x00\x00\xE8(....)\x85\xED',
     b'\x48\x89\xDE\xBF\x01\x00\x00\x00\x48\x89\x04\x24\xE8\g<01>\x48\x89\xDE\xBF\x02\x00\x00\x00\x89\xC5\xE8\g<02>\x48\x89\xDE\xBF\x0B\x00\x00\x00\xE8\g<03>\x85\xED',
     "NVMe I/O HDD hibernation fix for DSM 7.0-7.1"),
    (b'\x48\x89\xEE\xBF\x01\x00\x00\x00\x48\x89\x04\\x24\xE8(....)\x48\x89\xEE\xBF\x02\x00\x00\x00\x89\xC3\xE8(....)\x48\x89\xEE\xBF\x07\x00\x00\x00\xE8(....)\x85\xDB',
     b'\x48\x89\xEE\xBF\x01\x00\x00\x00\x48\x89\x04\x24\xE8\g<01>\x48\x89\xEE\xBF\x02\x00\x00\x00\x89\xC3\xE8\g<02>\x48\x89\xEE\xBF\x0B\x00\x00\x00\xE8\g<03>\x85\xDB',
     "NVMe I/O HDD hibernation fix for DSM 7.2"),
    ])

synostoraged_patchset = BinaryPatchSet("synostgd-disk", SYNOSTORAGED_PATH, [
    (b'\x4C\x89\xEE\xBF\x03\x00\x00\x00\xE8(....)\x85\xC0\x0F\x88(....)\x4C\x89\xEE\xBF\x07\x00\x00\x00\xE8(....)\x85\xC0\x0F\x88(....)\x4C\x89\xEE\xBF\x0B\x00\x00\x00\xE8',
     b'\x4C\x89\xEE\xBF\x03\x00\x00\x00\xE8\g<01>\x85\xC0\x0F\x88\g<02>\xEB\x13\xEE\xBF\x07\x00\x00\x00\xE8\g<03>\x85\xC0\x0F\x88\g<04>\x4C\x89\xEE\xBF\x0B\x00\x00\x00\xE8',
     "NVMe I/O HDD hibernation fix for DSM 7.0-7.1"),
    (b'\x48\x89\xDE\xBF\x03\x00\x00\x00\xE8(....)\x85\xC0\x0F\x88(....)\x48\x89\xDE\xBF\x07\x00\x00\x00\xE8(....)\x85\xC0\x0F\x88(....)\x48\x89\xDE\xBF\x0B\x00\x00\x00\xE8',
     b'\x48\x89\xDE\xBF\x03\x00\x00\x00\xE8\g<01>\x85\xC0\x0F\x88\g<02>\xEB\x13\xDE\xBF\x07\x00\x00\x00\xE8\g<03>\x85\xC0\x0F\x88\g<04>\x48\x89\xDE\xBF\x0B\x00\x00\x00\xE8',
     "NVMe I/O HDD hibernation fix for DSM 7.2"),
    ])


g_user_config = {
    #BEGIN_CONFIG_SECTION
    "builtin-synodbud-synodbud": "delete",
    "builtin-dyn-synodbud-default": "delete",
    "builtin-dyn-autopkgupgrade-default": "delete",
    "builtin-libhwcontrol-disk_daily_routine": "weekly",
    "builtin-libhwcontrol-disk_monthly_routine": "monthly",
    "builtin-libhwcontrol-disk_weekly_routine": "weekly",
    "builtin-libhwcontrol-syno_disk_health_record": "weekly",
    "builtin-libsynostorage-syno_disk_health_record": "weekly",
    "builtin-synobtrfssnap-synobtrfssnap": "monthly",
    "builtin-synobtrfssnap-synostgreclaim": "monthly",
    "builtin-synocrond_btrfs_free_space_analyze-default": "monthly",
    "builtin-synodatacollect-udc": "delete",
    "builtin-synodatacollect-udc-disk": "delete",
    "builtin-synorenewdefaultcert-renew_default_certificate": "monthly",
    "builtin-synorenewdefaultcert-default": "monthly",
    "builtin-synosharesnaptree_reconstruct-default": "weekly",
    "builtin-synosharing-default": "monthly",
    "builtin-synolegalnotifier-synolegalnotifier": "monthly",
    "builtin-synolegalnotifier-default": "monthly",
    "builtin-syno_ew_weekly_check-extended_warranty_check": "monthly",
    "builtin-syno_ew_weekly_check-default": "monthly",
    "builtin-syno_ntp_status_check-check_ntp_status": "monthly",
    "builtin-syno_ntp_status_check-default": "monthly",
    "builtin-libsynostorage-syno_disk_db_update": "monthly",
    "builtin-libsynostorage-syno_btrfs_metadata_check": "monthly",
    "pkg-ReplicationService-synobtrfsreplicacore-clean": "monthly",
    "builtin-Docker-docker_check_image_upgradable_job": "weekly",
    "pkg-Docker-docker_check_image_upgradable_job": "weekly",
    "pkg-Docker-default": "weekly",
    "builtin-ContainerManager-docker_check_image_upgradable_job": "weekly",
    "builtin-configautobackup-configautobackup": "unchanged",
    "builtin-dyn-configautobackup-default": "unchanged",
    "builtin-myds-job": "weekly",
    "builtin-dyn-myds-job": "weekly",
    "builtin-autopkgupgrade-autopkgupgrade": "weekly",
    "builtin-Spreadsheet-auto_clean_weekly": "monthly",
    "builtin-Spreadsheet-auto_office_clean_temp_daily": "weekly",
    "builtin-SynologyDrive-caculate-db-usage": "weekly",
    "builtin-SynologyDrive-cleanup-db": "weekly",
    "builtin-SynologyPhotos-SynologyPhotosDatabaseToolVacuum": "weekly",
    "builtin-CodecPack-CodecPackCheckAndUpdate": "monthly",
    "builtin-SynologyApplicationService-auto_vacuum_daily": "weekly",
    "builtin-DownloadStation-DownloadStationUpdateJob": "monthly",
    "builtin-DownloadStation-DownloadStationMonitorTransmissionJob": "weekly",
    "pkg-SynologyApplicationService-auto_vacuum_daily": "weekly",
    #END_CONFIG_SECTION
    }


_print_to_console = False

def err(mes):
    if _print_to_console:
        print(f"ERROR: {mes}")
    log.error(mes)

def warn(mes):
    if _print_to_console:
        print(f"WARNING: {mes}")
    log.warning(mes)

def info(mes):
    if _print_to_console:
        print(f"INFO: {mes}")
    log.warning(mes)


def get_pid_by_proc_name(process_name):
    try:
        return int(subprocess.check_output(["pidof", process_name]))
    except:
        return None


ProcMapEntry = namedtuple("ProcMapEntry", ["start", "end", "perm", "offset", "dev", "inode", "pathname"])

def parse_proc_maps(pid):
    entries = []
    maps_line_re = re.compile(r"(?P<start>[\da-f]+)-(?P<end>[\da-f]+)\s(?P<perm>\S+)\s(?P<offset>[\da-f]+)\s(?P<dev>\S+)\s+(?P<inode>\d+)\s+(?P<pathname>.*)$")

    try:
        with open(f"/proc/{pid}/maps", "r") as f:
            for line in f.readlines():
                m = maps_line_re.match(line)
                if not m:
                    log.debug(f"/proc/maps: skipping {line}")
                    continue

                start, end, perm, offset, dev, inode, pathname = m.groups()
                entries.append(ProcMapEntry(
                                start    = int(start, 16),
                                end      = int(end,   16),
                                perm     = perm,
                                offset   = int(offset, 16),
                                dev      = dev,
                                inode    = inode,
                                pathname = pathname.strip()))
    except:
        err(f"unable to access /proc/{pid}/maps")

    return entries

def get_module_base_addr(pid, module_name):
    entries = parse_proc_maps(pid)
    if not entries:
        return None

    filtered = [entry for entry in entries
                      if os.path.basename(entry.pathname) == module_name]
    if not filtered:
        return None

    for entry in filtered:
        if entry.offset == 0:
            return entry.start

    warn(f"didn't find the module {module_name} base addr")
    return None


# Returns a list of tuples (offset, orig_bytes, new_bytes)
# or None on error
def get_binary_patch_changelist(fpath, search_ptrn, replace_ptrn, max_matches=0):
    changes = []    

    try:
        with open(fpath, "rb") as f:
            data = f.read()
    except:
        err(f"cannot read {fpath}")
        return None

    nmatches = len(re.findall(search_ptrn, data, flags=re.DOTALL))
    if not nmatches:
        return None
    elif max_matches and nmatches > max_matches:
        err("too many matches encountered")
        return None

    new_data = re.sub(search_ptrn, replace_ptrn, data, flags=re.DOTALL)
    assert(len(new_data) == len(data))

    new_bytes  = bytearray()
    orig_bytes = bytearray()
    changes_offset = 0
    in_same = True

    for i in range(len(data)):
        if in_same:
            if new_data[i] == data[i]:
                continue
            else:   # start of a new changed area
                changes_offset = i
                new_bytes  = [new_data[i]]
                orig_bytes = [data[i]]
                in_same = False
        else:
            if new_data[i] != data[i]:  # changes continued
                new_bytes.append(new_data[i])
                orig_bytes.append(data[i])
            else:   # end of changes
                changes.append((changes_offset, bytes(orig_bytes), bytes(new_bytes)))
                new_bytes = orig_bytes = []
                in_same = True
    if not in_same and new_bytes:
        changes.append((changes_offset, bytes(orig_bytes), bytes(new_bytes)))

    return changes


libc = None

PTRACE_PEEKDATA = 2
PTRACE_POKEDATA = 5
PTRACE_ATTACH   = 16
PTRACE_DETACH   = 17

class iovec(Structure):
    _fields_ = [("iov_base", c_void_p),
                ("iov_len",  c_size_t)]

def init_ptrace():
    global libc
    libc = CDLL("libc.so.6")

    libc.process_vm_readv.argtypes = [c_uint64, POINTER(iovec), c_ulong,
                                      POINTER(iovec),  c_ulong, c_ulong]
    libc.process_vm_readv.restype  = c_ssize_t

    libc.process_vm_writev.argtypes = [c_uint64, POINTER(iovec), c_ulong,
                                      POINTER(iovec),  c_ulong, c_ulong]
    libc.process_vm_writev.restype  = c_ssize_t

    libc.ptrace.argtypes = [c_uint64, c_uint64, c_void_p, c_void_p]
    libc.ptrace.restype  = c_uint64

    libc.__errno_location.restype = POINTER(c_int)


# addrs_and_lens is a list of tuples (vaddr, num_bytes)
# Returns: list of 'bytes' entries
def read_mem_sg_list(pid, addrs_and_lens):
    iovcnt = len(addrs_and_lens)
    total_bytes = 0

    iovec_arr_type = iovec * iovcnt

    local_iov  = iovec_arr_type()
    remote_iov = iovec_arr_type()

    readbufs = []
    for i, (vaddr, part_len) in enumerate(addrs_and_lens):
        total_bytes += part_len
        entry_buf = create_string_buffer(part_len)
        readbufs.append(entry_buf)
        remote_iov[i] = iovec(c_void_p(vaddr), part_len)
        local_iov[i]  = iovec(cast(entry_buf, c_void_p), part_len)

    ret = libc.process_vm_readv(pid, local_iov, iovcnt, remote_iov, iovcnt, 0)
    if ret < 0:
        err("failed to read remote process memory, errno() = "
            f"{os.strerror(libc.__errno_location().contents.value)}")
        return []
    elif ret != total_bytes:
        err("partial remote process memory reads are unsupported")
        return []

    return [buf.raw for buf in readbufs]


# sg_list is a list of tuples (vaddr, bytes), process_vm_writev is a
# useless shit (only allows writes to the heap)
def write_mem_sg_list(pid, sg_list):
    ret = libc.ptrace(PTRACE_ATTACH, pid, None, None)
    if ret < 0:
        err(f"ptrace attach failed for pid {pid}")
        return False

    _, status = os.waitpid(pid, 0)
    if os.WIFSTOPPED(status):
        stop_signal = os.WSTOPSIG(status)
        if stop_signal != signal.SIGSTOP:
            err(f"tracee stopped on unexpected signal {stop_signal}")
            return False
    else:
        err(f"ptrace stop failed for pid {pid}")
        return False

    result = True
    for i, (vaddr, part_bytes) in enumerate(sg_list):
        part_len = len(part_bytes)

        for offset in range(0, part_len, 8):
            val = libc.ptrace(PTRACE_PEEKDATA, pid, c_void_p(vaddr+offset), None)

            if part_len - offset >= 8:
                data = part_bytes[offset:offset+8]
            else:
                nbytes_left = part_len - offset
                orig_bytes = struct.pack('<Q', val)
                data = part_bytes[offset:offset+nbytes_left] + \
                       orig_bytes[nbytes_left:]
                            
            val = struct.unpack("<Q", data)[0]

            ret = libc.ptrace(PTRACE_POKEDATA, pid, c_void_p(vaddr+offset), c_void_p(val))
            if ret < 0:
                err(f"ptrace write mem failed for pid {pid},"
                    "addr {:#x}, val {:#x}".format(vaddr+offset, val))
                result = False
                break

    ret = libc.ptrace(PTRACE_DETACH, pid, None, None)
    if ret < 0:
        err(f"ptrace detach failed for pid {pid}")

    return result


def apply_in_memory_patches(pid, base_addr, changelist):
    in_list = [(base_addr+offset, len(orig_bytes)) for offset, orig_bytes, _ in changelist]

    out_list = read_mem_sg_list(pid, in_list)
    if not out_list:
        err(f"failed reading memory for pid {pid}")
        return False

    matched_original = True
    matched_patched  = True
    for i, entry in enumerate(out_list):
        if matched_original and entry != changelist[i][1]:
            matched_original = False

        if matched_patched and entry != changelist[i][2]:
            matched_patched = False

    if matched_patched:
        info(f"pid {pid} already has in-memory patches applied")
        return True
        
    if not matched_original:
        err(f"encountered memory content mismatch for pid {pid}")
        return False

    write_list = [(base_addr+offset, new_bytes) for offset, _, new_bytes in changelist]

    log.debug(f"applying in-memory patches for pid {pid}")
    return write_mem_sg_list(pid, write_list)


def apply_binary_patchset(patchset):
    proc_name = patchset.process_name
    mod_fname = os.path.basename(patchset.binary_path)

    pid = get_pid_by_proc_name(proc_name)
    if not pid:
        err(f"cannot find pid of {proc_name} process")
        return False

    image_base = get_module_base_addr(pid, mod_fname)
    if not image_base:
        err(f"cannot find {mod_fname} image base")
        return False

    matched_any = False
    all_success = True
    for orig_pattern, new_pattern, patch_descr in patchset.patches:
        changelist = get_binary_patch_changelist(patchset.binary_path,
                                                 orig_pattern,
                                                 new_pattern,
                                                 max_matches=1)
        if changelist:
            matched_any = True

            rc = apply_in_memory_patches(pid, image_base, changelist)
            if not rc:
                all_success = False
                err(f"failed to apply patch '{patch_descr}' for {proc_name}")
            else:
                log.debug(f"successfully applied patch '{patch_descr}' for {proc_name}")

    return matched_any and all_success


def do_in_memory_fixes():
    init_ptrace()

    # allow HDD hibernation when there is an ongoing NVMe activity
    apply_binary_patchset(scemd_patchset)
    apply_binary_patchset(synostoraged_patchset)


def find_files_by_mask(pattern, path):
    result = []

    for root, dirs, files in os.walk(path):
        for name in files:
            if fnmatch.fnmatch(name, pattern):
                result.append(os.path.join(root, name))

    return result


def enumerate_synocrond_task_files():
    task_paths  = find_files_by_mask("*.conf", "/usr/syno/share/synocron.d/")
    task_paths += find_files_by_mask("*.conf", "/usr/syno/etc/synocron.d/")
    task_paths += find_files_by_mask("*.conf", "/usr/local/etc/synocron.d/")

    #log.debug(f"found {len(task_paths)} synocrond task files")
    return task_paths



SynocrondTask = namedtuple("SynocrondTask", ["task_name", "body"])

# Returns a dict {"fpath" -> [SynocrondTask, ...]}
def load_synocrond_task_files(task_paths):
    all_tasks = {}

    # loads jsons, resolves task name if there is no 'name' field
    # takes into account list/dict (creates multiple entries)
    for taskpath in task_paths:
        try:
            all_tasks[taskpath] = []

            with open(taskpath) as f:
                obj = json.load(f)

            if isinstance(obj, dict):
                file_tasks = [obj]
            elif isinstance(obj, list):
                file_tasks = obj
            else:
                err(f"unknown JSON format while parsing the task file {taskpath}")
                continue

            fname = os.path.basename(taskpath)
            if '.' in fname:
                fname = fname.split('.')[0]

            for task in file_tasks:
                if "name" in task:
                    task_name = "builtin-" + fname + '-' + task["name"]
                else:
                    task_name = "builtin-" + fname + "-default"

                all_tasks[taskpath].append(SynocrondTask(task_name, task))

        except Exception as e:
            err(f"got exception {e} while parsing the task file {taskpath}")
            continue

    return all_tasks

def load_synocrond_config():
    try:
        with open(SYNOCROND_CONFIG_PATH) as f:
            return json.load(f)
    except:
        return None

def save_synocrond_config(synocrond_config):
    try:
        shutil.copy(SYNOCROND_CONFIG_PATH, BACKUP_DIR)

        with open(SYNOCROND_CONFIG_PATH, "w") as f:
            json.dump(synocrond_config, f, indent=4)
            return True
    except:
        return False


def syno_get_key_value(conf_file, key):
    try:
        ret = subprocess.check_output(["/usr/syno/bin/synogetkeyvalue",
                                       conf_file, key],
                                       universal_newlines=True)
        return ret.strip()
    except:
        return None

def syno_set_key_value(conf_file, key, value):
    try:
        ret = subprocess.call(["/usr/syno/bin/synosetkeyvalue",
                              conf_file, key, value])
        return ret
    except:
        warn(f"failed to set {key}={value} in {conf_file}")
        return None


def remount_root_norelatime():
    need_remount = True
    try:
        ret = subprocess.check_output(["mount"], universal_newlines=True)
        lines = ret.split('\n')
        for line in lines:
            if "md0 on / " in line and "noatime" in line:
                need_remount = False
                break
    except:
        pass

    if not need_remount:
        return

    try:
        ret = subprocess.call(["mount", "-o", "noatime,remount", "/"],
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    except:
        ret = 1

    if ret:
        err("remounting md0 failed, expect a lot of HDD wakeups due to relatime")




def list_synoscheduler_tasks():
    try:
        out = subprocess.check_output([SYNOWEBAPI_PATH,
                                       "--exec", "api=SYNO.Core.TaskScheduler",
                                       "method=list",
                                       "version=2"],
                                       stderr=subprocess.DEVNULL)
        print(f"Regular Task Scheduler tasks:\n{out.decode()}")

        out = subprocess.check_output(["esynoscheduler", "--list"],
                                       stderr=subprocess.DEVNULL)
        print(f"Event-based Task Scheduler tasks:\n{out.decode()}")

    except:
        print("ERROR: failed to enumerate Task Scheduler tasks")


def add_esynoscheduler_task(task_name, event_type, description, operation):
    try:
        args = ["esynoscheduler", "--create", f'task_name={task_name}',
                f"event={event_type}", "enable=true", "operation_type=script",
                f"operation={operation}"]

        if description:
            args.append(f"description={description}")

        args.append(r'owner={"0":"root"}')  # uid:name

        # other optionals:
        #  - depend_on_task=s
        #  - notify_enable=b
        #  - notify_mail=b
        #  - notify_if_error=b
        #  - extra=s
        ret = subprocess.check_output(args, stderr=subprocess.DEVNULL).decode()
    except:
        err(f"failed to create Task Scheduler task '{task_name}'")
        return False

    return True if "save ok" in ret else False

def remove_esynoscheduler_task(task_name):
    try:
        ret = subprocess.check_output(["esynoscheduler", "--delete",
                                       f'task_name={task_name}'],
                                      stderr=subprocess.DEVNULL).decode()
    except:
        err(f"failed to delete Task Scheduler task '{task_name}'")
        return False

    return True if "delete task ok" in ret else False


UDC_DESC = "user data collection related"
SYNODBUD_DESC = "updates misc DBs: syno-abuser-blocklist, geoip-database, ca-certificates, securityscan-database"
SYNO_DISK_HEALTH_RECORD_DESC = "parses /var/log/disk_overview.xml which has disk-related stats like remaining life, errors and other information"
EW_WEEKLY_CHECK_DESC = "queries synology website for 'extended warranty' info, using device information, updates /var/cache/ew_info_cache.json"
SYNOLEGALNOTIFIER_DESC = "'legal data downloader'. Downloads user agreements from Synology site, can notify user about them"
NTP_STATUS_CHECK_DESC = "runs NTP time sync"
RENEW_DEFAULT_CERTIFICATE_DESC = "processes cryptographic certificates - generates some, checks expiration, deletes, copies"
DOCKER_CHECK_IMAGE_UPGRADABLE_DESC = "Docker upgradable image checker tool"

known_task_descriptions = {
    "builtin-synodbud-synodbud": SYNODBUD_DESC,  # /usr/syno/etc/synocron.d/synodbud.conf
    "builtin-dyn-synodbud-default": SYNODBUD_DESC,
    "builtin-dyn-autopkgupgrade-default": "update checker for installed packages",
    "builtin-libhwcontrol-disk_daily_routine": "disk SMART info collector, updates info in /var/log/diskprediction/",
    "builtin-libhwcontrol-disk_monthly_routine": "runs syno_disk_performance_monitor which works with HDD performance stats data in /var/log/disk-latency/",
    "builtin-libhwcontrol-disk_weekly_routine": "checks SMART/hotspare status for disks, updates information in /var/log/smart_result/, adds data to /var/log/disk-latency/.SYNODISKLATENCYDB",
    "builtin-libhwcontrol-syno_disk_health_record": SYNO_DISK_HEALTH_RECORD_DESC,
    "builtin-libsynostorage-syno_disk_health_record": SYNO_DISK_HEALTH_RECORD_DESC,
    "builtin-synobtrfssnap-synobtrfssnap": "cleans up all deleted subovlumes in the system",
    "builtin-synobtrfssnap-synostgreclaim": "checks the number of deleted BTRFS volumes which need reclaiming",
    "builtin-synocrond_btrfs_free_space_analyze-default": "calculates BTRFS fragmentation level for disks and writes results to a per-volume file 'frag_analysis'",
    "builtin-synodatacollect-udc": UDC_DESC,
    "builtin-synodatacollect-udc-disk": UDC_DESC,
    "builtin-synorenewdefaultcert-renew_default_certificate": RENEW_DEFAULT_CERTIFICATE_DESC,
    "builtin-synorenewdefaultcert-default": RENEW_DEFAULT_CERTIFICATE_DESC,
    "builtin-synosharesnaptree_reconstruct-default": "runs /usr/syno/sbin/synosharesnaptree -x <volume>, which reconstructs BTRFS snapshot tree",
    "builtin-synosharing-default": "does cleanup of SQLite DB tables (session/token/entry) in /usr/syno/etc/private/session/sharing/sharing.db",
    "builtin-synolegalnotifier-synolegalnotifier": SYNOLEGALNOTIFIER_DESC,
    "builtin-synolegalnotifier-default": SYNOLEGALNOTIFIER_DESC,
    "builtin-syno_ew_weekly_check-extended_warranty_check": EW_WEEKLY_CHECK_DESC,
    "builtin-syno_ew_weekly_check-default": EW_WEEKLY_CHECK_DESC,
    "builtin-syno_ntp_status_check-check_ntp_status": NTP_STATUS_CHECK_DESC,
    "builtin-syno_ntp_status_check-default": NTP_STATUS_CHECK_DESC,
    "builtin-libsynostorage-syno_disk_db_update": "downloads the archive with Synology disk compatibility database and extracts it",
    "builtin-libsynostorage-syno_btrfs_metadata_check": "checks BTRFS metadata usage and sends email notifications regarding it",
    "pkg-ReplicationService-synobtrfsreplicacore-clean": "cleanups 'received' BTRFS backup snapshots",
    "builtin-Docker-docker_check_image_upgradable_job": DOCKER_CHECK_IMAGE_UPGRADABLE_DESC,
    "pkg-Docker-docker_check_image_upgradable_job": DOCKER_CHECK_IMAGE_UPGRADABLE_DESC,
}

def get_synocrond_task_description(taskname):
    if taskname in known_task_descriptions:
        return known_task_descriptions[taskname]

    if taskname.startswith("pkg-"):
        return "package-installed synocrond task"

    return ""   # unknown


def get_task_period(task_config):
    period = task_config["period"]

    if period == "crontab" and "crontab" in task_config:
        crontab = task_config["crontab"]
        period += f" ({crontab})"

    return period

def get_task_recommended_action(task_name):
    if task_name in g_user_config:
        return g_user_config[task_name]

    log.debug(f"Encountered unfamiliar task {task_name}, suggesting to leave it unchanged")
    return "unchanged"

# Returns a dictionary of tuples
# "task name": (current_period, description, default_option)
def get_task_list_for_install():
    result = {}
    all_files_tasks = {}

    task_files_paths = enumerate_synocrond_task_files()
    if task_files_paths:
        all_files_tasks = load_synocrond_task_files(task_files_paths)

    for tasks in all_files_tasks.values():
        for synotask in tasks:
            task_name = synotask.task_name
            descr = get_synocrond_task_description(task_name)
            cur_period = get_task_period(synotask.body)
            recommended_opt = get_task_recommended_action(task_name)
            result[task_name] = (cur_period, descr, recommended_opt)

    synocrond_config = load_synocrond_config()
    if not synocrond_config:
        err("(install) cannot load synocrond.config")
        return result

    jobs = synocrond_config["jobs"]

    for task_name in jobs.keys():
        # DSM 7.2 task naming change
        clean_task_name = task_name
        if task_name.find("synocrond-job-") == 0:
            clean_task_name = task_name.replace("synocrond-job-", "")

        descr = get_synocrond_task_description(clean_task_name)
        cur_period = get_task_period(jobs[task_name]["config"])
        recommended_opt = get_task_recommended_action(clean_task_name)
        result[clean_task_name] = (cur_period, descr, recommended_opt)

    return result


# ask user for choices, fill g_user_config
def generate_user_config():
    global g_user_config

    tasks = get_task_list_for_install()

    import textwrap
    prompt = ("Select desired triggering periods for synocrond tasks. Depending "
              "on your NAS usage scenario you might want to leave some of them "
              "enabled (for eg. periodic BTRFS-related maintaining jobs). If you "
              "don't want to specify your setup, you can just press Enter for all "
              "tasks to choose the default recommended values")
    prompt_wrap = "\n".join(textwrap.wrap(prompt, width=100))

    try:
        print("-" * 100)
        print(prompt_wrap)
        print("-" * 100)
        input("Press Enter to start")
        ntasks = len(tasks.keys())

        for i, taskname in enumerate(tasks.keys()):
            cur_period, descr, default_option = tasks[taskname]

            while True:
                print("\nTask {:02}/{:02}: {}".format(i+1, ntasks, taskname))
                if descr:
                    print(f"Description: {descr}")
                print(f"Current triggering interval: {cur_period}")
                print("New triggering interval, (u)nchanged, (w)eekly, (m)onthly, "
                      f"(d)elete (default - {default_option}): ", end='')
                ch = input()

                if not ch:
                    ch = default_option

                selected = ""
                if ch[0] == 'u':
                    selected = "skip"
                elif ch[0] == 'w':
                    selected = "weekly"
                elif ch[0] == 'm':
                    selected = "monthly"
                elif ch[0] == 'd':
                    selected = "delete"
                else:
                    print("\nWrong input, please retry")
                    continue

                g_user_config[taskname] = selected
                break

    except KeyboardInterrupt:
        print("\n\nCancelled")
        return False
    except:
        print("\n\nBad input")
        return False

    return True


def handle_dyn_task_deletion(task_name):
    if task_name == "builtin-dyn-autopkgupgrade-default":
        log.debug(f"re-disabling dynamic task {task_name}")

        param_val = syno_get_key_value(SYNOINFO_CONF_PATH, "pkg_autoupdate_important")
        if not param_val or param_val != "no":
            syno_set_key_value(SYNOINFO_CONF_PATH, "pkg_autoupdate_important", "no")

        param_val = syno_get_key_value(SYNOINFO_CONF_PATH, "enable_pkg_autoupdate_all")
        if not param_val or param_val != "no":
            syno_set_key_value(SYNOINFO_CONF_PATH, "enable_pkg_autoupdate_all", "no")

        param_val = syno_get_key_value(SYNOINFO_CONF_PATH, "upgrade_pkg_dsm_notification")
        if not param_val or param_val != "no":
            syno_set_key_value(SYNOINFO_CONF_PATH, "upgrade_pkg_dsm_notification", "no")

    elif task_name in ("builtin-synodbud-synodbud", "builtin-dyn-synodbud-default"):
        log.debug(f"re-disabling dynamic task {task_name}")

        subprocess.run(["systemctl", "mask", "synodbud_autoupdate.service"])
        subprocess.run(["systemctl", "stop", "synodbud_autoupdate.service"])
        subprocess.run(["synodbud", "-p"])
    else:
        return


def get_task_action_from_config(task_name):
    if task_name in g_user_config:
        return g_user_config[task_name]

    log.warning(f"A new task {task_name} has been found, likely installed by "
                 "a new package or a DSM update. Re-run the script install to "
                 "tell what to do with this task. Skipping it for now")
    return "skip"

def apply_user_config_to_task_files():
    files_tasks = {}

    task_files_paths = enumerate_synocrond_task_files()
    if task_files_paths:
        files_tasks = load_synocrond_task_files(task_files_paths)

    for filepath, tasks in files_tasks.items():
        is_file_changed = False

        for synotask in tasks:
            task_name = synotask.task_name
            chosen_opt = get_task_action_from_config(task_name)
            cur_period = get_task_period(synotask.body)

            if chosen_opt == "skip":
                continue
            elif chosen_opt == "delete":
                is_file_changed = True
                synotask.body["period"] = None
            else:
                assert(chosen_opt in ("hourly", "daily", "weekly", "monthly"))

                if chosen_opt != cur_period:
                    is_file_changed = True
                    synotask.body["period"] = chosen_opt

        if is_file_changed:
            log.debug(f"applying user config to task files: going to change {filepath}")
            new_tasks = [synotask for synotask in tasks
                                  if synotask.body["period"] is not None]

            shutil.copy(filepath, BACKUP_DIR)

            if not new_tasks:
                log.debug(f"deleting a task file {filepath} which has no tasks")
                os.unlink(filepath)
                continue
            elif len(new_tasks) == 1:
                json_body = new_tasks[0].body
            else:
                json_body = [item.body for item in new_tasks]

            try:
                with open(filepath, "w") as f:
                    json.dump(json_body, f, indent=4)
            except:
                err("cannot save synocrond task changes to {filepath}")
                pass

def apply_user_config_to_synocrond_config():
    synocrond_config = load_synocrond_config()
    if not synocrond_config:
        err("(run) cannot load synocrond.config")
        return False

    jobs = synocrond_config["jobs"]

    is_changed = False
    for task_name in jobs.copy().keys():
        # DSM 7.2 task naming change
        clean_task_name = task_name
        if task_name.find("synocrond-job-") == 0:
            clean_task_name = task_name.replace("synocrond-job-", "")

        cur_period = get_task_period(jobs[task_name]["config"])
        chosen_opt = get_task_action_from_config(clean_task_name)

        if chosen_opt == "skip":
            continue
        elif chosen_opt == "delete":
            is_changed = True
            handle_dyn_task_deletion(clean_task_name)
            del synocrond_config["jobs"][task_name]
        else:
            assert(chosen_opt in ("hourly", "daily", "weekly", "monthly"))

            if chosen_opt != cur_period:
                is_changed = True
                synocrond_config["jobs"][task_name]["config"]["period"] = chosen_opt

    if is_changed:
        log.debug(f"going to change /usr/syno/etc/synocrond.config")

        # 'systemctl reload synocrond' can fail
        ret = subprocess.call(["systemctl", "stop", "synocrond"])
        if ret:
            err(f"stopping synocrond failed: {ret}")
            return False

        if not save_synocrond_config(synocrond_config):
            err("saving synocrond.config changes failed")
            subprocess.call(["systemctl", "start", "synocrond"])
            return False

        try:
            shutil.rmtree("/run/synocrond")
            os.unlink("/run/synocrond.st.config")
            os.unlink("/run/synocrond.config")
        except:
            pass

        ret = subprocess.call(["systemctl", "start", "synocrond"])
        if ret:
            err(f"starting synocrond failed: {ret}")
            return False

    return True


def process_volume_conf():
    spaces = []

    try:
        with open(SPACE_TABLE_PATH) as f:
            spaces = json.load(f)
    except:
        err(f"failed to load space table {SPACE_TABLE_PATH}")
        return

    volumes = {}    # fs_uuid -> id

    for space in spaces:
        for volume in space["volumes"]:
            fs_uuid = volume["fs_uuid"]
            vol_id  = volume["id"]
            volumes[fs_uuid] = vol_id

    volumes_atime_opt = {}  # fs_uuid -> atime_opt value

    import configparser
    volume_conf = None
    try:
        volume_conf = configparser.ConfigParser()
        volume_conf.read(VOLUME_CONF_PATH)

        for uuid in volume_conf.sections():
            if "atime_opt" in volume_conf[uuid]:
                volumes_atime_opt[uuid] = volume_conf[uuid]["atime_opt"]
            else:
                volumes_atime_opt[uuid] = ""
    except:
        err(f"failed to parse {VOLUME_CONF_PATH}")
        return


    bad_atime_opt_volumes = [uuid for uuid in volumes_atime_opt.keys()
                                  if volumes_atime_opt[uuid] != "noatime"]

    if not bad_atime_opt_volumes:
        return # ok

    bad_atime_opt_volnames = [volumes[uuid] if uuid in volumes else uuid
                              for uuid in bad_atime_opt_volumes]

    print("\nFound some volumes with 'Record File Access Time' enabled:",
          ", ".join(bad_atime_opt_volnames))
    print("It's better to disable this feature if you want to avoid random "
          "HDD wakeups (note: it's different from files modification time)")

    print("\nYou can change this setting yourself in DSM Storage Manager:")
    print('1. For every volume you have, open its "..." menu and select Settings.')
    print("2. On the volume Settings screen, set Record File Access Time to Never")

    print("\nOr, alternatvely, you can let this tool to update the volume settings for you.")

    answer = False
    try:
        resp = input("Would you like for the script to do it [y/N]? ")
        if resp.lower() in ["y","yes"]:
            answer = True
    except:
        pass

    if answer:
        # possible TBD: other *atime choices?
        for uuid in bad_atime_opt_volumes:
            volume_conf[uuid]["atime_opt"] = "noatime"

        shutil.copy(VOLUME_CONF_PATH, BACKUP_DIR)

        try:
            with open(VOLUME_CONF_PATH, "w") as f:
                volume_conf.write(f)
        except:
            err(f"failed to update {VOLUME_CONF_PATH}")
            return

        print("\nSuccessfully updated volume.conf to disable 'Record File Access Time'")
        print("Don't forget to reboot your NAS to apply the new settings")
    else:
        print("\nSkipping changing any volume settings")


def create_sched_task_content(script_body):
    assert(script_body)
    compressed = lzma.compress(script_body, preset=9, format=lzma.FORMAT_ALONE)
    compressed_base64 = base64.b64encode(compressed).decode()

    cmd_lines = f'echo "{compressed_base64}" | base64 -d | xz -d --stdout > /tmp/hiber_fixer.py'
    cmd_lines += '\n'
    cmd_lines += "python3 /tmp/hiber_fixer.py --run"
    #cmd_lines += '\n'
    #cmd_lines += "rm /tmp/hiber_fixer.py"
    return cmd_lines


# returns it as bytes
def prepare_own_body():
    with open(__file__, "r") as f:
        fcontent = f.read()

    config_part = '\n'
    for key, val in g_user_config.items():
        config_part += f'    "{key}": "{val}",\n'

    new_body = re.sub(r"#BEGIN_CONFIG_SECTION.+?    #END_CONFIG_SECTION",
                      f"#BEGIN_CONFIG_SECTION{config_part}    #END_CONFIG_SECTION",
                      fcontent, count=1, flags=re.DOTALL)
    return bytes(new_body, "utf-8")


def apply_misc_fixes():
    # redis-related HDD wakeup in 1 hour after DSM WebUI usage
    fpath1 = os.path.join(SYNOCACHED_CONF_DIRPATH, "synocached.conf")
    fpath2 = os.path.join(SYNOCACHED_CONF_DIRPATH, "synocached.default.conf")
    shutil.copy(fpath1, BACKUP_DIR)
    shutil.copy(fpath2, BACKUP_DIR)

    try:
        with open(fpath1, "r") as f:
            data = f.read()
        new_data = data.replace("timeout 3600", "timeout 900")
        if data != new_data:
            with open(fpath1, "w") as f:
                f.write(new_data)
            log.debug(f"applied fixes to {fpath1}")

        with open(fpath2, "r") as f:
            data = f.read()
        new_data = data.replace("timeout 3600", "timeout 900")
        if data != new_data:
            with open(fpath2, "w") as f:
                f.write(new_data)
            log.debug(f"applied fixes to {fpath2}")
    except Exception as e:
        err(f"cannot apply fixes to synocached: {e}")
        return


def get_boot_state():
    try:
        ret = subprocess.run(["systemctl", "is-system-running"],
                             capture_output=True,
                             universal_newlines=True)
        return ret.stdout.strip()
    except:
        return "unknown"

BOOT_TIMEOUT = 180  # 3 min

# returns False if timed out waiting
def ensure_boot_complete():
    state = get_boot_state()
    if state in ("running", "degraded"):
        return True

    # systemd is still booting
    pid = os.fork()
    if pid == 0:
        # in the child
        start_time = time.time()

        while True:
            time.sleep(0.5)
            state = get_boot_state()
            cur_time = time.time()

            if state in ("running", "degraded"):
                log.debug("waited for boot to finish for {:.2f} sec".format(cur_time - start_time))
                return True

            if cur_time > start_time + BOOT_TIMEOUT:
                return False
    else:
        # in the parent
        sys.exit(0)


def run():
    log.debug("run() triggered for the scheduled task")
    if not ensure_boot_complete():
        log.error("timed out while waiting for boot to complete!")
        return -1
    remount_root_norelatime()
    do_in_memory_fixes()
    apply_user_config_to_task_files()
    ret = apply_user_config_to_synocrond_config()
    return 0 if ret else -1

def install():
    global _print_to_console
    _print_to_console = True

    if not generate_user_config():
        return -1

    process_volume_conf()
    apply_misc_fixes()

    script_body = prepare_own_body()

    operation_cmds = create_sched_task_content(script_body)

    remove_esynoscheduler_task(TASK_SCHEDULER_TASKNAME)

    ret = add_esynoscheduler_task(TASK_SCHEDULER_TASKNAME, "bootup",
                                  "HDD hibernation fixer task",
                                  operation_cmds)
    if not ret:
        print("Failed to create the Task Scheduler task, aborting")
        return -1

    print("Applying changes...")
    ret = run()
    print("\nInstallation finished successfully. You can delete this file "
          f"({os.path.basename(__file__)}) now, it's no longer needed.")
    return ret

def uninstall():
    ret = remove_esynoscheduler_task(TASK_SCHEDULER_TASKNAME)
    if ret:
        print("Successfully deleted the hibernation fixer scheduled task. "
              "It's recommended to reboot your NAS")
        return 0
    else:
        print("ERROR: failed to delete the hibernation fixer scheduled task")
        return -1


def usage():
    print(f"USAGE: {sys.argv[0]} [--install | --uninstall | --run]\n")
    print(f"   --install\tInstall hibernation fixer as a (on-boot) scheduled task")
    print(f"   --uninstall\tRemove the hibernation fixer scheduled task")
    print(f"   --run\tApply all fixes (normally used by the task)")


def main():
    if len(sys.argv) != 2:
        usage()
        return -1

    if platform.machine() != "x86_64":
        print("Only x86-based NAS models are supported")
        return -1

    majorver = syno_get_key_value("/etc.defaults/VERSION", "majorversion")
    if not majorver or majorver != '7':
        print("Please run this script on DSM 7")
        return -1

    if os.geteuid() != 0:
        print("Please run this script with root privileges (using 'sudo')")
        return -1

    log.basicConfig(filename=LOGFILE, level=LOGLEVEL,
                    format="%(asctime)s %(levelname)s\t%(message)s")

    opt = sys.argv[1]
    if opt == "--install":
        return install()
    elif opt == "--uninstall":
        return uninstall()
    elif opt == "--run":
        return run()
    else:
        usage()

    return -1


exit(main())
