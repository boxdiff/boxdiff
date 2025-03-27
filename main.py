import datetime
import json
import os.path
import re
import subprocess
from html import escape
from typing import List, Dict, Tuple, Optional, Any
from pathlib import Path

USER_PATTERN = r"_[a-z0-9]{5}$"
DATE = datetime.datetime.now().strftime("%Y-%m-%d")
USER_PATH = Path(os.environ["USERPROFILE"])

class Entry:

    def __init__(self):
        self.display_name = ""
        self.unique_name = ""
        self.fields = {}

    def __repr__(self):
        return f"<Entry - {self.display_name} - {self.unique_name}>"


class Changed:

    def __init__(self):
        self.unique_name = ""
        self.display_name = ""
        self.changed_fields: List[Tuple[str, Optional[Any], Optional[Any]]] = []

    def __repr__(self):
        return f"<Entry - {self.display_name} - {self.unique_name}>"


class Generator:

    def __init__(self):
        self.name = self.__class__.__name__

        self.fields = {}
        self.ignore_keys = []
        self.keep_keys = []

        self.entries: List[Entry] = []
        self.previous_entries: List[Entry] = []

        self.added_entries: List[Entry] = []
        self.removed_entries: List[Entry] = []
        self.changed_data: List = []

    def get(self):
        raise NotImplementedError()

    def process_fields(self, fields: Dict):
        pass

    def get_file_name(self):
        return f"{self.name}.json"

    def load_previous(self):
        if not os.path.exists(self.get_file_name()):
            return

        with open(self.get_file_name(), "r", encoding="utf-8") as f:
            json_entries = json.load(f)

        self.previous_entries = []
        for j in json_entries:
            entry = Entry()
            entry.unique_name = j['unique_name']
            entry.display_name = j['display_name']
            entry.fields = j['fields']
            self.previous_entries.append(entry)

    def process_changes(self):
        current_names = set([e.unique_name for e in self.entries])
        previous_names = set([e.unique_name for e in self.previous_entries])

        shared_names = current_names.intersection(previous_names)
        added_names = current_names - previous_names
        removed_names = previous_names - current_names

        self.added_entries = [e for e in self.entries if e.unique_name in added_names]
        self.removed_entries = [e for e in self.previous_entries if e.unique_name in removed_names]

        # Compare current and previous
        shared_current_entries = [e for e in self.entries if e.unique_name in shared_names]
        shared_previous_entries = [e for e in self.previous_entries if e.unique_name in shared_names]

        self.changed_data = []
        for current_entry in shared_current_entries:
            previous_entry = [e for e in shared_previous_entries if e.unique_name == current_entry.unique_name][0]

            changed = Changed()
            changed.unique_name = current_entry.unique_name
            changed.display_name = current_entry.display_name
            for key, value in current_entry.fields.items():
                previous_value = previous_entry.fields.get(key)
                if value != previous_value:
                    changed.changed_fields.append((key, previous_value, value))

            for key, value in previous_entry.fields.items():
                if key not in current_entry.fields:
                    changed.changed_fields.append((key, value, None))

            if changed.changed_fields:
                self.changed_data.append(changed)

    def write_results(self):
        html = f"""<!DOCTYPE html>
        <html>
        <head>
            <title>{escape(self.name)}</title>
        
        <style>
            body {{
                font-family: Sans-Serif;
                background: #191919;
                color: #ccc;
            }}
            h2 {{
                color: #4cc2ff;
                padding-top: 2em;
            }}
            .entry-block {{
                padding-left: 2em;
            }}
            
            li{{
                padding-bottom: 0.5em;
            }}
            
            .arrow{{
                color: #4cc2ff;
                font-weight: bold;
                font-size: 1.2em;
            }}
        </style>
        
        </head>
        <body>
        <h1>{escape(self.name)} - {DATE}</h1>
"""
        # TODO refactor. Add classes.
        # Added
        html += f"<h2>Added ({len(self.added_entries)})</h2>\n"
        html += "<div class='entry-block'>\n"
        for e in self.added_entries:
            html += f"<h3>{escape(e.display_name)} ({escape(e.unique_name)})</h3>\n"
            html += "<ul>\n"
            for key, value in e.fields.items():
                try:
                    value = escape(value)
                except Exception:
                    pass

                html += f"<li>{escape(key)}: {value}</li>\n"
            html += "</ul>\n"
        html += "</div>"

        # Removed
        html += f"<h2>Removed ({len(self.removed_entries)})</h2>\n"
        html += "<div class='entry-block'>\n"
        for e in self.removed_entries:
            html += f"<h3>{escape(e.display_name)} ({escape(e.unique_name)})</h3>\n"
            html += "<ul>\n"
            for key, value in e.fields.items():
                try:
                    value = escape(value)
                except Exception:
                    pass

                html += f"<li>{escape(key)}: {value}</li>\n"
            html += "</ul>\n"
        html += "</div>"

        # Changed
        html += f"<h2>Changed ({len(self.changed_data)})</h2>\n"
        html += "<div class='entry-block'>\n"
        for e in self.changed_data:
            html += f"<h3>{escape(e.display_name)} ({escape(e.unique_name)})</h3>\n"
            html += "<ul>"
            for key, before_value, after_value in e.changed_fields:
                try:
                    before_value = escape(before_value)
                except Exception:
                    pass

                try:
                    after_value = escape(after_value)
                except Exception:
                    pass

                html += f"<li>{escape(key)}: {before_value} <span class='arrow'>-></span> {after_value}</li>\n"
            html += "</ul>\n"
        html += "</div>\n"

        # Current
        html += f"<h2>Current ({len(self.entries)})</h2>\n"
        html += "<div class='entry-block'>\n"
        for e in self.entries:
            html += f"<h3>{escape(e.display_name)} ({escape(e.unique_name)})</h3>\n"
            html += "<ul>\n"
            for key, value in e.fields.items():
                try:
                    value = escape(value)
                except Exception:
                    pass

                html += f"<li>{escape(key)}: {value}</li>\n"
            html += "</ul>\n"
        html += "</div>\n"

        # End
        html += "</body></html>"

        file_name = f"{self.name}.html"
        with open(file_name, "w", encoding="utf-8") as f:
            f.write(html)

        json_out = []
        for e in self.entries:
            fields = {k: v for k, v in e.fields.items()}
            entry = {
                "display_name": e.display_name,
                "unique_name": e.unique_name,
                "fields": fields
            }
            json_out.append(entry)

        with open(self.get_file_name(), "w", encoding="utf-8") as f:
            f.write(json.dumps(json_out, indent=4, sort_keys=True))

    def run(self):
        print(f"{self.name}...")
        self.get()
        self.load_previous()
        self.process_changes()
        self.write_results()


class PowershellGenerator(Generator):

    def __init__(self):
        super().__init__()
        self.command = "powershell "
        self.display_key = 'Caption'
        self.unique_key = 'Name'

    def get(self):
        proc = subprocess.run(self.command, text=True, capture_output=True, check=False, encoding="utf-8")
        assert proc.returncode == 0, f"{proc.returncode}\n{proc.stdout}\n{proc.stderr}"
        items = json.loads(proc.stdout)

        unique_names = set()

        entries = []
        for item in items:
            self.process_fields(item)
            fields = {}
            for key, value in sorted(item.items()):
                if self.ignore_keys:
                    if key not in self.ignore_keys:
                        fields[key] = value
                elif self.keep_keys:
                    if key in self.keep_keys:
                        fields[key] = value
                else:
                    fields[key] = value

            entry = Entry()
            entry.unique_name = item[self.unique_key]

            if entry.unique_name in unique_names:
                assert False, entry.unique_name

            unique_names.add(entry.unique_name)

            entry.display_name = item[self.display_key]
            entry.fields = fields
            entries.append(entry)

        entries = sorted(entries, key=lambda x: x.display_name)
        self.entries = entries


class Services(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.command += '"Get-CimInstance win32_service | ConvertTo-Json"'
        self.keep_keys = ['Caption', 'Description', 'InstallDate', 'Name', 'Status', 'StartMode', 'DesktopInteract',
                          'DisplayName', 'ErrorControl', 'PathName', 'ServiceType', 'StartName', 'DelayedAutoStart']

    def process_fields(self, fields: Dict):
        user_keys = ["Caption", "DisplayName", "Name"]
        for key in user_keys:
            value = fields.get(key)
            if isinstance(value, str):
                split = re.split(USER_PATTERN, value)
                if split[0]:
                    fields[key] = split[0]


class InstalledPrograms(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.command += '"Get-WmiObject -Class Win32_Product | ConvertTo-Json"'
        self.keep_keys = ['Caption', 'Description', 'IdentifyingNumber', '20250322', 'InstallDate2', 'InstallLocation',
                          'InstallSource', 'InstallState', 'Name', 'LocalPackage', 'PackageCode', 'PackageName',
                          'Vendor', 'Version']


class StartupPrograms(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.command += '"Get-CimInstance Win32_StartupCommand | ConvertTo-Json"'
        self.keep_keys = ['Caption', 'Description', 'SettingID', 'Command', 'Location', 'Name', 'User', 'UserSID',
                          'PSComputerName']


class PhysicalDisks(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.unique_key = 'UniqueId'
        self.display_key = "FriendlyName"
        self.command += '"Get-PhysicalDisk | ConvertTo-Json"'
        self.keep_keys = ['Usage', 'OperationalStatus', 'HealthStatus', 'BusType', 'CannotPoolReason', 'MediaType',
                          'SpindleSpeed', 'UniqueId', 'FriendlyName', 'Model', 'PhysicalLocation', 'SerialNumber',
                          'AllocatedSize', 'FirmwareVersion', 'FruId', 'Size', 'DeviceId']


class Disks(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.unique_key = 'UniqueId'
        self.display_key = "FriendlyName"
        self.command += '"Get-Disk | ConvertTo-Json"'
        self.keep_keys = ['OperationalStatus', 'HealthStatus', 'BusType', 'UniqueId', 'FriendlyName', 'Model',
                          'SerialNumber', 'AllocatedSize', 'FirmwareVersion']


class Printers(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.unique_key = 'Name'
        self.display_key = "Name"
        self.command += '"Get-Printer | ConvertTo-Json"'
        self.keep_keys = ['PrinterStatus', 'Type', 'DeviceType', 'Caption', 'Description', 'InstanceID', 'HealthState',
                          'Name', 'Datatype', 'DriverName', 'Location', 'PortName', 'PrintProcessor', 'Priority']


class NetworkAdapters(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.unique_key = 'DeviceID'
        self.display_key = "ifDesc"
        self.command += '"Get-NetAdapter | ConvertTo-Json"'
        self.keep_keys = ['MacAddress', 'Status', 'MediaType', 'PhysicalMediaType', 'MediaConnectionState',
                          'DriverInformation', 'DriverFileName', 'NdisVersion', 'InterfaceAlias', 'ifDesc', 'ifName',
                          'DriverVersion', 'LinkLayerAddress', 'InstanceID', 'DeviceID',
                          'ActiveMaximumTransmissionUnit', 'PermanentAddress', 'ComponentID', 'DeviceName',
                          'DriverDate', 'DriverMajorNdisVersion', 'DriverMinorNdisVersion', 'DriverName',
                          'DriverProvider', 'DriverVersionString', 'InterfaceGuid', 'InterfaceName', 'NetLuid',
                          'PnPDeviceID']


class PointingDevices(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.unique_key = 'DeviceID'
        self.display_key = "Caption"
        self.command += '"Get-CimInstance -ClassName Win32_PointingDevice| ConvertTo-Json"'
        self.keep_keys = ['Caption', 'Description', 'DeviceID', 'PNPDeviceID', 'Manufacturer']


class VideoControllers(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.unique_key = 'Caption'
        self.display_key = "Caption"
        self.command += '"Get-CimInstance -ClassName Win32_VideoController | ConvertTo-Json"'
        self.keep_keys = ['Caption', 'Description', 'Name', 'Status', 'Availability', 'DeviceID', 'PNPDeviceID',
                          'CurrentNumberOfColors', 'VideoMemoryType', 'VideoProcessor', 'AdapterCompatibility',
                          'AdapterDACType', 'DriverDate', 'DriverVersion', 'InfFilename', 'InfSection']


class SoundDevices(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.unique_key = 'DeviceID'
        self.display_key = "Caption"
        self.command += '"Get-CimInstance -ClassName Win32_SoundDevice | ConvertTo-Json"'
        self.keep_keys = ['Caption', 'Description', 'Name', 'Status', 'Availability', 'DeviceID', 'PNPDeviceID',
                          'Manufacturer']


class Displays(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.unique_key = 'PNPDeviceID'
        self.display_key = "Caption"
        self.command += '"Get-CimInstance -ClassName CIM_Display | ConvertTo-Json"'
        self.keep_keys = ['Caption', 'Description', 'Name', 'Status', 'Availability', 'PNPDeviceID']


class Users(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.unique_key = 'Name'
        self.display_key = "Name"
        self.command += '"Get-LocalUser | ConvertTo-Json"'
        self.keep_keys = ['AccountExpires', 'Description', 'Enabled', 'FullName', 'PasswordChangeableDate',
                          'PasswordExpires', 'PasswordExpires', 'UserMayChangePassword', 'PasswordRequired',
                          'PasswordLastSet', 'PrincipalSource']


class Groups(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.unique_key = 'Name'
        self.display_key = "Name"
        self.command += '"Get-LocalGroup | ConvertTo-Json"'
        self.keep_keys = ['Description', 'Name', 'PrincipalSource']


class Devices(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.unique_key = "DeviceID"
        self.command += '"Get-PnpDevice | ConvertTo-Json"'
        self.keep_keys = ['Caption', 'Description', 'FriendlyName', 'InstanceId', 'Problem', 'InstallDate', 'Name',
                          'Status', 'Availability', 'ConfigManagerUserConfig', 'DeviceID', 'PNPDeviceID', 'StatusInfo',
                          'HardwareID', 'Manufacturer', 'Service', 'PNPClass']

    def process_fields(self, fields: Dict):

        if fields['Caption'] is None:
            fields['Caption'] = fields['DeviceID']

        if fields['Name'] is None:
            fields['Name'] = fields['DeviceID']


class Drivers(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.display_key = "ClassDescription"
        self.unique_key = "Driver"
        self.command += '"Get-WindowsDriver -Online -All | ConvertTo-Json"'
        self.keep_keys = ['Driver', 'OriginalFileName', 'Inbox', 'CatalogFile', 'ClassName', 'ClassGuid',
                          'ClassDescription', 'BootCritical', 'DriverSignature', 'ProviderName', 'Date', 'MajorVersion',
                          'MinorVersion', 'Build', 'Revision', 'Path', 'Online', 'WinPath', 'SysDrivePath', 'LogPath',
                          'Version']


class Keyboards(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.display_key = 'Description'
        self.unique_key = 'DeviceID'
        self.command += '"Get-CimInstance Win32_Keyboard | ConvertTo-Json"'
        self.keep_keys = ['Description', 'DeviceID', 'Availability', 'Caption', ]


class EnvironmentVariables(Generator):

    def __init__(self):
        super().__init__()

    def get(self):
        entries = []
        for key, value in sorted(os.environ.items()):
            entry = Entry()
            entry.display_name = key
            entry.unique_name = key
            entry.fields = {
                "name": key,
                "value": value
            }
            entries.append(entry)

        entries = sorted(entries, key=lambda x: x.display_name)
        self.entries = entries

class DirListing(Generator):

    def __init__(self):
        super().__init__()
        self.path = ""

    def get(self):
        entries = []
        for name in os.listdir(self.path):
            entry = Entry()
            entry.display_name = name
            entry.unique_name = name
            entry.fields = {
                "name": name,
                "value": None
            }
            entries.append(entry)

        entries = sorted(entries, key=lambda x: x.display_name)
        self.entries = entries

class AppDataLocal(DirListing):

    def __init__(self):
        super().__init__()
        self.path = USER_PATH / "AppData" / "Local"

class AppDataLocalLow(DirListing):

    def __init__(self):
        super().__init__()
        self.path = USER_PATH / "AppData" / "LocalLow"

class AppDataRoaming(DirListing):

    def __init__(self):
        super().__init__()
        self.path = USER_PATH / "AppData" / "Roaming"

class ProgramData(DirListing):

    def __init__(self):
        super().__init__()
        self.path = "C:\\ProgramData"

class ProgramFiles(DirListing):

    def __init__(self):
        super().__init__()
        self.path = "C:\\Program Files"

class ProgramFilesx86(DirListing):

    def __init__(self):
        super().__init__()
        self.path = "C:\\Program Files (x86)"

class Windows(DirListing):

    def __init__(self):
        super().__init__()
        self.path = "C:\\Windows"

class System32(DirListing):

    def __init__(self):
        super().__init__()
        self.path = "C:\\Windows\\System32"

class DriverFiles(DirListing):

    def __init__(self):
        super().__init__()
        self.path = "C:\\Windows\\System32\\drivers"


if __name__ == '__main__':

    executed = []

    devices = Devices()
    devices.run()
    executed.append(devices)

    system32 = System32()
    system32.run()
    executed.append(system32)

    windows = Windows()
    windows.run()
    executed.append(windows)

    program_files = ProgramFiles()
    program_files.run()
    executed.append(program_files)

    program_files_x86 = ProgramFilesx86()
    program_files_x86.run()
    executed.append(program_files_x86)

    appdata_local = AppDataLocal()
    appdata_local.run()
    executed.append(appdata_local)

    appdata_local_low = AppDataLocalLow()
    appdata_local_low.run()
    executed.append(appdata_local_low)

    appdata_roaming = AppDataRoaming()
    appdata_roaming.run()
    executed.append(appdata_roaming)

    program_data = ProgramData()
    program_data.run()
    executed.append(program_data)

    groups = Groups()
    groups.run()
    executed.append(groups)

    users = Users()
    users.run()
    executed.append(users)

    sound = SoundDevices()
    sound.run()
    executed.append(sound)

    video = VideoControllers()
    video.run()
    executed.append(video)

    displays = Displays()
    displays.run()
    executed.append(displays)

    pointing_devices = PointingDevices()
    pointing_devices.run()
    executed.append(pointing_devices)

    network_adapters = NetworkAdapters()
    network_adapters.run()
    executed.append(network_adapters)

    printers = Printers()
    printers.run()
    executed.append(printers)

    env_vars = EnvironmentVariables()
    env_vars.run()
    executed.append(env_vars)

    services = Services()
    services.run()
    executed.append(services)

    startup = StartupPrograms()
    startup.run()
    executed.append(startup)

    disks = Disks()
    disks.run()
    executed.append(disks)

    physical_disks = PhysicalDisks()
    physical_disks.run()
    executed.append(physical_disks)

    keyboards = Keyboards()
    keyboards.run()
    executed.append(keyboards)

    programs = InstalledPrograms()
    programs.run()
    executed.append(programs)

    driver_files = DriverFiles()
    driver_files.run()
    executed.append(driver_files)

    # drivers = Drivers()
    # drivers.run()
    # executed.append(drivers)

    # Bluetooth

    print("\n### CHANGED")
    for gen in executed:
        has_diff = gen.added_entries or gen.removed_entries or gen.changed_data or None
        if has_diff:
            print(gen.name)