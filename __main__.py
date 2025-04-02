import ctypes
import datetime
import getpass
import json
import os
import re
import subprocess
import sys
from abc import ABCMeta
from html import escape
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any

try:
    IS_ADMIN = ctypes.windll.shell32.IsUserAnAdmin() == 1
except Exception:
    IS_ADMIN = False

try:
    USER_NAME = sys.argv[1]
except IndexError:
    USER_NAME = getpass.getuser()

RESULTS_DIR_NAME = f"results_{USER_NAME}"
USER_PATTERN = r"_[a-z0-9]{4,6}$"
DATE = datetime.datetime.now().strftime("%Y-%m-%d")
USER_PATH = Path(f"C:\\Users\\{USER_NAME}")
INDEX_NAME = "0index.html"


def get_html_head(title, h1):
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{escape(title)}</title>

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
    
    .entries {{
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
<h1>{escape(h1)} - {DATE}</h1>
"""
    return html


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


class Generator(metaclass=ABCMeta):

    def __init__(self):
        self.name = self.__class__.__name__
        self.requires_admin = False
        self.skip_duplicates = False

        self.ignore_keys = []
        self.keep_keys = []

        self.entries: List[Entry] = []
        self.previous_entries: List[Entry] = []

        self.added_entries: List[Entry] = []
        self.removed_entries: List[Entry] = []
        self.changed_data: List = []

    def __repr__(self):
        return f"<Generator - {self.name}>"

    def get(self):
        raise NotImplementedError()

    def process_fields(self, fields: Dict):
        pass

    def get_file_name(self):
        return f"{self.name}.json"

    def get_html_name(self):
        return f"{self.name}.html"

    def load_previous(self):
        path = os.path.join(RESULTS_DIR_NAME, self.get_file_name())
        if not os.path.exists(path):
            return

        with open(path, "r", encoding="utf-8") as f:
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

    @staticmethod
    def entry_block(title, entries) -> str:
        html = "\n<div class='entry-block'>"
        html += f"\n\t<h2>{title} ({len(entries)})</h2>\n"
        html += "\t<div class='entries'>\n"
        for e in entries:
            html += "\t\t<div class='entry'>\n"
            html += f"\t\t\t<h3>{escape(e.display_name)} ({escape(e.unique_name)})</h3>\n"
            html += "\t\t\t<ul>\n"
            for key, value in e.fields.items():
                try:
                    value = escape(value)
                except Exception:
                    pass

                html += f"\t\t\t\t<li>{escape(key)}: {value}</li>\n"
            html += "\t\t\t</ul>\n"
            html += "\t\t</div>\n"
        html += "\t</div>\n"
        html += "</div>\n"

        return html

    def write_results(self):
        html = get_html_head(self.name, self.name)
        # TODO refactor. Add classes.
        # Added
        html += self.entry_block("Added", self.added_entries)

        # Removed
        html += self.entry_block("Removed", self.removed_entries)

        # Changed
        html += "\n<div class='entry-block'>"
        html += f"\n\t<h2>Changed ({len(self.changed_data)})</h2>\n"
        html += "\t<div class='entries'>\n"
        for e in self.changed_data:
            html += "\t\t<div class='entry'>\n"
            html += f"\t\t\t<h3>{escape(e.display_name)} ({escape(e.unique_name)})</h3>\n"
            html += "\t\t\t<ul>\n"
            for key, before_value, after_value in e.changed_fields:
                try:
                    before_value = escape(before_value)
                except Exception:
                    pass

                try:
                    after_value = escape(after_value)
                except Exception:
                    pass

                html += f"\t\t\t\t<li>{escape(key)}: {before_value} <span class='arrow'>-></span> {after_value}</li>\n"
            html += "\t\t\t</ul>\n"
            html += "\t\t</div>\n"
        html += "\t</div>\n"
        html += "</div>\n"

        # Current
        html += self.entry_block("Current", self.entries)

        # End
        html += "\n</body>\n</html>"

        path = os.path.join(RESULTS_DIR_NAME, self.get_html_name())
        with open(path, "w", encoding="utf-8") as f:
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

        path = os.path.join(RESULTS_DIR_NAME, self.get_file_name())
        with open(path, "w", encoding="utf-8") as f:
            f.write(json.dumps(json_out, indent=4, sort_keys=True))

    def has_diff(self) -> bool:
        diff = self.added_entries or self.removed_entries or self.changed_data or None
        return bool(diff)

    def run(self):
        print(f"{self.name}...")
        self.get()
        self.load_previous()
        self.process_changes()


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

        if isinstance(items, dict):
            items = [items]

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
            if self.unique_key is None:
                unique = self.get_unique_name(fields)
            else:
                unique = item[self.unique_key]
            entry.unique_name = unique
            assert entry.unique_name

            if entry.unique_name in unique_names:
                if self.skip_duplicates:
                    continue
                import pdb
                pdb.set_trace()
                assert False, entry.unique_name

            unique_names.add(entry.unique_name)

            entry.display_name = item[self.display_key]
            assert entry.display_name
            entry.fields = fields
            entries.append(entry)

        entries = sorted(entries, key=lambda x: x.display_name)
        self.entries = entries

    def get_unique_name(self, fields: dict):
        raise NotImplementedError()


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


class InstalledProgramsAppx(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.display_key = "Name"
        self.unique_key = "PackageFullName"
        self.command += '"Get-AppxPackage | ConvertTo-Json"'
        self.keep_keys = ['Status', 'SignatureKind', 'IsPartiallyStaged', 'NonRemovable', 'Version', 'InstallLocation',
                          'PackageFullName', 'PackageFamilyName', 'ResourceId', 'PublisherId', 'Name', 'Publisher']


class StartupPrograms(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.unique_key = None
        self.command += '"Get-CimInstance Win32_StartupCommand | ConvertTo-Json"'
        self.keep_keys = ['Caption', 'Description', 'SettingID', 'Command', 'Location', 'Name', 'User', 'UserSID',
                          'PSComputerName']

    def get_unique_name(self, fields: dict):
        return f"{fields['Caption']}-{fields['User']}-{fields['Command']}"


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


class Drives(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.unique_key = 'Name'
        self.display_key = "Name"
        self.command += '"Get-PSDrive | ConvertTo-Json"'
        self.keep_keys = ['Name', 'Root', 'Description']


class Partitions(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.unique_key = 'Guid'
        self.display_key = "Guid"
        self.command += '"Get-Partition | ConvertTo-Json"'
        self.keep_keys = ['Guid', 'Size', 'PartitionNumber', 'Offset', 'IsActive', 'GptType', 'DiskNumber', 'UniqueId',
                          'Type', 'OperationalStatus', 'DiskId', 'UniqueId', 'IsActive', 'IsBoot', 'IsDAX', 'IsHidden',
                          'IsOffline', 'IsReadOnly', 'IsShadowCopy', 'IsSystem']


class SmbShares(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.unique_key = 'Name'
        self.display_key = "Description"
        self.command += '"Get-SmbShare | ConvertTo-Json"'
        self.keep_keys = ['Temporary', 'Special', 'ShadowCopy', 'SecurityDescriptor', 'Name', 'ShareType', 'ShareState',
                          'AvailabilityType', 'FolderEnumerationMode', 'DirectoryHandleLeasing', 'EncryptData',
                          'IdentityRemoting', 'IsolatedTransport', 'Path']


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
        self.keep_keys = ['Caption', 'Description', 'Name', 'Status', 'DeviceID', 'PNPDeviceID',
                          'VideoMemoryType', 'VideoProcessor', 'AdapterCompatibility',
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

    def process_fields(self, fields: Dict):
        if fields['PNPDeviceID'] is None:
            fields['PNPDeviceID'] = fields['Caption']


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
        self.keep_keys = ['Caption', 'Description', 'FriendlyName', 'InstanceId', 'InstallDate', 'Name'
            , 'Availability', 'ConfigManagerUserConfig', 'DeviceID', 'PNPDeviceID', 'StatusInfo',
                          'HardwareID', 'Manufacturer', 'Service', 'PNPClass']

    def process_fields(self, fields: Dict):

        if fields['Caption'] is None:
            fields['Caption'] = fields['DeviceID']

        if fields['Name'] is None:
            fields['Name'] = fields['DeviceID']


class Drivers(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.requires_admin = True
        self.display_key = "Driver"
        self.unique_key = "OriginalFileName"
        self.command += '"Get-WindowsDriver -Online -All | ConvertTo-Json"'
        self.keep_keys = ['Driver', 'OriginalFileName', 'Inbox', 'CatalogFile', 'ClassName', 'ClassGuid',
                          'ClassDescription', 'BootCritical', 'DriverSignature', 'ProviderName', 'Date', 'MajorVersion',
                          'MinorVersion', 'Build', 'Revision', 'Path', 'Online', 'WinPath', 'SysDrivePath', 'LogPath',
                          'Version']


class BitLocker(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.requires_admin = True
        self.display_key = "MountPoint"
        self.unique_key = "MountPoint"
        self.command += '"Get-BitLockerVolume | ConvertTo-Json"'


class FileShares(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.requires_admin = True
        self.display_key = "Name"
        self.unique_key = "UniqueId"
        self.command += '"Get-FileShare | ConvertTo-Json"'
        self.keep_keys = ['HealthStatus', 'OperationalStatus', 'ShareState', 'FileSharingProtocol', 'ObjectId',
                          'UniqueId', 'ContinuouslyAvailable', 'Description', 'EncryptData', 'Name',
                          'VolumeRelativePath']


class Tpm(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.requires_admin = True
        self.display_key = "ManufacturerIdTxt"
        self.unique_key = "ManufacturerIdTxt"
        self.command += '"Get-Tpm | ConvertTo-Json"'


class SecureBootPolicy(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.display_key = "Publisher"
        self.unique_key = "Publisher"
        self.command += '"Get-SecureBootPolicy | ConvertTo-Json"'


class ConfirmSecureBootUEFI(Generator):

    def __init__(self):
        super().__init__()
        self.requires_admin = True

    def get(self):
        command = 'powershell "Confirm-SecureBootUEFI"'
        proc = subprocess.run(command, text=True, capture_output=True, check=False, encoding="utf-8")
        assert proc.returncode == 0, f"{proc.returncode}\n{proc.stdout}\n{proc.stderr}"
        output = proc.stdout.strip() + proc.stderr.strip()
        fields = {
            "output": output,
        }
        self.process_fields(fields)

        entry = Entry()
        entry.display_name = "SecureBootEnabled"
        entry.unique_name = entry.display_name
        entry.fields = fields
        self.entries = [entry]


class ComputerInfo(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.display_key = "OsName"
        self.unique_key = "OsName"
        self.command += '"Get-ComputerInfo | ConvertTo-Json"'
        self.keep_keys = ['DeviceGuardUserModeCodeIntegrityPolicyEnforcementStatus',
                          'DeviceGuardCodeIntegrityPolicyEnforcementStatus', 'DeviceGuardSmartStatus',
                          'HyperVisorPresent', 'LogonServer', 'KeyboardLayout', 'OsStatus', 'OsRegisteredUser',
                          'OsSerialNumber', 'OsPrimary', 'OsPortableOperatingSystem', 'OsLanguage', 'OsManufacturer',
                          'OsMaxNumberOfProcesses', 'OsMaxProcessMemorySize', 'OsEncryptionLevel', 'OsDistributed',
                          'OsCodeSet', 'OsLocaleID', 'OsWindowsDirectory', 'OsSystemDrive', 'OsSystemDirectory',
                          'OsSystemDevice', 'OsBootDevice', 'OsBuildNumber', 'OsOperatingSystemSKU', 'OsType',
                          'CsWorkgroup', 'CsUserName', 'CsPrimaryOwnerName', 'CsPartOfDomain',
                          'CsPowerOnPasswordStatus', 'CsManufacturer', 'CsBootupState', 'CsDomain', 'CsDNSHostName',
                          'CsBootROMSupported', 'CsAutomaticResetCapability', 'CsAutomaticResetBootOption',
                          'CsAutomaticManagedPagefile', 'CsAdminPasswordStatus', 'BiosVersion',
                          'BiosSystemBiosMajorVersion', 'BiosSystemBiosMinorVersion', 'BiosStatus',
                          'BiosSoftwareElementState', 'BiosSMBIOSPresent', 'BiosSMBIOSBIOSVersion',
                          'BiosSMBIOSMajorVersion', 'BiosSMBIOSMinorVersion', 'BiosSeralNumber', 'BiosManufacturer',
                          'BiosFirmwareType', 'BiosEmbeddedControllerMajorVersion',
                          'BiosEmbeddedControllerMinorVersion', 'WindowsVersion', 'OSDisplayVersion',
                          'WindowsProductId', 'WindowsBuildLabEx']


class OsConfig(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.display_key = "FriendlyName"
        self.unique_key = "SourceId"
        self.command += '"Get-OSConfiguration | ConvertTo-Json"'
        self.keep_keys = ['SourceId', 'FriendlyName']

    def process_fields(self, fields: Dict):
        if not fields['FriendlyName']:
            fields['FriendlyName'] = fields['SourceId']


class Tasks(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.display_key = "TaskName"
        self.unique_key = "URI"
        self.command += '"Get-ScheduledTask | Select-Object URI, TaskName, SecurityDescriptor, Author, State, Triggers | ConvertTo-Json"'
        self.keep_keys = ['TaskName', 'URI', 'SecurityDescriptor', 'Author', 'State', 'Triggers']


class FirewallRules(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.display_key = "DisplayName"
        self.unique_key = "ID"
        self.command += '"Get-NetFirewallRule | ConvertTo-Json"'
        self.keep_keys = ['Name', 'ID', 'DisplayName', 'Group', 'Enabled', 'Profile', 'Direction', 'Action', 'Status',
                          'EdgeTraversalPolicy', 'LSM', 'PrimaryStatus', 'EnforcementStatus', 'PolicyStoreSourceType',
                          'InstanceID', 'PolicyDecisionStrategy', 'ConditionListType', 'ExecutionStrategy',
                          'SequencedActions', 'DisplayGroup', 'Owner', 'PolicyStoreSource', 'Profiles', 'RuleGroup',
                          'StatusCode']


class Keyboards(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.display_key = 'Description'
        self.unique_key = 'DeviceID'
        self.command += '"Get-CimInstance Win32_Keyboard | ConvertTo-Json"'
        self.keep_keys = ['Description', 'DeviceID', 'Availability', 'Caption', ]


class Certificates(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.skip_duplicates = True
        self.display_key = 'FriendlyName'
        self.unique_key = 'FriendlyName'
        self.command += '"Get-ChildItem Cert:\\ -Recurse | ConvertTo-Json"'
        self.keep_keys = ['Archived', 'Location','FriendlyName','NotAfter', 'NotBefore', 'HasPrivateKey', 'PrivateKey', 'RawData', 'SerialNumber', 'SubjectName', 'Thumbprint', 'Version', 'Issuer', 'Subject', 'PSPath', 'PSChildName']

    def process_fields(self, fields: Dict):
        fields['FriendlyName'] = fields.get('FriendlyName') or fields.get('Name') or fields.get('Subject') or fields.get('PSPath')
        assert fields['FriendlyName'], fields

        fields.setdefault('Thumbprint', 'No Thumbprint')
        fields['FriendlyName'] += f"-{fields['Thumbprint']}"
        if fields['Thumbprint'] == 'No Thumbprint':
            fields['FriendlyName'] += f'-{fields['Location']}'

        raw_data = fields.get('RawData')
        if raw_data:
            fields['RawData'] = str(raw_data)


class EnvironmentVariables(Generator):

    def __init__(self):
        super().__init__()

    def get(self):
        entries = []
        items = sorted(os.environ.items())
        for key, value in items:
            fields = {
                "name": key,
                "value": value
            }
            self.process_fields(fields)

            if fields['name'].startswith("EFC_"):
                split = re.split(USER_PATTERN, fields['name'])
                if split[0]:
                    fields['name'] = split[0]

            entry = Entry()
            entry.display_name = fields['name']
            entry.unique_name = fields['name']
            entry.fields = fields
            entries.append(entry)

        entries = sorted(entries, key=lambda x: x.display_name)
        self.entries = entries


class DirListing(Generator):

    def __init__(self):
        super().__init__()
        self.path = ""

    def get(self):
        entries = []
        if not os.path.exists(self.path):
            self.entries = []
            return

        for name in os.listdir(self.path):
            fields = {
                "name": name,
                "value": None
            }
            self.process_fields(fields)

            entry = Entry()
            entry.display_name = fields['name']
            entry.unique_name = fields['name']
            entry.fields = fields
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


ALL_GENERATORS_CLS = [
    Devices,
    System32,
    Windows,
    ProgramFiles,
    ProgramFilesx86,
    AppDataLocal,
    AppDataLocalLow,
    AppDataRoaming,
    ProgramData,
    DriverFiles,
    EnvironmentVariables,
    Groups,
    Users,
    SoundDevices,
    VideoControllers,
    Displays,
    Keyboards,
    PointingDevices,
    NetworkAdapters,
    Printers,
    Services,
    StartupPrograms,
    Disks,
    PhysicalDisks,
    Drives,
    Partitions,
    SmbShares,
    Tasks,
    FirewallRules,
    ComputerInfo,
    OsConfig,
    InstalledPrograms,
    InstalledProgramsAppx,
    FileShares,
    Drivers,
    Tpm,
    BitLocker,
    SecureBootPolicy,
    ConfirmSecureBootUEFI,
    Certificates,
]

def execute_generators():
    executed = []

    all_generators: List[Generator] = [generator() for generator in ALL_GENERATORS_CLS]
    for generator in all_generators:
        if generator.requires_admin and not IS_ADMIN:
            continue

        generator.run()
        executed.append(generator)

    return executed


def run():
    os.makedirs(RESULTS_DIR_NAME, exist_ok=True)
    executed = execute_generators()

    index_html = get_html_head("Changes", "Changes")

    print("\n### CHANGED")
    any_changed = False
    for generator in executed:
        if generator.has_diff():
            any_changed = True
            print(generator.name)
            index_html += f"<a href='./{generator.get_html_name()}'><h2>{generator.name}</h2></a>"
    index_html += "</body></html>"
    p = os.path.join(RESULTS_DIR_NAME, INDEX_NAME)
    if any_changed:
        with open(p, 'w', encoding='utf-8') as f:
            f.write(index_html)
    else:
        if os.path.exists(p):
            os.remove(p)

    for gen in executed:
        gen.write_results()

    print("")
    print(f"user: {USER_NAME}")
    print(f"is_admin: {IS_ADMIN}")

try:
    import plugin
except ModuleNotFoundError:
    pass
else:
    plugin.hook(locals())

if __name__ == '__main__':
    run()
