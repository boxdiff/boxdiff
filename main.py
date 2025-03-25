import json
import os.path
import subprocess
from html import escape
from typing import List, Dict, Tuple, Optional, Any


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
        self.display_key = ""
        self.unique_key = ""

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
                    changed.changed_fields.append((key, value, previous_value))

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
        <h1>{escape(self.name)}</h1>
"""

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

                html += f"<li>{escape(key)}: {before_value} <span class='arrow'>→</span> {after_value}</li>\n"
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
            entry.display_name = item[self.display_key]
            entry.fields = fields
            entries.append(entry)

        entries = sorted(entries, key=lambda x: x.display_name)
        self.entries = entries


class Services(PowershellGenerator):

    def __init__(self):
        super().__init__()
        # self.command += '"Get-CimInstance \'CIM_Service\' | ConvertTo-Json"'
        # self.command += '"Get-Service | ConvertTo-Json"'
        self.command += '"Get-CimInstance win32_service | ConvertTo-Json"'
        self.keep_keys = ['Caption', 'Description', 'InstallDate', 'Name', 'Status', 'StartMode', 'DesktopInteract',
                          'DisplayName', 'ErrorControl', 'PathName', 'ServiceType', 'StartName', 'DelayedAutoStart']


class InstalledPrograms(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.command += '"Get-WmiObject -Class Win32_Product | ConvertTo-Json"'
        self.keep_keys = ['Caption', 'Description', 'IdentifyingNumber', '20250322', 'InstallDate2', 'InstallLocation',
                          'InstallSource', 'InstallState', 'Name', 'LocalPackage', 'PackageCode', 'PackageName',
                          'Vendor', 'Version']


class Keyboards(PowershellGenerator):

    def __init__(self):
        super().__init__()
        self.display_key = 'Description'
        self.unique_key = 'DeviceID'
        self.command += '"Get-CimInstance win32_keyboard | ConvertTo-Json"'
        self.keep_keys = ['Description', 'DeviceID', 'Availability', 'Caption', ]


if __name__ == '__main__':
    programs = InstalledPrograms()
    # programs.run()

    services = Services()
    services.run()

    # keyboards = Keyboards()
    # keyboards.get()
