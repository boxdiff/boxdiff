import random
import string


def modify_fields(self, fields):
    print(f"\tModify fields called: {fields}")
    fields['Name'] = f"{fields['Name']}-HOOK"

def hook(main_locals):
    print("Enter hook")

    # Useful fields and classes
    all_generators_cls = main_locals['ALL_GENERATORS_CLS']
    generator_cls = main_locals['Generator']
    powershell_generator_cls = main_locals['PowershellGenerator']
    dir_listing_cls = main_locals['DirListing']
    entry_cls = main_locals['Entry']

    # Remove by name
    all_generators_cls[:] = [gen for gen in all_generators_cls if gen.__name__ != "Disks"]

    # Custom modifying fields on a generator
    drives = [gen for gen in all_generators_cls if gen.__name__ == 'Drives'][0]
    drives.process_fields = modify_fields

    # AppxValue https://learn.microsoft.com/en-us/powershell/module/appx/get-appxvolume?view=windowsserver2025-ps
    class AppxVolume(powershell_generator_cls):
        def __init__(self):
            super().__init__()
            self.display_key = "Name"
            self.unique_key = "PackageStorePath"
            self.command += '"Get-AppxVolume | ConvertTo-Json"'
            self.keep_keys = ['Name', 'PackageStorePath', 'IsOffline', 'IsSystemVolume']
    all_generators_cls.append(AppxVolume)

    # Directory Listing
    class CListing(dir_listing_cls):

        def __init__(self):
            super().__init__()
            self.path = "C:\\"
    all_generators_cls.append(CListing)

    # A Simple Generator example
    class SimpleGen(generator_cls):

        def __init__(self):
            super().__init__()

        def get(self):
            entry = entry_cls()
            entry.display_name = "bar1"
            entry.unique_name = "world1"
            entry.fields = {
                "foo": "bar1",
                "hello": "world1",
                "string": "static"
            }
            self.entries.append(entry)

            entry = entry_cls()
            entry.display_name = "bar2"
            entry.unique_name = "world2"
            entry.fields = {
                "foo": "bar2",
                "hello": "world2",
                "string": ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
            }
            self.entries.append(entry)
    all_generators_cls.append(SimpleGen)

    print("Exit hook")