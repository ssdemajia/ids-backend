vendors = ['johnson', 'siemens', 'tridium']

scripts = [{

}]

def get_vendor(vendor_key):
    for name in vendors:
        if name in vendor_key.lower():
            return name
    return ''
