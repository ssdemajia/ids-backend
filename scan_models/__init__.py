vendors = ['johnson', 'siemens']


def get_vendor(vendor_key):
    for name in vendors:
        if name in vendor_key:
            return name
    return ''
