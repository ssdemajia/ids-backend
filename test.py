from scan_models.s7 import s7_resolve, s7_scan


if __name__ == '__main__':
    key = {
        'System Name': 'SIMATIC 300 Station',
        'Copyright': 'Original Siemens Equipment',
        'Version': '3.3.2'
    }
    print(len(s7_scan(key)))
