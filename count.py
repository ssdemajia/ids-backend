import os

"""
统计代码量
"""

def calc_lines(dirpath, filename):
    f = open(os.path.join(dirpath, filename), 'r')
    content = f.readlines()
    return len(content)


result = 0
ignore_dirs = ['venv', '.git', '.idea', 'nse']
print(__file__)
current_dir = os.path.abspath(os.path.curdir)
for dirpath, dirnames, filenames in os.walk(current_dir):
    if any([ignore_dir in dirpath for ignore_dir in ignore_dirs]):
        continue
    for filename in filenames:
        if '.' == filename[0]:
            continue
        if '.py' != filename[-3:]:
            continue
        count = calc_lines(dirpath, filename)
        print(filename, count)
        result += count
print(result)