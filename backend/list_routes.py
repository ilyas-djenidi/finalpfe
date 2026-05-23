import re
with open('app.py', encoding='utf-8') as f:
    for i, line in enumerate(f, 1):
        if '@app.route' in line:
            print(f"L{i}: {line.strip()}")
