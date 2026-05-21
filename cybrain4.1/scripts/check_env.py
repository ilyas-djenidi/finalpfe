#!/usr/bin/env python3
"""Quick environment check for CyBrain."""
import sys
import subprocess

def check_nmap():
    """Check if nmap is installed."""
    try:
        result = subprocess.run(['nmap', '--version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return "✅ INSTALLED", result.stdout.split('\n')[0]
        return "❌ NOT WORKING", result.stderr
    except FileNotFoundError:
        return "❌ NOT FOUND", "nmap command not in PATH"
    except Exception as e:
        return "❌ ERROR", str(e)

def check_python_nmap():
    """Check if python-nmap is installed."""
    try:
        import nmap
        return "✅ INSTALLED", f"Version: {nmap.__version__ if hasattr(nmap, '__version__') else 'unknown'}"
    except ImportError:
        return "❌ NOT INSTALLED", "Run: pip install python-nmap"

def check_flask():
    """Check if Flask is installed."""
    try:
        import flask
        return "✅ INSTALLED", f"Version: {flask.__version__}"
    except ImportError:
        return "❌ NOT INSTALLED", "Run: pip install flask"

def check_database():
    """Check if database exists."""
    import os
    if os.path.exists('cybrain.db'):
        size = os.path.getsize('cybrain.db')
        return "✅ EXISTS", f"Size: {size/1024:.2f} KB"
    return "⚠️ MISSING", "Database will be created on first run"

def main():
    print("\n🔍 CyBrain Environment Check\n" + "="*50)
    
    checks = [
        ("System nmap", check_nmap),
        ("Python-nmap module", check_python_nmap),
        ("Flask framework", check_flask),
        ("Database", check_database),
    ]
    
    results = []
    for name, check_fn in checks:
        status, detail = check_fn()
        results.append((name, status, detail))
        print(f"{name:25} {status:20} {detail}")
    
    print("\n" + "="*50)
    
    # Summary
    all_ok = all("✅" in s for _, s, _ in results)
    if all_ok:
        print("\n✅ All checks passed! Ready to use.\n")
        print("Start the app:")
        print("  python app.py")
        print("\nOr run a scan:")
        print("  python scripts/run_netscan.py 127.0.0.1 --out result.json")
        return 0
    else:
        print("\n⚠️ Some checks failed. See details above.\n")
        print("To install missing packages:")
        print("  pip install -r requirements.txt")
        print("  # Then install nmap from https://nmap.org/download.html")
        return 1

if __name__ == '__main__':
    sys.exit(main())
