"""Run every SDK example in order (each is a standalone script).

    python run_all.py
"""
import glob
import subprocess
import sys

failed = []
for path in sorted(glob.glob("[0-9]*.py")):
    print(f"\n{'=' * 72}\n{path}\n{'=' * 72}")
    if subprocess.run([sys.executable, path]).returncode != 0:
        failed.append(path)

print("\n" + "=" * 72)
print(f"DONE - {len(failed)} failed" + (": " + ", ".join(failed) if failed else ""))
sys.exit(1 if failed else 0)
