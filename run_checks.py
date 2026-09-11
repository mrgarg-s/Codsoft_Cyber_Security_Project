from pathlib import Path
import py_compile

root=Path(__file__).parent
for p in root.rglob('*.py'):
    py_compile.compile(str(p), doraise=True)
print('Python syntax check: PASS')
