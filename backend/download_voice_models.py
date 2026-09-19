"""Downloads the Kokoro voice model (free, Apache-2.0) into backend/models/.

    python download_voice_models.py          # full model, about 310 MB, best quality
    python download_voice_models.py --small  # int8 model, about 90 MB, faster on weak laptops
"""
import sys
import urllib.request
from pathlib import Path

BASE = "https://github.com/thewh1teagle/kokoro-onnx/releases/download/model-files-v1.0/"
model = "kokoro-v1.0.int8.onnx" if "--small" in sys.argv else "kokoro-v1.0.onnx"
out = Path(__file__).resolve().parent / "models"
out.mkdir(exist_ok=True)


def progress(blocks, size, total):
    if total > 0:
        print(f"\r  {min(100, blocks * size * 100 // total)}%", end="", flush=True)


for name in (model, "voices-v1.0.bin"):
    dest = out / name
    if dest.exists():
        print(f"{name}: already downloaded")
        continue
    print(f"Downloading {name} ...")
    try:
        urllib.request.urlretrieve(BASE + name, dest, progress)
        print()
    except Exception as e:
        dest.unlink(missing_ok=True)
        sys.exit(f"\nDownload failed: {e}\nTry another network (a phone hotspot), or download the file by hand from\n{BASE}{name}\nand put it in {out}")
print("Done. Restart the server and pick 'Kokoro' under Settings, Voice engine.")
