#!/usr/bin/env python3
"""
Portable standalone APK builder for Cryostasis using standard JDK + Android SDK tools.
Dependencies: Python 3 stdlib, JDK (javac + keytool), Android SDK (build-tools + platform).
"""

import hashlib
import os
import shutil
import subprocess
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
XPOSED_API_URL = "https://api.xposed.info/de/robv/android/xposed/api/82/api-82.jar"
XPOSED_API_SHA256 = "f48c635f1c7469fdec0e00ad2ea0b7a6b2f5b55065784a35b7ca3a84615e8e25"


def find_sdk_root() -> Path:
    candidates = [
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        str(Path.home() / "Library/Android/sdk"),
        "/opt/homebrew/share/android-commandlinetools",
        str(Path.home() / "Android/Sdk"),
    ]
    for raw in candidates:
        if raw and (Path(raw) / "build-tools").is_dir():
            return Path(raw)
    raise RuntimeError("Android SDK not found. Set ANDROID_HOME or ANDROID_SDK_ROOT.")


def pick_latest_subdir(parent: Path, key_fn=None) -> Path:
    dirs = [p for p in parent.iterdir() if p.is_dir()]
    if not dirs:
        raise RuntimeError(f"No subdirectories found under {parent}")
    return sorted(dirs, key=key_fn or (lambda p: [int(x) if x.isdigit() else x for x in p.name.replace("-", ".").split(".")]))[-1]


def find_jdk_tool(name: str) -> str:
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        cand = Path(java_home) / "bin" / name
        if cand.is_file():
            return str(cand)
    found = shutil.which(name)
    if found:
        return found
    raise RuntimeError(f"JDK tool '{name}' not found. Set JAVA_HOME or add JDK bin to PATH.")


def ensure_xposed_api_jar() -> Path:
    jar_path = ROOT / "tools/libs/api-82.jar"
    jar_path.parent.mkdir(parents=True, exist_ok=True)
    if not jar_path.is_file():
        print(f"[*] Downloading Xposed API 82 jar from {XPOSED_API_URL}...")
        urllib.request.urlretrieve(XPOSED_API_URL, jar_path)
    digest = hashlib.sha256(jar_path.read_bytes()).hexdigest()
    if digest != XPOSED_API_SHA256:
        jar_path.unlink(missing_ok=True)
        raise RuntimeError(f"Checksum mismatch for api-82.jar: got {digest}")
    return jar_path


def ensure_keystore(build_dir: Path, keytool: str) -> tuple[Path, str, str]:
    custom_ks = os.environ.get("KEYSTORE_PATH")
    if custom_ks:
        return (
            Path(custom_ks),
            os.environ.get("KEYSTORE_PASS", "android"),
            os.environ.get("KEY_ALIAS", "cryostasis"),
        )
    ks_path = build_dir / "dev.jks"
    ks_pass = "cryostasis"
    alias = "cryostasis"
    if not ks_path.is_file():
        subprocess.run([
            keytool, "-genkeypair", "-v",
            "-keystore", str(ks_path),
            "-storepass", ks_pass,
            "-keypass", ks_pass,
            "-alias", alias,
            "-keyalg", "RSA",
            "-keysize", "2048",
            "-validity", "10000",
            "-dname", "CN=Cryostasis, O=AotianNeo, C=US",
        ], check=True)
    return ks_path, ks_pass, alias


def main() -> None:
    sdk_root = find_sdk_root()
    build_tools = pick_latest_subdir(sdk_root / "build-tools")
    platform_dir = pick_latest_subdir(
        sdk_root / "platforms",
        key_fn=lambda p: int(p.name.split("-")[-1]) if p.name.split("-")[-1].isdigit() else 0,
    )

    android_jar = platform_dir / "android.jar"
    d8 = build_tools / "d8"
    aapt2 = build_tools / "aapt2"
    zipalign = build_tools / "zipalign"
    apksigner = build_tools / "apksigner"
    javac = find_jdk_tool("javac")
    keytool = find_jdk_tool("keytool")
    xposed_jar = ensure_xposed_api_jar()

    build_dir = ROOT / "build"
    javac_out = build_dir / "javac_out"
    d8_out = build_dir / "d8_out"
    shutil.rmtree(javac_out, ignore_errors=True)
    shutil.rmtree(d8_out, ignore_errors=True)
    javac_out.mkdir(parents=True, exist_ok=True)
    d8_out.mkdir(parents=True, exist_ok=True)

    java_sources = sorted((ROOT / "app/src/main/java").rglob("*.java"))
    assert java_sources, "No Java source files found under app/src/main/java"

    # 1. Compile Java -> classfiles -> classes.dex
    subprocess.run([
        javac,
        "--release", "11",
        "-encoding", "UTF-8",
        "-cp", f"{android_jar}:{xposed_jar}",
        "-d", str(javac_out),
        *[str(p) for p in java_sources],
    ], check=True)

    class_files = sorted(javac_out.rglob("*.class"))
    subprocess.run([
        str(d8),
        "--min-api", "26",
        "--lib", str(android_jar),
        "--output", str(d8_out),
        *[str(p) for p in class_files],
    ], check=True)

    dex_bytes = (d8_out / "classes.dex").read_bytes()
    (build_dir / "classes.dex").write_bytes(dex_bytes)
    print(f"[+] Built classes.dex ({len(dex_bytes)} bytes) via {build_tools.name}")

    # 2. Compile & link resources + assets with aapt2
    res_zip = build_dir / "res.zip"
    base_apk = build_dir / "base.apk"
    subprocess.run([
        str(aapt2), "compile", "--dir", str(ROOT / "app/src/main/res"), "-o", str(res_zip),
    ], check=True)
    subprocess.run([
        str(aapt2), "link",
        "-I", str(android_jar),
        "--manifest", str(ROOT / "app/src/main/AndroidManifest.xml"),
        "-A", str(ROOT / "app/src/main/assets"),
        "-o", str(base_apk),
        str(res_zip),
    ], check=True)

    # 3. Inject classes.dex, zipalign, and sign with apksigner
    with zipfile.ZipFile(base_apk, "a") as zf:
        zi = zipfile.ZipInfo("classes.dex")
        zi.compress_type = zipfile.ZIP_STORED
        zf.writestr(zi, dex_bytes)

    aligned_apk = build_dir / "Cryostasis-aligned.apk"
    signed_apk = build_dir / "Cryostasis.apk"
    subprocess.run([str(zipalign), "-f", "4", str(base_apk), str(aligned_apk)], check=True)

    ks_path, ks_pass, alias = ensure_keystore(build_dir, keytool)
    subprocess.run([
        str(apksigner), "sign",
        "--ks", str(ks_path),
        "--ks-pass", f"pass:{ks_pass}",
        "--key-pass", f"pass:{ks_pass}",
        "--ks-key-alias", alias,
        "--out", str(signed_apk),
        str(aligned_apk),
    ], check=True)
    subprocess.run([str(apksigner), "verify", "--verbose", str(signed_apk)], check=True)
    print(f"[+] Built & verified APK: {signed_apk} ({signed_apk.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
