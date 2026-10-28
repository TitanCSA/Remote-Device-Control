"""Package exact user-mode corresponding source; never scans private state.

Run after Build.ps1. Output includes modified Sunshine and initialized source
submodules, codec sources/build patches, static libiconv source/recipe and the
minimal Vdevice user-mode adapter sources. Kernel sources are never included.
"""
from pathlib import Path
import argparse, hashlib, json, subprocess, zipfile

p=argparse.ArgumentParser()
p.add_argument("--project",type=Path,required=True)
p.add_argument("--output",type=Path,required=True)
p.add_argument("--work",type=Path)
a=p.parse_args()
root=a.project.resolve(); work=(a.work or root/"obj").resolve()
source=work/"Upstream/Sunshine"
codec=work/"Upstream/SunshineCodecSources"
iconv=work/"Upstream/LibiconvSource"
required=[source,codec,iconv/"libiconv-1.18.tar.gz",work/"Upstream/MoonlightCommon",work/"Upstream/MbedTLS"]
for path in required:
    if not path.exists(): raise SystemExit(f"Missing corresponding source: {path}")
def head(path):
    return subprocess.check_output(["git","rev-parse","HEAD"],cwd=path,text=True).strip()
if head(source)!="86188d47a7463b0f73b35de18a628353adeaa20e": raise SystemExit("Sunshine source pin mismatch")
if head(codec)!="2851db101eeddae8f02489d48a52a4d83e6f7e7b": raise SystemExit("Codec source pin mismatch")
if hashlib.sha256((iconv/"libiconv-1.18.tar.gz").read_bytes()).hexdigest()!="3b08f5f4f9b4eb82f151a7040bfd6fe6c6fb922efe4b1659c66ea933276965e8": raise SystemExit("libiconv source hash mismatch")
entries={}
def add(path,name):
    name=name.replace("\\","/")
    # Prepared codec binaries for unrelated OS/architectures are not source.
    # Their exact source/build recipe and dist revision are included separately.
    if name.startswith("CorrespondingSource/Sunshine/third-party/build-deps/dist/"):return
    if name.startswith("CorrespondingSource/Sunshine/gh-pages-template/"):return
    # Only AMF headers are consumed. The AMF repository also vendors unrelated
    # FFmpeg binary/PDB trees and samples; they are not linked into this product.
    if name.startswith("CorrespondingSource/CodecBuild/third-party/FFmpeg/AMF/Thirdparty/"):return
    if path.is_file() and not path.is_symlink(): entries[name]=path
def tree(path,prefix):
    for item in sorted(path.rglob("*")):
        parts=item.relative_to(path).parts
        if not any(part in (".git","__pycache__") for part in parts) and item.suffix not in (".pyc",".pyo"):
            add(item,str(Path(prefix)/item.relative_to(path)))
def repo(path,prefix):
    names=subprocess.check_output(["git","ls-files","-z"],cwd=path).decode().split("\0")
    for name in names:
        if name: add(path/name,str(Path(prefix)/name))
    # A submodule's .git is only a redirection file, never included in output.
    for marker in path.rglob(".git"):
        if marker.is_file():
            sub=marker.parent
            if sub!=path:
                for name in subprocess.check_output(["git","ls-files","-z"],cwd=sub).decode().split("\0"):
                    if name:add(sub/name,str(Path(prefix)/sub.relative_to(path)/name))
repo(source,"CorrespondingSource/Sunshine")
repo(codec,"CorrespondingSource/CodecBuild")
native_pins={"MoonlightCommon":"5d3c0ecca00c1bb3f587acb8060476edcf8e24aa","MbedTLS":"068ff080b369adfac81509f9b57b2afabaf82dc5"}
for name,pin in native_pins.items():
    directory=work/f"Upstream/{name}"
    if head(directory)!=pin: raise SystemExit(f"Native dependency pin mismatch: {name}")
    repo(directory,f"CorrespondingSource/{name}")
tree(iconv,"CorrespondingSource/Libiconv")
tree(root/"ThirdParty/Sunshine","ThirdParty/Sunshine")
tree(root/"Source","Source")
tree(root/"Vdevice","Vdevice")
tree(root/"licenses","licenses")
tree(root/"docs","docs")
for name in (".gitignore",".gitattributes","CMakeLists.txt","Build.ps1","README.md","LICENSE","Vdevice/NOTICE.md","ThirdParty/NOTICE.md","Tools/Prepare-Moonlight.py","Tools/Pack-Engine.ps1"):
    add(root/name,name)
add(work/"Upstream/moonlight-pins.json","CorrespondingSource/moonlight-pins.json")
for name in ("Core","Input","Discovery","Setup","GameStream","GameStreamCodec","EngineBundle"):
    add(root/f"Tests/{name}Tests.cpp",f"Tests/{name}Tests.cpp")
# Preserve the original, compressed source distributions fetched by CMake.
# This includes all source without re-expanding 78,000 files in the download.
for name,filename,expected in (
    ("boost","boost-1.87.0-cmake.tar.xz","7da75f171837577a52bbf217e17f8ea576c7c246e4594d617bfde7fafd408be5"),
    ("json","json.tar.xz","d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d")):
    archive=work/f"SunshineBuild/_deps/{name}-subbuild/{name}-populate-prefix/src/{filename}"
    if not archive.exists():raise SystemExit(f"Missing original source archive: {archive}")
    if expected and hashlib.sha256(archive.read_bytes()).hexdigest()!=expected:raise SystemExit("Source archive hash mismatch")
    add(archive,f"CorrespondingSource/Archives/{filename}")
a.output.parent.mkdir(parents=True,exist_ok=True)
with zipfile.ZipFile(a.output,"w",compression=zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
    manifest={}
    for name,path in sorted(entries.items()):
        digest=hashlib.sha256()
        with path.open("rb") as incoming,archive.open(name,"w",force_zip64=True) as outgoing:
            while block:=incoming.read(1024*1024):digest.update(block);outgoing.write(block)
        manifest[name]=digest.hexdigest()
    generated={
        "CorrespondingSource/Sunshine/.rdc-source-pin":b"86188d47a7463b0f73b35de18a628353adeaa20e\n",
        "BUILD-PROVENANCE.json":json.dumps({
            "sunshine_commit":head(source),"codec_source_commit":head(codec),
            "native_dependencies":native_pins,
            "engine_sha256":hashlib.sha256((work/"Payload/Engine/sunshine.exe").read_bytes()).hexdigest(),
            "engine_path":"Engine/sunshine.exe",
            "note":"The separately supplied signed Vdevice kernel binary is not part of this user-mode source archive."
        },indent=2).encode()
    }
    for name,data in generated.items():archive.writestr(name,data);manifest[name]=hashlib.sha256(data).hexdigest()
    archive.writestr("SOURCE-MANIFEST.json",json.dumps(manifest,indent=2))
print(f"Packaged {len(entries)} user-mode source files: {a.output} ({a.output.stat().st_size} bytes)")
