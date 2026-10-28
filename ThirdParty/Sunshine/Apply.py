"""Apply the audited RDC integration to exactly Sunshine v2025.924.154138.

The fetched checkout is a private build artifact. Modified source and patch
recipes are distributed with the GPLv3 notices; no kernel source is involved.
"""
from pathlib import Path
import re
import subprocess
import sys

source=Path(sys.argv[1]).resolve()
sdk=Path(sys.argv[2]).resolve()
here=Path(__file__).resolve().parent
pin="86188d47a7463b0f73b35de18a628353adeaa20e"
if subprocess.check_output(["git","rev-parse","HEAD"],cwd=source,text=True).strip()!=pin:
    raise SystemExit("The Sunshine checkout does not match the audited source pin")
def read(path):return (source/path).read_text(encoding="utf-8")
def write(path,value):(source/path).write_text(value,encoding="utf-8",newline="\n")
def change(path,old,new):
    value=read(path)
    if value.count(old)!=1:raise RuntimeError(f"Expected one pinned context in {path}: {old[:70]!r}")
    write(path,value.replace(old,new,1))
if "RDC_VDEVICE_BACKEND" in read("src/platform/windows/input.cpp"):
    raise SystemExit("Sunshine integration was already applied; use a clean pinned checkout")
for patch in ("upstream-certificate-validation.patch","upstream-enet-control-bounds.patch"):
    subprocess.run(["git","apply",str(here/"Patches"/patch)],cwd=source,check=True)

# Bound the complete encrypted envelope before reading any header/cipher byte,
# and bound the authenticated inner header before constructing its payload view.
change("src/stream.cpp","#include <cstring>","#include <cstring>\n#include <span>\n#include \"ControlValidation.h\"")
change("src/stream.cpp",'''      auto header = (control_encrypted_p) (payload.data() - 2);''','''      if (!rdc::control::Encrypted(std::span(reinterpret_cast<const std::uint8_t*>(payload.data()),payload.size()))) return;
      auto header = (control_encrypted_p) (payload.data() - 2);''')
change("src/stream.cpp",'''      auto type = *(std::uint16_t *) plaintext.data();''','''      if (!rdc::control::Plaintext(plaintext)) return;
      std::uint16_t type;
      std::memcpy(&type,plaintext.data(),sizeof(type));''')
change("src/stream.cpp",'''      auto tagged_cipher_length = util::endian::big(*(int32_t *) payload.data());''','''      if (!rdc::control::LegacyInput(std::span(reinterpret_cast<const std::uint8_t*>(payload.data()),payload.size()))) return;
      std::int32_t wire_length;
      std::memcpy(&wire_length,payload.data(),sizeof(wire_length));
      auto tagged_cipher_length = util::endian::big(wire_length);''')
change("src/stream.cpp",'''      int32_t *stats = (int32_t *) payload.data();''','''      if (payload.size() < sizeof(std::int32_t)*4) return;
      int32_t *stats = (int32_t *) payload.data();''')
change("src/stream.cpp",'''      auto frames = (std::int64_t *) payload.data();''','''      if (payload.size() < sizeof(std::int64_t)*2) return;
      auto frames = (std::int64_t *) payload.data();''')

# GHSA-ph75-mgxh-mv57 and GHSA-6jvv-jqr7-m6m3: only the exact paired leaf
# is trusted, never another certificate issued by a paired key/certificate.
change("src/crypto.cpp","for (auto &[_, x509_store] : _certs)","for (auto &[trusted_cert, x509_store] : _certs)")
change("src/crypto.cpp","if (err == 1) {\n        return nullptr;\n      }","if (err == 1 && X509_cmp(trusted_cert.get(), cert) == 0) {\n        return nullptr;\n      }\n      if (err == 1) { err_code = X509_V_ERR_CERT_REJECTED; continue; }")

# Original upstream input-size validation (1583e7c), before batching/typed access.
change("src/input.cpp","#include <cmath>","#include <cmath>\n#include <cstring>\n#include <span>")
validation=(here/"InputValidation.inc").read_text(encoding="utf-8")
change("src/input.cpp","  void passthrough(std::shared_ptr<input_t> &input, std::vector<std::uint8_t> &&input_data) {","\n"+validation+"\n  void passthrough(std::shared_ptr<input_t> &input, std::vector<std::uint8_t> &&input_data) {\n    if (!validate_input_packet(input_data)) return;")
change("src/input.cpp","    std::mutex input_queue_lock;","    std::mutex input_queue_lock;\n    bool rdc_worker_scheduled = false;")
original_queue='''  void passthrough(std::shared_ptr<input_t> &input, std::vector<std::uint8_t> &&input_data) {
    if (!validate_input_packet(input_data)) return;
    {
      std::lock_guard<std::mutex> lg(input->input_queue_lock);
      input->input_queue.push_back(std::move(input_data));
    }
    task_pool.push(passthrough_next_message, input);
  }'''
change("src/input.cpp",original_queue,(here/"InputQueue.inc").read_text(encoding="utf-8").rstrip())
# Sunshine 2025 loses the extended-key modifier before its Windows backend.
# Preserve it in flags (including the pressed-key identity), e.g. keypad Enter.
change("src/input.cpp","    auto keyCode = packet->keyCode & 0x00FF;","    auto keyCode = packet->keyCode & 0x00FF;\n    if (packet->modifiers & 0x10 /* MODIFIER_EXTENDED */) packet->flags |= static_cast<char>(0x80);")
# Do not log captured keyboard/mouse packets in this application.
change("src/input.cpp","    input::print((void *) payload);","    // RDC: input payloads are never written to logs.")
# There is no reason to move the user's pointer just to provoke a new frame.
value=read("src/input.cpp")
value,count=re.subn(r"    // Workaround to ensure new frames will be captured when a client connects\n    task_pool.pushDelayed\(\[\]\(\) \{.*?100ms\);\n", "",value,flags=re.S)
if count!=1:raise RuntimeError("Capture workaround pinned context missing")
write("src/input.cpp",value)

# Expose the live request's socket by an aliasing shared_ptr, keeping its
# connection alive; exact certificate authorization is enforced per route.
path="third-party/Simple-Web-Server/server_http.hpp"
change(path,"      std::string method, path, query_string, http_version;","      std::shared_ptr<socket_type> socket() const noexcept {\n        auto owner=connection.lock();\n        return owner?std::shared_ptr<socket_type>(owner,owner->socket.get()):std::shared_ptr<socket_type>{};\n      }\n\n      std::string method, path, query_string, http_version;")
change("src/nvhttp.cpp","#include <filesystem>","#include <filesystem>\n#include <algorithm>\n#include <mutex>\n#include <set>\n#include \"RdcVdevice.h\"")
change("src/nvhttp.cpp","  crypto::cert_chain_t cert_chain;","  crypto::cert_chain_t cert_chain;\n  std::recursive_mutex client_auth_mutex;")
change("src/nvhttp.cpp","boost::asio::ssl::verify_peer | boost::asio::ssl::verify_fail_if_no_peer_cert | boost::asio::ssl::verify_client_once","boost::asio::ssl::verify_peer | boost::asio::ssl::verify_client_once")
change("src/nvhttp.cpp","              if (verify && !verify(session->connection->socket->native_handle())) {\n                this->write(session, on_verify_failed);\n              } else {\n                this->read(session);\n              }","              // RDC authorizes every route after its bounded HTTP request is parsed.\n              this->read(session);")
for signature in ("  void save_state() {","  void load_state() {","  void add_authorized_client(const std::string &name, std::string &&cert) {","  void erase_all_clients() {","  bool unpair_client(const std::string_view uuid) {"):
    change("src/nvhttp.cpp",signature,signature+"\n    std::lock_guard<std::recursive_mutex> auth_lock(client_auth_mutex);")
change("src/nvhttp.cpp","    https_server.verify = [add_cert](SSL *ssl) {","    https_server.verify = [add_cert](SSL *ssl) {\n      std::lock_guard<std::recursive_mutex> auth_lock(client_auth_mutex);")
change("src/nvhttp.cpp","  void launch(bool &host_audio, resp_https_t response, req_https_t request) {",(here/"RdcPairing.inc").read_text(encoding="utf-8")+"\n\n  void launch(bool &host_audio, resp_https_t response, req_https_t request) {")

# Validate the AES key before constructing a fixed-size cipher; callers never
# reach virtual input creation through malformed launch parameters.
change("src/nvhttp.cpp","    auto rikey = util::from_hex_vec(get_arg(args, \"rikey\"), true);","    const auto supplied_key=get_arg(args, \"rikey\");\n    if(supplied_key.size()!=32 || std::any_of(supplied_key.begin(),supplied_key.end(),[](char c){return !((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F'));})) throw std::invalid_argument(\"The stream AES key must contain exactly 32 hexadecimal characters\");\n    auto rikey = util::from_hex_vec(supplied_key, true);")

# Permission and Vdevice setup precede RTSP launch, with a reservation cleanup
# guard for failed encoder/app setup. A rejected second client owns no guard.
for function,next_function in (("launch","resume"),("resume","cancel")):
    text=read("src/nvhttp.cpp");start=text.index("  void "+function+"(");end=text.index("  void "+next_function+"(",start)
    block=text[start:end]
    block=block.replace("    pt::ptree tree;","    pt::ptree tree;\n    bool rdc_reserved=false;",1)
    block=block.replace("    auto g = util::fail_guard([&]() {","    auto g = util::fail_guard([&]() {\n      if(rdc_reserved)rdc::cancel_launch();",1)
    anchor="    host_audio = util::from_view" if function=="launch" else "    // Newer Moonlight clients"
    pos=block.index(anchor)
    # The same hook also rejects an already pending/active controller.
    hook="    std::string rdc_error;\n    if(!rdc::authorize_launch(rdc_client_identity(request),rdc_error)){tree.put(\"root.<xmlattr>.status_code\",403);tree.put(\"root.<xmlattr>.status_message\",rdc_error);tree.put(\"root.gamesession\",0);return;}\n    rdc_reserved=true;\n\n"
    block=block[:pos]+hook+block[pos:]
    block=block.replace("    rtsp_stream::launch_session_raise(launch_session);","    rtsp_stream::launch_session_raise(launch_session);\n    rdc_reserved=false;")
    text=text[:start]+block+text[end:];write("src/nvhttp.cpp",text)
change("src/nvhttp.cpp","  void cancel(resp_https_t response, req_https_t request) {","  void cancel(resp_https_t response, req_https_t request) {\n    if(rdc::busy()&&!rdc::owns_session(rdc_client_identity(request))){response->close_connection_after_response=true;response->write(SimpleWeb::StatusCode::client_error_forbidden,\"Another controller owns the active session.\",{{\"Content-Length\",\"43\"}});return;}")

# Disable the legacy PIN routes (GHSA-36ff-frg7-492f). They are replaced by
# explicit key authorization, or open-mode authorization on every launch.
text=read("src/nvhttp.cpp")
for expression in (r'    https_server.resource\["\^/pair\$"\]\["GET"\] = \[&add_cert\]\(auto resp, auto req\) \{\n.*?\n    \};\n',r'    http_server.resource\["\^/pair\$"\]\["GET"\] = \[&add_cert\]\(auto resp, auto req\) \{\n.*?\n    \};\n'):
    text,count=re.subn(expression,"",text,flags=re.S)
    if count!=1:raise RuntimeError("Legacy pairing route context missing")
write("src/nvhttp.cpp",text)
guards='''    for(auto& route:https_server.resource)for(auto& method:route.second){auto handler=method.second;method.second=[&https_server,handler](auto response,auto request){auto socket=request->socket();if(!socket||!https_server.verify(socket->native_handle())){https_server.on_verify_failed(response,request);return;}handler(response,request);};}
    for(auto& method:https_server.default_resource){auto handler=method.second;method.second=[&https_server,handler](auto response,auto request){auto socket=request->socket();if(!socket||!https_server.verify(socket->native_handle())){https_server.on_verify_failed(response,request);return;}handler(response,request);};}
    https_server.resource["^/rdc-pair$"]["POST"]=rdc_pair;
    https_server.config.max_request_streambuf_size=16384;
    https_server.config.timeout_request=5;
    https_server.config.timeout_content=90;
'''
change("src/nvhttp.cpp","    https_server.config.reuse_address = true;",guards+"\n    https_server.config.reuse_address = true;")

# The managed product never starts the local configuration web UI, whose
# application/preparation command editor would otherwise execute as SYSTEM.
change("src/main.cpp","  std::thread configThread {confighttp::start};","  std::thread configThread {[](){ /* RDC_HEADLESS: installer UI owns configuration. */ }};")

# The service owns one protected mutable state directory. Upstream otherwise
# writes Engine/config before it has parsed the explicit file_apps override.
change("src/platform/windows/misc.cpp",'''    WCHAR sunshine_path[MAX_PATH];
    GetModuleFileNameW(nullptr, sunshine_path, _countof(sunshine_path));
    return std::filesystem::path {sunshine_path}.remove_filename() / L"config"sv;''','''    wchar_t managed[32768] {};
    const DWORD length = GetEnvironmentVariableW(L"RDC_STATE_DIR", managed, 32768);
    if (!length || length >= 32768 || !std::filesystem::path(managed).is_absolute())
      throw std::runtime_error("RDC_STATE_DIR must name the protected absolute engine state directory.");
    return std::filesystem::path(managed);''')
change("src/config.cpp",'''    if (!fs::exists(stream.file_apps.c_str())) {
      fs::copy_file(SUNSHINE_ASSETS_DIR "/apps.json", stream.file_apps);
    }''','''    // RDC: the supervisor writes the sealed Desktop-only apps configuration.
    // Do not copy an upstream default before parsing its explicit path.''')

# No ViGEm sources or paid external input driver are built into this fork.
path="cmake/compile_definitions/windows.cmake";text=read(path)
text=text.replace('"${CMAKE_SOURCE_DIR}/src/platform/windows/input.cpp"','"${RDC_SOURCE_ROOT}/ThirdParty/Sunshine/RdcVdevice.cpp"\n        "${RDC_SOURCE_ROOT}/Source/VirtualInput.cpp"\n        "${RDC_SOURCE_ROOT}/Source/Common.cpp"\n        "${RDC_SOURCE_ROOT}/Vdevice/Vdevice.cpp"')
text=re.sub(r'^.*\$\{CMAKE_SOURCE_DIR\}/third-party/ViGEmClient/.*\n',"",text,flags=re.M)
text+='\ninclude_directories("${RDC_SOURCE_ROOT}/ThirdParty/Sunshine")\nlist(APPEND PLATFORM_LIBRARIES cfgmgr32 ole32 advapi32)\n'
write(path,text)
write("src/platform/windows/input.cpp","// RDC_VDEVICE_BACKEND: replaced by the managed Vdevice-only backend.\n")
# Upstream 2025 still compiles its tray references when the dependency option
# is OFF. Replace those functions completely; the supervisor has its own UI.
change("cmake/compile_definitions/common.cmake",'"${CMAKE_SOURCE_DIR}/src/system_tray.cpp"','"${RDC_SOURCE_ROOT}/ThirdParty/Sunshine/RdcTray.cpp"')
# No npm/UI build is needed when no configuration HTTP service is shipped.
path="cmake/targets/common.cmake";text=read(path);start=text.index("# Homebrew build fails");end=text.index("# docs",start);text=text[:start]+"# RDC: configuration UI is supplied by the managed installer.\n"+text[end:];write(path,text)
print("Applied RDC Vdevice, exact certificate auth, input/ENet bounds and headless integration to",pin)
