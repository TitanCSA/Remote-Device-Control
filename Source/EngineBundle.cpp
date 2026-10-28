#include "EngineBundle.h"
#include "Config.h"
#include <windows.h>
#include <bcrypt.h>
#include <aclapi.h>
#include <sddl.h>
#include <fdi.h>
#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>

namespace RemoteControl::EngineBundle {
namespace {
constexpr uint64_t FileLimit=128ull*1024*1024,TotalLimit=512ull*1024*1024,CabinetLimit=256ull*1024*1024;
constexpr wchar_t Marker[]=L".rdc-engine-owner.txt",Manifest[]=L".rdc-manifest.txt";
constexpr char Owner[]="RDC-OWNED-ENGINE-1\n";
[[noreturn]] void Fail(const char* operation,DWORD error=GetLastError()){throw std::runtime_error(std::string(operation)+" failed (Windows error "+std::to_string(error)+").");}
void Require(bool value,const char* operation){if(!value)Fail(operation);}
void Crypto(NTSTATUS result){if(result<0)throw std::runtime_error("Engine SHA-256 operation failed.");}
std::string Lower(std::string text){for(char& c:text)if(c>='A'&&c<='Z')c=static_cast<char>(c-'A'+'a');return text;}
std::string Path(std::string_view raw){
 if(raw.empty()||raw.size()>240)throw std::invalid_argument("Engine relative path length is invalid.");
 std::string path(raw);std::replace(path.begin(),path.end(),'\\','/');
 if(path.front()=='/'||path.back()=='/'||path.find("..")!=path.npos)throw std::invalid_argument("Engine path traversal was refused.");
 size_t start=0;unsigned depth=0;
 while(start<path.size()){
  if(++depth>32)throw std::invalid_argument("Engine directory depth exceeds its bound.");auto end=path.find('/',start);if(end==path.npos)end=path.size();const auto component=path.substr(start,end-start);
  if(component.empty()||component=="."||component.back()=='.')throw std::invalid_argument("Engine path component is invalid.");
  for(char c:component)if(!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='_'||c=='-'||c=='.'))throw std::invalid_argument("Engine paths require safe ASCII components.");
  auto stem=Lower(component.substr(0,component.find('.')));
  if(stem=="con"||stem=="prn"||stem=="aux"||stem=="nul"||(stem.size()==4&&(stem.substr(0,3)=="com"||stem.substr(0,3)=="lpt")&&stem[3]>='1'&&stem[3]<='9'))throw std::invalid_argument("Reserved Windows engine path was refused.");
  start=end+1;
 }
 const auto lower=Lower(path);if(lower==".rdc-engine-owner.txt"||lower==".rdc-manifest.txt")throw std::invalid_argument("Engine metadata cannot be replaced by cabinet content.");
 return path;
}
std::wstring WidePath(std::string_view path){std::wstring out(path.begin(),path.end());std::replace(out.begin(),out.end(),L'/',L'\\');return out;}
std::wstring Native(const std::wstring& path){if(path.size()<3||path[1]!=L':'||path[2]!=L'\\'||path.size()>32000)throw std::runtime_error("An absolute local engine path is required.");return L"\\\\?\\"+path;}
bool Exists(const std::wstring& path){const auto attributes=GetFileAttributesW(Native(path).c_str());if(attributes!=INVALID_FILE_ATTRIBUTES)return true;const DWORD error=GetLastError();if(error==ERROR_FILE_NOT_FOUND||error==ERROR_PATH_NOT_FOUND)return false;Fail("Inspect engine path",error);}
struct Handle {
 HANDLE value=INVALID_HANDLE_VALUE;explicit Handle(HANDLE handle=INVALID_HANDLE_VALUE):value(handle){}
 ~Handle(){if(value!=INVALID_HANDLE_VALUE)CloseHandle(value);}
 Handle(const Handle&)=delete;Handle& operator=(const Handle&)=delete;
};
struct Security {
 PSECURITY_DESCRIPTOR value=nullptr;
 explicit Security(bool directory){Require(ConvertStringSecurityDescriptorToSecurityDescriptorW(directory?L"O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)":L"O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",SDDL_REVISION_1,&value,nullptr)!=FALSE,"Build protected engine policy");}
 ~Security(){if(value)LocalFree(value);}
};
void Protected(const std::wstring& path,bool directory){
 CheckPlain(path,directory);
 Handle file(CreateFileW(Native(path).c_str(),READ_CONTROL|FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|(directory?FILE_FLAG_BACKUP_SEMANTICS:0),nullptr));
 Require(file.value!=INVALID_HANDLE_VALUE,"Open engine ownership metadata");
 BY_HANDLE_FILE_INFORMATION info{};Require(GetFileInformationByHandle(file.value,&info)!=FALSE,"Read engine file identity");
 if((info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)||(!directory&&info.nNumberOfLinks!=1))throw std::runtime_error("Redirected or multiply-linked engine files are refused.");
 PSID owner=nullptr;PACL dacl=nullptr;PSECURITY_DESCRIPTOR descriptor=nullptr;
 const auto result=GetSecurityInfo(file.value,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,nullptr,&dacl,nullptr,&descriptor);if(result)Fail("Read engine security",result);
 SECURITY_DESCRIPTOR_CONTROL control=0;DWORD revision=0;GetSecurityDescriptorControl(descriptor,&control,&revision);
 bool valid=owner&&dacl&&dacl->AceCount==2&&(control&SE_DACL_PROTECTED)&&(IsWellKnownSid(owner,WinBuiltinAdministratorsSid)||IsWellKnownSid(owner,WinLocalSystemSid));
 bool system=false,admins=false;
 if(dacl)for(DWORD i=0;i<dacl->AceCount;++i){
  void* item=nullptr;if(!GetAce(dacl,i,&item)){valid=false;break;}auto header=static_cast<ACE_HEADER*>(item);
  if(header->AceType!=ACCESS_ALLOWED_ACE_TYPE){valid=false;break;}auto ace=static_cast<ACCESS_ALLOWED_ACE*>(item);
  if((ace->Mask&FILE_ALL_ACCESS)!=FILE_ALL_ACCESS){valid=false;break;}PSID sid=&ace->SidStart;
  if(IsWellKnownSid(sid,WinLocalSystemSid))system=true;else if(IsWellKnownSid(sid,WinBuiltinAdministratorsSid))admins=true;else valid=false;
 }
 LocalFree(descriptor);if(!valid||!system||!admins)throw std::runtime_error("Engine files require protected SYSTEM/Administrators ownership and access.");
}
void Directory(const std::wstring& path){
 Security policy(true);SECURITY_ATTRIBUTES attributes{sizeof(attributes),policy.value,FALSE};
 if(!CreateDirectoryW(Native(path).c_str(),&attributes)&&GetLastError()!=ERROR_ALREADY_EXISTS)Fail("Create protected engine directory");
 Protected(path,true);
}
std::unique_ptr<Handle> Create(const std::wstring& path){
 Security policy(false);SECURITY_ATTRIBUTES attributes{sizeof(attributes),policy.value,FALSE};
 auto handle=CreateFileW(Native(path).c_str(),GENERIC_WRITE|READ_CONTROL|FILE_READ_ATTRIBUTES,FILE_SHARE_READ,&attributes,CREATE_NEW,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
 if(handle==INVALID_HANDLE_VALUE)Fail("Create owned engine file");return std::make_unique<Handle>(handle);
}
void Write(const std::wstring& path,std::string_view bytes){
 auto file=Create(path);DWORD count=0;
 Require(WriteFile(file->value,bytes.data(),static_cast<DWORD>(bytes.size()),&count,nullptr)&&count==bytes.size()&&FlushFileBuffers(file->value),"Write engine ownership metadata");
}
std::string Read(const std::wstring& path,size_t limit){
 Protected(path,false);Handle file(CreateFileW(Native(path).c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
 Require(file.value!=INVALID_HANDLE_VALUE,"Read owned engine file");LARGE_INTEGER size{};Require(GetFileSizeEx(file.value,&size),"Read engine file size");
 if(size.QuadPart<0||static_cast<uint64_t>(size.QuadPart)>limit)throw std::runtime_error("Engine metadata exceeds its limit.");
 std::string bytes(static_cast<size_t>(size.QuadPart),'\0');DWORD count=0;
 Require(ReadFile(file.value,bytes.data(),static_cast<DWORD>(bytes.size()),&count,nullptr)&&count==bytes.size(),"Read complete engine metadata");return bytes;
}
struct Hash {
 BCRYPT_ALG_HANDLE algorithm=nullptr;BCRYPT_HASH_HANDLE value=nullptr;
 Hash(){Crypto(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,nullptr,0));try{Crypto(BCryptCreateHash(algorithm,&value,nullptr,0,nullptr,0,0));}catch(...){BCryptCloseAlgorithmProvider(algorithm,0);throw;}}
 ~Hash(){if(value)BCryptDestroyHash(value);if(algorithm)BCryptCloseAlgorithmProvider(algorithm,0);}
 void Add(const void* bytes,size_t count){Crypto(BCryptHashData(value,static_cast<PUCHAR>(const_cast<void*>(bytes)),static_cast<ULONG>(count),0));}
 std::string Finish(){std::array<uint8_t,32> digest{};Crypto(BCryptFinishHash(value,digest.data(),static_cast<ULONG>(digest.size()),0));constexpr char hex[]="0123456789abcdef";std::string text;for(auto b:digest){text+=hex[b>>4];text+=hex[b&15];}return text;}
};
std::string HashFile(const std::wstring& path,uint64_t expected){
 Protected(path,false);Handle file(CreateFileW(Native(path).c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_SEQUENTIAL_SCAN,nullptr));
 Require(file.value!=INVALID_HANDLE_VALUE,"Open extracted engine file");LARGE_INTEGER size{};Require(GetFileSizeEx(file.value,&size),"Read extracted engine size");
 if(size.QuadPart<0||static_cast<uint64_t>(size.QuadPart)!=expected)throw std::runtime_error("Extracted engine file has an unexpected size.");
 Hash hash;std::array<uint8_t,65536> bytes{};for(;;){DWORD count=0;Require(ReadFile(file.value,bytes.data(),static_cast<DWORD>(bytes.size()),&count,nullptr),"Hash extracted engine file");if(!count)break;hash.Add(bytes.data(),count);}return hash.Finish();
}
std::set<std::wstring> Directories(const std::wstring& root,const std::vector<Entry>& entries){
 std::set<std::wstring> dirs;
 for(const auto& entry:entries){auto path=std::filesystem::path(root+L"\\"+WidePath(entry.path)).parent_path();while(path.wstring()!=root){dirs.insert(path.wstring());path=path.parent_path();}}
 return dirs;
}
std::vector<Entry> Owned(const std::wstring& root){
 Protected(root,true);if(Read(root+L"\\"+Marker,128)!=Owner)throw std::runtime_error("Engine directory has no recognized ownership marker.");
 return ValidateManifest(Read(root+L"\\"+Manifest,1024*1024));
}
void Verify(const std::wstring& root,const std::vector<Entry>& entries){
 Protected(root,true);for(const auto& entry:entries)if(HashFile(root+L"\\"+WidePath(entry.path),entry.size)!=entry.sha256)throw std::runtime_error("Extracted engine file failed SHA-256 verification.");
}
void Note(std::wstring& retained,const std::wstring& text){if(retained.size()>4096)return;if(!retained.empty())retained+=L"\n";retained+=text;}
bool Delete(const std::wstring& path,bool directory,bool allowDelay){
 if(directory?RemoveDirectoryW(Native(path).c_str()):DeleteFileW(Native(path).c_str()))return false;
 const auto error=GetLastError();if(error==ERROR_FILE_NOT_FOUND||error==ERROR_PATH_NOT_FOUND)return false;
 if(allowDelay&&(error==ERROR_SHARING_VIOLATION||error==ERROR_ACCESS_DENIED||error==ERROR_DIR_NOT_EMPTY)){
  Require(MoveFileExW(Native(path).c_str(),nullptr,MOVEFILE_DELAY_UNTIL_REBOOT)!=FALSE,"Schedule owned engine removal");return true;
 }
 Fail("Remove owned engine path",error);
}
bool RemoveAt(const std::wstring& root,std::wstring& retained,bool allowDelay){
 if(!Exists(root))return false;std::vector<Entry> entries;
 try{entries=Owned(root);}catch(...){Note(retained,root+L": unrecognized or unsafe ownership; retained.");return false;}
 bool restart=false,unexpected=false;
 std::set<std::string> files{Lower(".rdc-engine-owner.txt"),Lower(".rdc-manifest.txt")};for(const auto& entry:entries)files.insert(Lower(entry.path));
 auto dirs=Directories(root,entries);
 for(const auto& path:dirs)if(Exists(path))try{Protected(path,true);}catch(...){Note(retained,path+L": unsafe directory retained.");return false;}
 size_t inspected=0;for(auto it=std::filesystem::recursive_directory_iterator(root,std::filesystem::directory_options::none);it!=std::filesystem::recursive_directory_iterator{};++it){
  if(++inspected>16384){unexpected=true;break;}
  const auto path=it->path().wstring();const auto attributes=GetFileAttributesW(Native(path).c_str());if(attributes==INVALID_FILE_ATTRIBUTES)Fail("Inspect engine removal entry");
  if(attributes&FILE_ATTRIBUTE_REPARSE_POINT){it.disable_recursion_pending();unexpected=true;continue;}
  if(attributes&FILE_ATTRIBUTE_DIRECTORY){if(!dirs.count(path)){unexpected=true;it.disable_recursion_pending();}}
  else {const auto relative=std::filesystem::relative(it->path(),root).generic_string();if(!files.count(Lower(relative)))unexpected=true;}
 }
 for(const auto& entry:entries){
  const auto path=root+L"\\"+WidePath(entry.path);if(!Exists(path))continue;
  try{Protected(path,false);restart=Delete(path,false,allowDelay)||restart;}
  catch(...){Note(retained,path+L": locked, redirected or unsafe file retained.");unexpected=true;}
 }
 if(unexpected){Note(retained,root+L": unexpected contents retained with ownership metadata.");return restart;}
 for(const auto* name:{Marker,Manifest}){const auto path=root+L"\\"+name;Protected(path,false);restart=Delete(path,false,allowDelay)||restart;}
 std::vector<std::wstring> ordered(dirs.begin(),dirs.end());std::sort(ordered.begin(),ordered.end(),[](const auto& a,const auto& b){return a.size()>b.size();});
 for(const auto& path:ordered)if(Exists(path)){Protected(path,true);restart=Delete(path,true,allowDelay)||restart;}
 restart=Delete(root,true,allowDelay)||restart;return restart;
}
struct Extraction;
thread_local Extraction* current=nullptr;
struct Stream {
 bool input=false,closed=false,complete=false;size_t position=0,index=0;uint64_t written=0;
 std::unique_ptr<Handle> file;std::unique_ptr<Hash> hash;
};
struct Extraction {
 const std::vector<uint8_t>& cabinet;const std::vector<Entry>& entries;std::wstring target;std::string error;
 std::map<std::string,size_t> names;std::vector<bool> seen;std::vector<std::unique_ptr<Stream>> handles;size_t allocated=0;
 Extraction(const std::vector<uint8_t>& bytes,const std::vector<Entry>& manifest,std::wstring root):cabinet(bytes),entries(manifest),target(std::move(root)),seen(manifest.size(),false){
  for(size_t i=0;i<entries.size();++i)names.emplace(Lower(entries[i].path),i);handles.reserve(entries.size()+8);
 }
 void Error(const char* text)noexcept{try{if(error.empty())error=text;}catch(...){}}
 INT_PTR OpenInput(){
  if(handles.size()>entries.size()+8)throw std::runtime_error("Cabinet opened too many streams.");
  auto file=std::make_unique<Stream>();file->input=true;auto pointer=file.get();handles.push_back(std::move(file));return reinterpret_cast<INT_PTR>(pointer);
 }
 INT_PTR OpenFile(const char* raw,long size){
  const auto length=raw?strnlen_s(raw,241):0;const auto path=Path(raw?std::string_view(raw,length):std::string_view{});
  auto found=names.find(Lower(path));
  if(found==names.end()||size<0||static_cast<uint64_t>(size)!=entries[found->second].size||seen[found->second])throw std::runtime_error("Cabinet file is absent, duplicated or differs from its manifest.");
  seen[found->second]=true;auto stream=std::make_unique<Stream>();stream->index=found->second;stream->hash=std::make_unique<Hash>();
  if(!target.empty())stream->file=Create(target+L"\\"+WidePath(entries[stream->index].path));
  auto pointer=stream.get();handles.push_back(std::move(stream));return reinterpret_cast<INT_PTR>(pointer);
 }
 void Complete(Stream& stream){
  if(stream.closed||stream.input||stream.written!=entries[stream.index].size)throw std::runtime_error("Cabinet file output size differs from its manifest.");
  if(stream.hash->Finish()!=entries[stream.index].sha256)throw std::runtime_error("Cabinet content failed SHA-256 verification.");
  if(stream.file)Require(FlushFileBuffers(stream.file->value)!=FALSE,"Flush verified engine file");
  stream.file.reset();stream.hash.reset();stream.closed=stream.complete=true;
 }
};
struct alignas(std::max_align_t) Allocation {size_t size;};
void* DIAMONDAPI Allocate(ULONG count){
 if(!current||count>32*1024*1024||current->allocated>128*1024*1024-count)return nullptr;
 auto pointer=static_cast<Allocation*>(std::malloc(sizeof(Allocation)+count));if(!pointer)return nullptr;pointer->size=count;current->allocated+=count;return pointer+1;
}
void DIAMONDAPI Free(void* value){if(!value)return;auto pointer=static_cast<Allocation*>(value)-1;if(current)current->allocated-=pointer->size;std::free(pointer);}
INT_PTR DIAMONDAPI Open(char* path,int,int){
 try{if(!current||!path||std::strcmp(path,"payload.cab"))return -1;return current->OpenInput();}
 catch(const std::exception& e){if(current)current->Error(e.what());return -1;}
}
UINT DIAMONDAPI ReadInput(INT_PTR value,void* buffer,UINT count){
 auto* stream=reinterpret_cast<Stream*>(value);if(!current||!stream||!stream->input||stream->closed)return static_cast<UINT>(-1);
 const auto available=current->cabinet.size()-stream->position;const auto length=(std::min)(static_cast<size_t>(count),available);
 std::memcpy(buffer,current->cabinet.data()+stream->position,length);stream->position+=length;return static_cast<UINT>(length);
}
UINT DIAMONDAPI WriteOutput(INT_PTR value,void* buffer,UINT count){
 try{
  auto* stream=reinterpret_cast<Stream*>(value);if(!current||!stream||stream->input||stream->closed||count>current->entries[stream->index].size-stream->written)return static_cast<UINT>(-1);
  if(stream->file){DWORD written=0;if(!WriteFile(stream->file->value,buffer,count,&written,nullptr)||written!=count)Fail("Write bounded engine file");}
  stream->hash->Add(buffer,count);stream->written+=count;return count;
 }catch(const std::exception& e){if(current)current->Error(e.what());return static_cast<UINT>(-1);}
}
int DIAMONDAPI Close(INT_PTR value){auto* stream=reinterpret_cast<Stream*>(value);if(!stream)return -1;stream->file.reset();stream->closed=true;return 0;}
long DIAMONDAPI Seek(INT_PTR value,long offset,int origin){
 auto* stream=reinterpret_cast<Stream*>(value);if(!current||!stream||!stream->input||stream->closed)return -1;
 int64_t base=origin==SEEK_SET?0:origin==SEEK_CUR?static_cast<int64_t>(stream->position):origin==SEEK_END?static_cast<int64_t>(current->cabinet.size()):-1;
 if(base<0||base+offset<0||static_cast<uint64_t>(base+offset)>current->cabinet.size())return -1;stream->position=static_cast<size_t>(base+offset);return static_cast<long>(stream->position);
}
INT_PTR DIAMONDAPI Notify(FDINOTIFICATIONTYPE kind,PFDINOTIFICATION info){
 auto* context=static_cast<Extraction*>(info->pv);
 try{
  if(kind==fdintCOPY_FILE)return context->OpenFile(info->psz1,info->cb);
  if(kind==fdintCLOSE_FILE_INFO){if(info->cb)throw std::runtime_error("Cabinet requested automatic execution; refused.");context->Complete(*reinterpret_cast<Stream*>(info->hf));return TRUE;}
  if(kind==fdintNEXT_CABINET||kind==fdintPARTIAL_FILE)throw std::runtime_error("Spanning cabinets are unsupported.");
  if(kind==fdintCABINET_INFO&&(info->iCabinet||(info->psz1&&*info->psz1)))throw std::runtime_error("Chained cabinets are unsupported.");
  return 0;
 }catch(const std::exception& e){context->Error(e.what());if(kind==fdintCLOSE_FILE_INFO)Close(info->hf);return -1;}
}
void Extract(const std::vector<uint8_t>& cabinet,const std::vector<Entry>& entries,const std::wstring& target){
 if(cabinet.empty()||cabinet.size()>CabinetLimit||current)throw std::runtime_error("Engine cabinet size or extraction nesting is invalid.");
 Extraction extraction(cabinet,entries,target);current=&extraction;struct Clear{~Clear(){current=nullptr;}} clear;
 ERF error{};HFDI fdi=FDICreate(Allocate,Free,Open,ReadInput,WriteOutput,Close,Seek,cpuUNKNOWN,&error);
 if(!fdi)throw std::runtime_error("Windows cabinet decompressor could not be created.");
 struct Destroy{HFDI fdi;~Destroy(){FDIDestroy(fdi);}} destroy{fdi};
 const auto handle=extraction.OpenInput();FDICABINETINFO info{};const bool valid=FDIIsCabinet(fdi,handle,&info)!=FALSE;Close(handle);
 if(!valid||info.hasprev||info.hasnext||info.cFiles!=entries.size()||info.cbCabinet!=cabinet.size())throw std::runtime_error("Engine cabinet header differs from its bounded manifest.");
 char name[]="payload.cab",path[]="";
 if(!FDICopy(fdi,name,path,0,Notify,nullptr,&extraction))throw std::runtime_error(extraction.error.empty()?"Windows cabinet extraction failed.":extraction.error);
 for(const auto& seen:extraction.seen)if(!seen)throw std::runtime_error("Cabinet omitted a required manifest file.");
 for(const auto& stream:extraction.handles)if(!stream->input&&!stream->complete)throw std::runtime_error("Cabinet did not complete all manifest files.");
}
}
std::vector<Entry> ValidateManifest(std::string_view bytes){
 if(bytes.empty()||bytes.size()>1024*1024)throw std::invalid_argument("Engine manifest size exceeds its limit.");
 std::vector<Entry> entries;std::set<std::string> names;uint64_t total=0;size_t at=0;bool header=false;
 while(at<bytes.size()){
  auto end=bytes.find('\n',at);if(end==bytes.npos)end=bytes.size();auto line=bytes.substr(at,end-at);if(!line.empty()&&line.back()=='\r')line.remove_suffix(1);at=end==bytes.size()?end:end+1;
  if(!header){if(line!="RDC-ENGINE-1")throw std::invalid_argument("Engine manifest header is invalid.");header=true;continue;}
  if(line.empty()||entries.size()==2048)throw std::invalid_argument("Engine manifest has empty or excessive entries.");
  const auto first=line.find('\t'),second=first==line.npos?line.npos:line.find('\t',first+1);
  if(first==line.npos||second==line.npos||line.find('\t',second+1)!=line.npos)throw std::invalid_argument("Engine manifest columns are invalid.");
  Entry entry;auto size=line.substr(0,first);const auto converted=std::from_chars(size.data(),size.data()+size.size(),entry.size);
  if(size.empty()||converted.ec!=std::errc{}||converted.ptr!=size.data()+size.size()||entry.size>FileLimit||total>TotalLimit-entry.size)throw std::invalid_argument("Engine manifest file size exceeds its bounds.");
  entry.sha256=std::string(line.substr(first+1,second-first-1));
  if(entry.sha256.size()!=64||entry.sha256.find_first_not_of("0123456789abcdef")!=entry.sha256.npos)throw std::invalid_argument("Engine manifest SHA-256 is invalid.");
  entry.path=Path(line.substr(second+1));if(!names.insert(Lower(entry.path)).second)throw std::invalid_argument("Duplicate Windows engine path was refused.");
  total+=entry.size;entries.push_back(std::move(entry));
 }
 if(entries.empty())throw std::invalid_argument("Engine manifest contains no files.");
 std::set<std::string> directories;for(const auto& entry:entries){auto path=Lower(entry.path);for(auto separator=path.find('/');separator!=path.npos;separator=path.find('/',separator+1)){const auto parent=path.substr(0,separator);if(names.count(parent))throw std::invalid_argument("Engine file/directory path collision was refused.");directories.insert(parent);if(directories.size()>4096)throw std::invalid_argument("Engine directory count exceeds its bound.");}}
 return entries;
}
void ValidateCabinet(const std::vector<uint8_t>& cabinet,const std::vector<uint8_t>& manifest){
 const std::string_view bytes(reinterpret_cast<const char*>(manifest.data()),manifest.size());Extract(cabinet,ValidateManifest(bytes),{});
}
std::wstring EngineDirectory(){return RemoteControl::EngineDirectory();}
bool Present(){
 try{auto root=EngineBundle::EngineDirectory();auto entries=Owned(root);const auto found=std::find_if(entries.begin(),entries.end(),[](const auto& entry){return Lower(entry.path)=="sunshine.exe";});if(found==entries.end())return false;return HashFile(root+L"\\"+WidePath(found->path),found->size)==found->sha256;}catch(...){return false;}
}
bool Install(const std::vector<uint8_t>& cabinet,const std::vector<uint8_t>& manifest){
 const std::string_view bytes(reinterpret_cast<const char*>(manifest.data()),manifest.size());const auto entries=ValidateManifest(bytes);
 if(std::none_of(entries.begin(),entries.end(),[](const auto& entry){return Lower(entry.path)=="sunshine.exe";}))throw std::runtime_error("Engine bundle has no Sunshine.exe entry.");
 CheckProtectedDirectory(ProgramDirectory());const auto root=EngineBundle::EngineDirectory(),stage=root+L".new",old=root+L".old";
 std::wstring retained;for(const auto& path:{stage,old})if(Exists(path)){(void)RemoveAt(path,retained,false);if(Exists(path))throw std::runtime_error("A previous engine staging/rollback folder must be cleared before installation.");}
 Directory(stage);bool preserved=false,activated=false,metadata=false;
 try{
  Write(stage+L"\\"+Marker,Owner);Write(stage+L"\\"+Manifest,bytes);metadata=true;
  auto dirs=Directories(stage,entries);std::vector<std::wstring> ordered(dirs.begin(),dirs.end());std::sort(ordered.begin(),ordered.end(),[](const auto& a,const auto& b){return a.size()<b.size();});for(const auto& path:ordered)Directory(path);
  Extract(cabinet,entries,stage);Verify(stage,entries);
  if(Exists(root)){(void)Owned(root);Require(MoveFileExW(Native(root).c_str(),Native(old).c_str(),MOVEFILE_WRITE_THROUGH)!=FALSE,"Preserve previous engine");preserved=true;}
  Require(MoveFileExW(Native(stage).c_str(),Native(root).c_str(),MOVEFILE_WRITE_THROUGH)!=FALSE,"Activate verified engine");activated=true;Verify(root,entries);
 }catch(...){
  bool rollbackFailed=false;
  if(activated){if(MoveFileExW(Native(root).c_str(),Native(stage).c_str(),MOVEFILE_WRITE_THROUGH)){if(preserved&&!MoveFileExW(Native(old).c_str(),Native(root).c_str(),MOVEFILE_WRITE_THROUGH))rollbackFailed=true;}else rollbackFailed=true;}
  else if(preserved&&!Exists(root)&&!MoveFileExW(Native(old).c_str(),Native(root).c_str(),MOVEFILE_WRITE_THROUGH))rollbackFailed=true;
  if(Exists(stage))try{if(metadata){std::wstring ignored;(void)RemoveAt(stage,ignored,true);}else{for(const auto* name:{Marker,Manifest}){const auto file=stage+L"\\"+name;if(Exists(file)){Protected(file,false);(void)Delete(file,false,false);}}Protected(stage,true);(void)Delete(stage,true,false);}}catch(...){}
  if(rollbackFailed)throw std::runtime_error("Engine activation failed and its rollback folder could not be restored. The previous files were retained for repair.");
  throw;
 }
 bool restart=false;if(Exists(old))restart=RemoveAt(old,retained,true);if(!retained.empty())throw std::runtime_error("The new engine was verified, but unexpected rollback contents were retained. Review the Engine.old directory before repairing.");return restart;
}
bool Remove(std::wstring& retained){
 retained.clear();bool restart=false;const auto root=EngineBundle::EngineDirectory();
 for(const auto& path:{root,root+L".new",root+L".old"})try{restart=RemoveAt(path,retained,true)||restart;}catch(...){Note(retained,path+L": removal incomplete; retained.");}
 return restart;
}
}
