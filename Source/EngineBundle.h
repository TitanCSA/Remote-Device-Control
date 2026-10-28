#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
namespace RemoteControl::EngineBundle {
struct Entry {uint64_t size=0;std::string sha256,path;};
std::vector<Entry> ValidateManifest(std::string_view bytes);
void ValidateCabinet(const std::vector<uint8_t>& cabinet,const std::vector<uint8_t>& manifest);
std::wstring EngineDirectory();
// Caller serializes installer operations and stops the host/engine first.
// true means locked owned files have been scheduled for deletion at restart.
bool Install(const std::vector<uint8_t>& cabinet,const std::vector<uint8_t>& manifest);
bool Remove(std::wstring& retained);
bool Present();
}
