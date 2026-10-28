#pragma once
#include "Transport.h"
#include "Protocol.h"
#include <cstring>
#include <mutex>
#include <stdexcept>
namespace RemoteControl {
enum class Message:uint32_t {Auth=1,Grant=2,Inputs=3,Ack=4,VideoAuth=5,Video=6,Error=7,KeepAlive=8};
struct Packet {Message type;uint64_t sequence=0;std::vector<uint8_t> data;};
struct WireHeader {uint32_t magic=0x31434452,version=1,type=0,size=0;uint64_t sequence=0;};
static_assert(sizeof(WireHeader)==24);
class Link {
 std::mutex writer_;
public:
 TitanTransport::Channel channel;
 explicit Link(SOCKET socket):channel(socket){}
 explicit Link(std::unique_ptr<TitanTransport::ByteStream> stream):channel(std::move(stream)){}
 void Send(Message type,const void* data,size_t size,uint64_t sequence=0){
  if(size>MaxFrameBytes+64)throw std::runtime_error("Outgoing packet is too large.");std::lock_guard<std::mutex> lock(writer_);WireHeader header;header.type=static_cast<uint32_t>(type);header.size=static_cast<uint32_t>(size);header.sequence=sequence;channel.Send(&header,sizeof(header));if(size)channel.Send(data,size);
 }
 void Send(Message type,const std::vector<uint8_t>& data,uint64_t sequence=0){Send(type,data.data(),data.size(),sequence);}
 void Send(Message type,const std::string& data,uint64_t sequence=0){Send(type,data.data(),data.size(),sequence);}
 Packet Receive(uint32_t timeout=5000){WireHeader header{};channel.Receive(&header,sizeof(header),timeout);if(header.magic!=0x31434452||header.version!=1||header.type<1||header.type>8||header.size>MaxFrameBytes+64)throw std::runtime_error("Invalid remote packet header.");Packet p{static_cast<Message>(header.type),header.sequence,{}};p.data.resize(header.size);if(header.size)channel.Receive(p.data.data(),p.data.size(),timeout);return p;}
 void Close()noexcept{channel.Close();}
};
inline std::string Text(const Packet& p){if(p.data.size()>2048)throw std::runtime_error("Invalid remote message size.");return {reinterpret_cast<const char*>(p.data.data()),p.data.size()};}
inline void ThrowIfError(const Packet& p){if(p.type==Message::Error)throw std::runtime_error(Text(p));}
struct VideoMetadata {uint32_t width,height;uint64_t sequence,capturedQpc;};
inline std::vector<uint8_t> VideoBytes(const EncodedFrame& f){if(!f.width||!f.height||f.width>MaxWidth||f.height>MaxHeight||f.jpeg.empty()||f.jpeg.size()>MaxFrameBytes)throw std::runtime_error("Invalid captured video frame.");VideoMetadata m{f.width,f.height,f.sequence,f.capturedQpc};std::vector<uint8_t> out(sizeof(m)+f.jpeg.size());memcpy(out.data(),&m,sizeof(m));memcpy(out.data()+sizeof(m),f.jpeg.data(),f.jpeg.size());return out;}
inline VideoMetadata VideoInfo(const Packet& p){if(p.type!=Message::Video||p.data.size()<=sizeof(VideoMetadata))throw std::runtime_error("Invalid video packet.");VideoMetadata m{};memcpy(&m,p.data.data(),sizeof(m));if(!m.width||!m.height||m.width>MaxWidth||m.height>MaxHeight||p.data.size()-sizeof(m)>MaxFrameBytes)throw std::runtime_error("Video dimensions exceed limits.");return m;}
}
