#include "Client.h"
#include "GameStreamClient.h"
#include "GameStreamCodec.h"
#include "Transport.h"
#include <atomic>
#include <array>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <stdexcept>
#include <thread>

namespace RemoteControl {
struct Client::State {
    static std::atomic<State*> active;static std::mutex engineMutex;
    TitanTransport::Runtime runtime;std::function<void()> changed;
    mutable std::mutex mutex;std::mutex inputMutex,startMutex;std::condition_variable wake;
    ClientInfo info;std::shared_ptr<const Frame> latest;std::shared_ptr<GameStreamControl> control;
    std::thread supervisor,decoder;std::atomic<bool> stop{true},starting{false},decodeStop{true};
    std::array<bool,232> held{};uint8_t buttons=0;uint32_t width=0,height=0,fps=0;
    explicit State(std::function<void()> callback):changed(std::move(callback)){GameStreamFormat::InitializeCrypto();}
    void Notify()noexcept{if(changed)try{changed();}catch(...){} }
    void Status(const std::string& text){{std::lock_guard<std::mutex> lock(mutex);info.status=text;}Notify();}
    void Failure(std::string_view text)noexcept{try{std::lock_guard<std::mutex> lock(mutex);info.status=text;info.connecting=false;}catch(...){}stop=true;wake.notify_all();Notify();}
    static void Stage(int stage)noexcept{if(auto self=active.load())try{self->Status("GameStream: "+std::string(LiGetStageName(stage)));}catch(...){self->stop=true;}}
    static void StageFailed(int stage,int error)noexcept{if(auto self=active.load())try{self->Failure("GameStream "+std::string(LiGetStageName(stage))+" failed (error "+std::to_string(error)+").");}catch(...){self->Failure("GameStream connection stage failed.");}}
    static void Terminated(int error)noexcept{if(auto self=active.load())try{if(!self->stop)self->Failure("Sunshine ended the stream (error "+std::to_string(error)+").");self->stop=true;self->wake.notify_all();}catch(...){self->Failure("Sunshine ended the stream.");}}
    static int SetupVideo(int format,int w,int h,int rate,void* context,int)noexcept{
        auto self=static_cast<State*>(context);if(!self||format!=VIDEO_FORMAT_H264||w<2||h<2||w>static_cast<int>(MaxWidth)||h>static_cast<int>(MaxHeight)||rate<1||rate>240)return -1;
        self->width=static_cast<uint32_t>(w);self->height=static_cast<uint32_t>(h);self->fps=static_cast<uint32_t>(rate);return 0;
    }
    static void StartVideo()noexcept{if(auto self=active.load())try{self->decodeStop=false;self->decoder=std::thread([self]{self->Decode();});}catch(const std::exception& error){self->Failure(error.what());}}
    static void StopVideo()noexcept{if(auto self=active.load()){self->decodeStop=true;LiWakeWaitForVideoFrame();if(self->decoder.joinable())self->decoder.join();}}
    void Decode()noexcept{
        try{
            // Every COM/MF operation, including destruction, stays on this fixed
            // worker. Moonlight owns the only bounded encoded-frame queue.
            GameStreamCodec codec;codec.Configure(width,height,fps);std::vector<uint8_t> bytes;
            uint64_t window=GetTickCount64(),frames=0;unsigned failures=0;
            while(!decodeStop){
                VIDEO_FRAME_HANDLE handle=nullptr;PDECODE_UNIT unit=nullptr;
                if(!LiWaitForNextVideoFrame(&handle,&unit))break;
                struct Complete {VIDEO_FRAME_HANDLE handle;int status=DR_OK;~Complete(){LiCompleteVideoFrame(handle,status);}} complete{handle};
                if(decodeStop)break;
                try{
                    if(!unit||unit->fullLength<=0||static_cast<uint32_t>(unit->fullLength)>MaxFrameBytes)throw std::runtime_error("GameStream H.264 access unit exceeds its bound.");
                    bytes.resize(static_cast<size_t>(unit->fullLength));size_t at=0;unsigned fragments=0;
                    for(auto entry=unit->bufferList;entry;entry=entry->next){if(++fragments>4096||!entry->data||entry->length<=0||static_cast<size_t>(entry->length)>bytes.size()-at)throw std::runtime_error("Invalid GameStream H.264 fragment chain.");memcpy(bytes.data()+at,entry->data,static_cast<size_t>(entry->length));at+=static_cast<size_t>(entry->length);}
                    if(at!=bytes.size())throw std::runtime_error("Truncated GameStream H.264 access unit.");
                    auto frame=codec.Decode(bytes.data(),bytes.size(),static_cast<uint32_t>(unit->frameNumber),unit->frameType==FRAME_TYPE_IDR);
                    if(frame){failures=0;std::lock_guard<std::mutex> lock(mutex);latest=std::move(frame);++frames;const auto now=GetTickCount64();if(now-window>=1000){info.framesPerSecond=double(frames)*1000.0/double(now-window);frames=0;window=now;}if(info.connected)info.status="Connected. "+codec.Description();}
                    Notify();
                }catch(const std::exception& error){complete.status=DR_NEED_IDR;if(++failures>3){Failure(error.what());break;}}
            }
            codec.Reset();
        }catch(const std::exception& error){Failure(error.what());}
        catch(...){Failure("Unexpected H.264 decoder failure.");}
    }
    char Modifiers()const noexcept{unsigned flags=0;if(held[225]||held[229])flags|=MODIFIER_SHIFT;if(held[224]||held[228])flags|=MODIFIER_CTRL;if(held[226]||held[230])flags|=MODIFIER_ALT;if(held[227]||held[231])flags|=MODIFIER_META;return static_cast<char>(flags);}
    void ReleaseHeld()noexcept{
        for(uint32_t usage=4;usage<held.size();++usage)if(held[usage]){held[usage]=false;const auto key=GameStreamFormat::KeyFromUsage(usage);if(key.value)(void)LiSendKeyboardEvent2(static_cast<short>(key.value),KEY_ACTION_UP,static_cast<char>(Modifiers()|(key.extended?MODIFIER_EXTENDED:0)),0);}
        static constexpr int map[]{0,BUTTON_LEFT,BUTTON_RIGHT,BUTTON_MIDDLE,BUTTON_X1,BUTTON_X2};for(unsigned button=1;button<=5;++button)if(buttons&(1u<<(button-1)))(void)LiSendMouseButtonEvent(BUTTON_ACTION_RELEASE,map[button]);buttons=0;
    }
    void Send(const Input& value){
        int result=0;switch(value.kind){
        case InputKind::Pointer:result=LiSendMousePositionEvent(static_cast<short>(uint32_t(value.x)*32767u/65535u),static_cast<short>(uint32_t(value.y)*32767u/65535u),32767,32767);break;
        case InputKind::Button:{static constexpr int map[]{0,BUTTON_LEFT,BUTTON_RIGHT,BUTTON_MIDDLE,BUTTON_X1,BUTTON_X2};const auto bit=static_cast<uint8_t>(1u<<(value.code-1));if(value.down)buttons|=bit;else buttons&=static_cast<uint8_t>(~bit);result=LiSendMouseButtonEvent(value.down?BUTTON_ACTION_PRESS:BUTTON_ACTION_RELEASE,map[value.code]);break;}
        case InputKind::Key:{const auto key=GameStreamFormat::KeyFromUsage(value.code);if(!key.value)return;held[value.code]=value.down!=0;result=LiSendKeyboardEvent2(static_cast<short>(key.value),value.down?KEY_ACTION_DOWN:KEY_ACTION_UP,static_cast<char>(Modifiers()|(key.extended?MODIFIER_EXTENDED:0)),0);break;}
        case InputKind::Wheel:if(value.y)result=LiSendScrollEvent(static_cast<signed char>(value.y));if(!result&&value.x)result=LiSendHScrollEvent(static_cast<signed char>(value.x));break;
        case InputKind::ReleaseAll:ReleaseHeld();break;
        default:return;
        }
        if(result)throw std::runtime_error("GameStream input queue rejected an event (error "+std::to_string(result)+").");
    }
    void Run(Pairing pairing,unsigned targetFps)noexcept{
        std::unique_lock<std::mutex> exclusive(engineMutex,std::try_to_lock);if(!exclusive.owns_lock()){Failure("Only one GameStream client connection can run in this process.");return;}
        bool opened=false;active=this;
        try{
            auto engine=std::make_shared<GameStreamControl>(std::move(pairing),[this]{return stop.load();});{std::lock_guard<std::mutex> guard(mutex);control=engine;}
            Status("Authorizing and preparing Sunshine; approve the connection on the host if requested...");
            engine->AuthorizeAndLaunch(1920,1080,targetFps);if(stop)throw std::runtime_error("GameStream connection cancelled.");
            auto server=engine->Server();auto configuration=engine->Stream();CONNECTION_LISTENER_CALLBACKS connection{};DECODER_RENDERER_CALLBACKS video{};LiInitializeConnectionCallbacks(&connection);LiInitializeVideoCallbacks(&video);connection.stageStarting=Stage;connection.stageFailed=StageFailed;connection.connectionTerminated=Terminated;video.setup=SetupVideo;video.start=StartVideo;video.stop=StopVideo;video.capabilities=CAPABILITY_PULL_RENDERER;
            {std::lock_guard<std::mutex> guard(startMutex);if(stop)throw std::runtime_error("GameStream connection cancelled.");starting=true;}
            const auto result=LiStartConnection(&server,&configuration,&connection,&video,nullptr,this,0,nullptr,0);starting=false;wake.notify_all();SecureZeroMemory(&configuration,sizeof(configuration));
            if(result)throw std::runtime_error("Moonlight GameStream connection failed (error "+std::to_string(result)+").");opened=true;
            {std::lock_guard<std::mutex> inputLock(inputMutex);if(stop)throw std::runtime_error("GameStream connection cancelled.");std::lock_guard<std::mutex> guard(mutex);info.connected=true;info.connecting=false;info.route="Direct Sunshine / encrypted GameStream";info.status="Connected. Click the desktop to control keyboard and mouse.";}
            Notify();
            while(!stop){uint32_t rtt=0,variance=0;if(LiGetEstimatedRttInfo(&rtt,&variance)){std::lock_guard<std::mutex> guard(mutex);info.inputRttMs=rtt;}std::unique_lock<std::mutex> guard(mutex);wake.wait_for(guard,std::chrono::milliseconds(250),[this]{return stop.load();});}
        }catch(const std::exception& error){if(!stop)Failure(error.what());}
        catch(...){Failure("Unexpected GameStream client failure.");}
        starting=false;wake.notify_all();
        {std::lock_guard<std::mutex> inputLock(inputMutex);{std::lock_guard<std::mutex> guard(mutex);info.connected=info.connecting=false;}if(opened)ReleaseHeld();}
        if(opened)LiStopConnection();else if(decoder.joinable())StopVideo();
        std::shared_ptr<GameStreamControl> engine;{std::lock_guard<std::mutex> guard(mutex);engine=std::move(control);}
        if(engine)engine->CloseApp();active=nullptr;stop=true;Notify();
    }
    void Stop()noexcept{
        stop=true;wake.notify_all();std::shared_ptr<GameStreamControl> engine;{std::lock_guard<std::mutex> guard(mutex);engine=control;}if(engine)engine->Cancel();
        {std::lock_guard<std::mutex> guard(startMutex);}
        // Repeated interruption covers the small interval before LiStartConnection
        // resets its cancellation flag. No polling exists while streaming.
        while(starting&&active.load()==this){LiInterruptConnection();std::unique_lock<std::mutex> guard(mutex);wake.wait_for(guard,std::chrono::milliseconds(10));}
        if(supervisor.joinable())supervisor.join();
    }
};
std::atomic<Client::State*> Client::State::active{nullptr};std::mutex Client::State::engineMutex;
Client::Client(std::function<void()> changed):state_(std::make_unique<State>(std::move(changed))){}
Client::~Client(){Stop();}
void Client::Start(Pairing pairing,unsigned mode,unsigned targetFps){
    if(mode>2||targetFps<1||targetFps>240)throw std::invalid_argument("Choose a video target between 1 and 240 FPS.");if(!TitanTransport::IsFingerprint(pairing.pin)||!TitanTransport::IsSecret(pairing.secret)||pairing.noCode!=(pairing.secret==OpenAccessSecret))throw std::invalid_argument("Invalid pinned Sunshine connection parameters.");
    wchar_t localFingerprint[80]{};DWORD length=sizeof(localFingerprint);if(RegGetValueW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\TitanCSA\\RemoteDeviceControl",L"HostFingerprint",RRF_RT_REG_SZ|RRF_SUBKEY_WOW6464KEY,nullptr,localFingerprint,&length)==ERROR_SUCCESS&&TitanTransport::ConstantTimeEqual(Utf8(localFingerprint),pairing.pin))throw std::runtime_error("Connecting this viewer to its own installed host is refused to prevent keyboard/mouse feedback.");
    Stop();state_->stop=false;state_->decodeStop=true;state_->held.fill(false);state_->buttons=0;{std::lock_guard<std::mutex> guard(state_->mutex);state_->info={};state_->info.connecting=true;state_->info.status="Connecting directly to Sunshine...";state_->latest.reset();}state_->Notify();try{state_->supervisor=std::thread([state=state_.get(),pairing=std::move(pairing),targetFps]()mutable{state->Run(std::move(pairing),targetFps);});}catch(const std::exception& error){state_->Failure(error.what());throw;}
}
void Client::Stop()noexcept{state_->Stop();}
void Client::Push(Input input){if(!ValidInput(input))return;std::lock_guard<std::mutex> inputLock(state_->inputMutex);{std::lock_guard<std::mutex> guard(state_->mutex);if(!state_->info.connected||state_->stop)return;}try{state_->Send(input);}catch(const std::exception& error){state_->Failure(error.what());}}
ClientInfo Client::Info()const{std::lock_guard<std::mutex> guard(state_->mutex);return state_->info;}
std::shared_ptr<const Frame> Client::Latest()const{std::lock_guard<std::mutex> guard(state_->mutex);return state_->latest;}
}
