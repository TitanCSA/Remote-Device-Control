#include "../Source/GameStreamClient.h"
#include "../Source/Transport.h"
#define USE_MBEDTLS
extern "C" {
#include <PlatformCrypto.h>
}
#undef USE_MBEDTLS
#include <array>
#include <atomic>
#include <thread>
#include <cstring>
#include <iostream>
#include <limits>
#include <stdexcept>

int main(){try{
 using namespace RemoteControl;using namespace GameStreamFormat;unsigned checks=0;
 const auto check=[&](bool value,const char* why){++checks;if(!value)throw std::runtime_error(why);};
 const auto refuses=[&](auto action,const char* why){bool invalid=false;try{action();}catch(const std::exception&){invalid=true;}check(invalid,why);};
 check(Decimal("0",0)==0&&Decimal("65535",65535)==65535,"Valid bounded decimal rejected");
 check(Decimal("4294967295",(std::numeric_limits<uint32_t>::max)())==(std::numeric_limits<uint32_t>::max)(),"Maximum uint32 rejected");
 for(const auto* text:{"","-1","+1"," 1","1 ","1a","4294967296","99999999999"})refuses([&]{(void)Decimal(text,(std::numeric_limits<uint32_t>::max)());},"Invalid decimal accepted");
 refuses([&]{(void)Decimal("4294967296",0);},"Small-bound arithmetic overflow accepted");
 for(uint32_t maximum=0;maximum<100;++maximum){check(Decimal(std::to_string(maximum),maximum)==maximum,"Exact decimal limit rejected");refuses([&]{(void)Decimal(std::to_string(maximum+1),maximum);},"Decimal limit exceeded");}
 ValidateVersion("7.1.431.-1",true);check(true,"Canonical Sunshine version marker rejected");ValidateVersion("3.23.0.74");check(true,"Canonical GFE version rejected");ValidateVersion("7.1.431.0",true);check(true,"Normal four-component version rejected");ValidateVersion("2147483647.2147483647.2147483647.2147483647");check(true,"Bounded signed integer version rejected");
 for(const auto* invalid:{"","7.1.431","7.1.431.0.1","7.1..0","7.1.431.","7.1.431.-2","-1.1.431.0","7.-1.431.0","7.1.-1.0","7.1.431.+1","7.1.431.-0","7.1.431.1 ","7.1.431.2147483648","7.1.431.0junk"})refuses([&]{ValidateVersion(invalid,true);},"Malformed/overflowing version accepted");
 refuses([&]{ValidateVersion("3.23.0.-1");},"Sunshine marker accepted in a GFE version");
 check(XmlText("<?xml version=\"1.0\"?><root status_code=\"200\"><name>A &amp; B &#x1f642;</name></root>","name")=="A & B \xf0\x9f\x99\x82","XML UTF-8/entity decoding");
 check(XmlText("<root><empty></empty></root>","missing").empty(),"Missing optional XML field");
 for(const auto* xml:{"<name>&unknown;</name>","<name>&#0;</name>","<name>&#xD800;</name>","<name>&#x110000;</name>","<name><nested/></name>","<!DOCTYPE x><name>x</name>","<name>unfinished"})refuses([&]{(void)XmlText(xml,"name");},"Unsafe XML accepted");
 refuses([&]{(void)XmlText("<name>12345</name>","name",4);},"XML output limit exceeded");
 RequireXmlSuccess("<?xml version=\"1.0\"?><root status_code=\"200\" />");check(true,"Valid GameStream status rejected");
 std::string diagnostic;try{RequireXmlSuccess("<root status_code='403' status_message='Host &amp; client: permission denied &#x1f642;'/>");}catch(const std::exception& error){diagnostic=error.what();}
 check(diagnostic=="Sunshine refused the GameStream request (status 403). Host & client: permission denied \xf0\x9f\x99\x82","Authenticated escaped UTF-8 status detail lost");
 try{RequireXmlSuccess("<root status_code='503' status_message='  A&#x0a;&#x1b; B&#x202e; C&#x85;  '/>");}catch(const std::exception& error){diagnostic=error.what();}
 check(diagnostic=="Sunshine refused the GameStream request (status 503). A B C","Error controls or bidirectional markers reached UI");
 for(const auto* invalid:{"<root extra_status_code='200'/>","<root status_code='200' status_code='200'/>","<root status_code='403' status_message='A' status_message='B'/>","<root status_code='200'broken='x'/>","<rooted status_code='200'/>","<root status_code=200/>","<root status_code='403' status_message='&#0;'/>","<root status_code='403' status_message='&#xD800;'/>","<!DOCTYPE root><root status_code='200'/>"})refuses([&]{RequireXmlSuccess(invalid);},"Malformed GameStream root attributes accepted");
 try{RequireXmlSuccess("<root status_code='403' status_message='"+std::string(513,'x')+"'/>");}catch(const std::exception& error){diagnostic=error.what();}
 check(diagnostic=="GameStream error message exceeds its limit.","Oversized authenticated error reached UI");
 try{RequireXmlSuccess("<root status_code='403' status_message='"+std::string("\xc0\xaf",2)+"'/>");}catch(const std::exception& error){diagnostic=error.what();}
 check(diagnostic.find("UTF-8")!=diagnostic.npos,"Malformed UTF-8 authenticated error reached UI");
 check(JsonQuote("line\n\"quoted\"\\path")=="\"line\\u000a\\\"quoted\\\"\\\\path\"","Bootstrap JSON escaping");
 refuses([&]{(void)JsonQuote(std::string(8193,'x'));},"Bootstrap field limit exceeded");
 refuses([&]{(void)JsonQuote(std::string("\xc0\xaf",2));},"Invalid UTF-8 JSON accepted");
 const std::string body="<root status_code=\"200\"><appversion>7.1.431.0</appversion></root>";
 const auto response="HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: "+std::to_string(body.size())+"\r\n\r\n"+body;
 const auto decoded=DecodeHttp(response);check(decoded.status==200&&decoded.body==body,"HTTP content-length parsing");
 for(size_t size=0;size<response.size();++size)refuses([&]{(void)DecodeHttp(std::string_view(response).substr(0,size));},"Truncated HTTP accepted");
 const auto chunks=DecodeHttp("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4;mode=test\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Test: yes\r\n\r\n");check(chunks.body=="Wikipedia","HTTP bounded chunk/trailer parsing");
 check(DecodeHttp("HTTP/1.1 204 No Content\r\n\r\n").body.empty(),"Empty HTTP204 parsing");
 for(const auto* invalid:{"HTTP/1.1 abc Error\r\nContent-Length: 0\r\n\r\n","HTTP/1.1 200 OK\r\n\r\n","HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx","HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n","HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n","HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffff\r\n","HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n","HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nxZZ","HTTP/1.1 204 No Content\r\n\r\nextra"})refuses([&]{(void)DecodeHttp(invalid);},"Ambiguous/oversized HTTP accepted");
 check(KeyFromUsage(4).value=='A'&&KeyFromUsage(29).value=='Z',"USB letter mapping");check(KeyFromUsage(30).value=='1'&&KeyFromUsage(39).value=='0',"USB number mapping");
 check(KeyFromUsage(40).value==VK_RETURN&&!KeyFromUsage(40).extended&&KeyFromUsage(88).value==VK_RETURN&&KeyFromUsage(88).extended,"Main/keypad Enter distinction");
 check(KeyFromUsage(224).value==VK_LCONTROL&&!KeyFromUsage(224).extended&&KeyFromUsage(228).value==VK_RCONTROL&&KeyFromUsage(228).extended,"Left/right Control distinction");
 check(KeyFromUsage(104).value==VK_F13&&KeyFromUsage(115).value==VK_F24,"Extended function keys");check(!KeyFromUsage(0).value&&!KeyFromUsage(232).value,"Unsupported key bounds");
 // Exercise the exact upstream crypto compiled into this client, not a mock or
 // a different ENet/OpenSSL library found elsewhere on the PC.
 InitializeCrypto();std::array<unsigned char,16> key{},iv{},tag{};std::array<unsigned char,37> plain{};PltGenerateRandomData(key.data(),static_cast<int>(key.size()));for(size_t i=0;i<plain.size();++i)plain[i]=static_cast<unsigned char>(i);
 struct Crypto {PPLT_CRYPTO_CONTEXT value=PltCreateCryptoContext();~Crypto(){PltDestroyCryptoContext(value);}} encrypt,decrypt,tampered;
 check(encrypt.value&&decrypt.value&&tampered.value,"Upstream crypto context creation");std::array<unsigned char,128> cipher{},restored{};int cipherSize=0,restoredSize=0;
 const auto encoded=PltEncryptMessage(encrypt.value,ALGORITHM_AES_GCM,CIPHER_FLAG_RESET_IV,key.data(),16,iv.data(),12,tag.data(),16,plain.data(),static_cast<int>(plain.size()),cipher.data(),&cipherSize);
 if(!encoded){psa_key_attributes_t attributes=PSA_KEY_ATTRIBUTES_INIT;psa_set_key_type(&attributes,PSA_KEY_TYPE_AES);psa_set_key_bits(&attributes,128);psa_set_key_usage_flags(&attributes,PSA_KEY_USAGE_ENCRYPT);psa_set_key_algorithm(&attributes,PSA_ALG_GCM);psa_key_id_t id=0;const auto imported=psa_import_key(&attributes,key.data(),key.size(),&id);psa_aead_operation_t operation=PSA_AEAD_OPERATION_INIT;const auto setup=psa_aead_encrypt_setup(&operation,id,PSA_ALG_GCM);const auto lengths=psa_aead_set_lengths(&operation,0,plain.size());const auto nonce=psa_aead_set_nonce(&operation,iv.data(),12);size_t used=0,tail=0,auth=0;const auto update=psa_aead_update(&operation,plain.data(),plain.size(),cipher.data(),plain.size(),&used);const auto finish=psa_aead_finish(&operation,cipher.data()+used,plain.size()-used,&tail,tag.data(),tag.size(),&auth);psa_aead_abort(&operation);psa_destroy_key(id);psa_reset_key_attributes(&attributes);std::cerr<<"PSA diagnostics import="<<imported<<" setup="<<setup<<" lengths="<<lengths<<" nonce="<<nonce<<" update="<<update<<" finish="<<finish<<" bytes="<<used<<" tail="<<tail<<"\n";}
 check(encoded,"Upstream encrypted input/video encoding");
 check(PltDecryptMessage(decrypt.value,ALGORITHM_AES_GCM,CIPHER_FLAG_RESET_IV,key.data(),16,iv.data(),12,tag.data(),16,cipher.data(),cipherSize,restored.data(),&restoredSize)&&restoredSize==plain.size()&&!memcmp(plain.data(),restored.data(),plain.size()),"Upstream authenticated encryption roundtrip");
 tag[0]^=1;check(!PltDecryptMessage(tampered.value,ALGORITHM_AES_GCM,CIPHER_FLAG_RESET_IV,key.data(),16,iv.data(),12,tag.data(),16,cipher.data(),cipherSize,restored.data(),&restoredSize),"Tampered upstream encrypted packet accepted");
 // ControlStream encrypts in place with a reused context and variable packet
 // sizes, unlike video decryption. Cover every short/tail size, including the
 // real key/button/pointer/scroll payloads plus their four-byte control header.
 Crypto controlWriter,controlReader;
 for(size_t size=0;size<=128;++size){std::array<unsigned char,160> packet{},expected{};std::array<unsigned char,16> nonce{},auth{};nonce[0]=static_cast<unsigned char>(size);for(size_t at=0;at<size;++at)packet[at]=expected[at]=static_cast<unsigned char>(at*13+size);int written=0,read=0;
  check(PltEncryptMessage(controlWriter.value,ALGORITHM_AES_GCM,0,key.data(),16,nonce.data(),12,auth.data(),16,packet.data(),static_cast<int>(size),packet.data(),&written)&&written==size,"In-place variable-length control encryption failed");
  check(PltDecryptMessage(controlReader.value,ALGORITHM_AES_GCM,0,key.data(),16,nonce.data(),12,auth.data(),16,packet.data(),written,packet.data(),&read)&&read==size&&!memcmp(packet.data(),expected.data(),size),"In-place variable-length control decryption failed");}
 std::atomic<unsigned> cryptoFailures{0};std::array<std::thread,8> workers;
 for(unsigned worker=0;worker<workers.size();++worker)workers[worker]=std::thread([&,worker]{for(unsigned iteration=0;iteration<1000;++iteration){Crypto writer,reader;std::array<unsigned char,16> nonce{},auth{};std::array<unsigned char,128> encrypted{},decrypted{};nonce[0]=static_cast<unsigned char>(worker);memcpy(nonce.data()+1,&iteration,sizeof(iteration));int written=0,read=0;
   if(!writer.value||!reader.value||!PltEncryptMessage(writer.value,ALGORITHM_AES_GCM,CIPHER_FLAG_RESET_IV,key.data(),16,nonce.data(),12,auth.data(),16,plain.data(),static_cast<int>(plain.size()),encrypted.data(),&written)||!PltDecryptMessage(reader.value,ALGORITHM_AES_GCM,CIPHER_FLAG_RESET_IV,key.data(),16,nonce.data(),12,auth.data(),16,encrypted.data(),written,decrypted.data(),&read)||read!=plain.size()||memcmp(plain.data(),decrypted.data(),plain.size()))++cryptoFailures;}});
 for(auto& worker:workers)worker.join();check(!cryptoFailures,"Concurrent upstream PSA key-slot/crypto operations failed");
 {Client client([]{});check(!client.Info().connected&&!client.Latest(),"Client started before an explicit connection");client.Stop();}
 std::cout<<"PASS "<<checks<<" offline GameStream numeric/XML/JSON/HTTP/input/lifecycle checks. No network, driver or capture access.\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
