  // Pairing is TLS-pinned by the native viewer and authorized by the managed
  // access policy. The legacy HTTP PIN pairing routes are not registered.
  std::string rdc_client_identity(req_https_t request) {
    const auto socket=request->socket();
    if(!socket)return {};
    crypto::x509_t certificate{SSL_get1_peer_certificate(socket->native_handle())};
    if(!certificate)return {};
    unsigned char digest[EVP_MAX_MD_SIZE]{};unsigned length=0;
    if(!X509_digest(certificate.get(),EVP_sha256(),digest,&length)||length!=32)return {};
    constexpr char hex[]="0123456789abcdef";std::string result(64,'0');
    for(size_t i=0;i<32;++i){result[i*2]=hex[digest[i]>>4];result[i*2+1]=hex[digest[i]&15];}return result;
  }
  bool rdc_hex(std::string_view value,size_t count) {
    if(value.size()!=count)return false;
    for(char c:value)if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return false;
    return true;
  }
  void rdc_pair(resp_https_t response,req_https_t request) {
    const SimpleWeb::CaseInsensitiveMultimap headers{{"Content-Type","application/json"},{"Cache-Control","no-store"}};
    response->close_connection_after_response=true;
    auto send=[&](SimpleWeb::StatusCode code,std::string body){auto framed=headers;framed.emplace("Content-Length",std::to_string(body.size()));response->write(code,body,framed);};
    auto reject=[&](SimpleWeb::StatusCode code,const char* text){nlohmann::json body={{"ok",false},{"error",text}};send(code,body.dump());};
    try{
      if(!request->query_string.empty()||request->header.count("Origin")||request->header.count("Content-Type")!=1||request->header.find("Content-Type")->second!="application/json"){
        reject(SimpleWeb::StatusCode::client_error_bad_request,"Use an application/json POST without query parameters or browser Origin.");return;
      }
      const auto text=request->content.string();if(text.empty()||text.size()>12288){reject(SimpleWeb::StatusCode::client_error_payload_too_large,"Pairing JSON exceeds the 12288-byte limit.");return;}
      std::set<std::string> fields;
      const auto body=nlohmann::json::parse(text,[&](int,nlohmann::json::parse_event_t event,nlohmann::json& parsed){if(event==nlohmann::json::parse_event_t::key&&!fields.insert(parsed.get<std::string>()).second)throw std::invalid_argument("Duplicate JSON field");return true;});
      if(!body.is_object()||body.size()!=3||!body.contains("certificate")||!body.contains("secret")||!body.contains("clientid")||!body["certificate"].is_string()||!body["secret"].is_string()||!body["clientid"].is_string()){
        reject(SimpleWeb::StatusCode::client_error_bad_request,"Expected certificate, secret and clientid string fields.");return;
      }
      const auto secret=body["secret"].get<std::string>();const auto id=body["clientid"].get<std::string>();
      if(!rdc_hex(id,32)||!rdc::pairing_allowed(secret)){reject(SimpleWeb::StatusCode::client_error_forbidden,"The access key is invalid or connections without a key are disabled.");return;}
      const auto pem=body["certificate"].get<std::string>();if(pem.empty()||pem.size()>8192){reject(SimpleWeb::StatusCode::client_error_bad_request,"The client certificate exceeds the 8192-byte limit.");return;}
      auto certificate=crypto::x509(pem);if(!certificate){reject(SimpleWeb::StatusCode::client_error_bad_request,"The client certificate is not valid PEM X.509 data.");return;}
      const auto key=X509_get0_pubkey(certificate.get());if(!key||EVP_PKEY_base_id(key)!=EVP_PKEY_RSA||EVP_PKEY_bits(key)<2048||EVP_PKEY_bits(key)>4096){reject(SimpleWeb::StatusCode::client_error_bad_request,"Use an RSA client certificate with a 2048-to-4096-bit key.");return;}
      const auto canonical=crypto::pem(certificate);
      std::lock_guard<std::recursive_mutex> lock(client_auth_mutex);
      bool exists=false;for(const auto& stored:client_root.named_devices){auto parsed=crypto::x509(stored.cert);if(parsed&&X509_cmp(parsed.get(),certificate.get())==0){exists=true;break;}}
      if(!exists){
        // Registrations are ephemeral across host boots. Keep a fixed bound,
        // retaining the one active controller's exact identity during eviction.
        if(client_root.named_devices.size()>=64){
          auto candidate=std::find_if(client_root.named_devices.begin(),client_root.named_devices.end(),[](const auto& stored){auto parsed=crypto::x509(stored.cert);unsigned char digest[32]{};unsigned count=0;if(!parsed||!X509_digest(parsed.get(),EVP_sha256(),digest,&count)||count!=32)return true;constexpr char hex[]="0123456789abcdef";std::string identity(64,'0');for(size_t n=0;n<32;++n){identity[n*2]=hex[digest[n]>>4];identity[n*2+1]=hex[digest[n]&15];}return !rdc::owns_session(identity);});
          if(candidate==client_root.named_devices.end()){reject(SimpleWeb::StatusCode::server_error_service_unavailable,"The temporary pairing registry is full.");return;}
          client_root.named_devices.erase(candidate);
        }
        named_cert_t client;client.name="Remote viewer "+id;client.uuid=id;client.cert=canonical;client_root.named_devices.push_back(std::move(client));
        cert_chain.clear();for(const auto& stored:client_root.named_devices){auto parsed=crypto::x509(stored.cert);if(parsed)cert_chain.add(std::move(parsed));}
        if(!config::sunshine.flags[config::flag::FRESH_STATE])save_state();
      }
      send(SimpleWeb::StatusCode::success_ok,"{\"ok\":true}");
    }catch(const std::exception&){reject(SimpleWeb::StatusCode::client_error_bad_request,"The pairing request contains invalid or unsupported JSON/certificate data.");}
  }
