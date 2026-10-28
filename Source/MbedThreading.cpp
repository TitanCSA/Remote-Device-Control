#include "GameStreamClient.h"
#include <mbedtls/threading.h>
#include <psa/crypto.h>
#include <mutex>
#include <stdexcept>

namespace RemoteControl::GameStreamFormat {
namespace {
void Init(mbedtls_threading_mutex_t* mutex){if(mutex){InitializeSRWLock(&mutex->lock);mutex->initialized=1;}}
void Free(mbedtls_threading_mutex_t* mutex){if(mutex)mutex->initialized=0;}
int Lock(mbedtls_threading_mutex_t* mutex){if(!mutex||!mutex->initialized)return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;AcquireSRWLockExclusive(&mutex->lock);return 0;}
int Unlock(mbedtls_threading_mutex_t* mutex){if(!mutex||!mutex->initialized)return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;ReleaseSRWLockExclusive(&mutex->lock);return 0;}
}
void InitializeCrypto(){
    static std::once_flag initialized;
    std::call_once(initialized,[]{
        mbedtls_threading_set_alt(Init,Free,Lock,Unlock);
        if(psa_crypto_init()!=PSA_SUCCESS)throw std::runtime_error("Initialize thread-safe GameStream crypto failed.");
    });
}
}
