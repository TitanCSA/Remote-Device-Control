#pragma once
// PSA key-slot and RNG state is shared by Moonlight's independent transport
// threads. Use Windows locks instead of the upstream single-thread default.
#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_ALT
