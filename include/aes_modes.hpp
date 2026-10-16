#pragma once
#include <cstdint>
#include <string>
#include <vector>
#if defined(_WIN32) && defined(AES_MODES_SHARED)
# if defined(AES_MODES_BUILD)
#  define AES_MODES_API __declspec(dllexport)
# else
#  define AES_MODES_API __declspec(dllimport)
# endif
#else
# define AES_MODES_API
#endif
namespace aes_modes {
using Bytes = std::vector<std::uint8_t>;
// IV is external (never prefixed). AEAD results are ciphertext || tag.
// parameter: CFB segment bits or CCM tag bytes; 0 selects 128 or 16.
// GMAC enc: data=message; dec: data=tag, aad=message; returns empty on success.
AES_MODES_API Bytes transform(const std::string& name, bool enc,
    const Bytes& key, const Bytes& data, const Bytes& iv = {},
    const Bytes& aad = {}, int parameter = 0);
AES_MODES_API Bytes from_hex(const std::string& hex);
AES_MODES_API std::string to_hex(const Bytes& bytes);
}
