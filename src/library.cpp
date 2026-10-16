#include "aes_modes.hpp"
#define MODES_NO_MAIN
#include "modes.cpp"
namespace aes_modes {
Bytes from_hex(const std::string& s) { return ::from_hex(s); }
std::string to_hex(const Bytes& b) { return ::to_hex(b); }
Bytes transform(const std::string& name, bool enc, const Bytes& key,
                const Bytes& data, const Bytes& v, const Bytes& aad, int parameter) {
    if (parameter == 0) parameter = name == "cfb" ? 128 : 16;
        AES::Bytes base = key;
        if (name == "xts" && key.size() == 64) base.resize(32);
        AESModes m(base);
        AES::Bytes out;
        if (name == "ecb") out = enc ? m.ecb_encrypt(data) : m.ecb_decrypt(data);
        else if (name == "ecb-raw") out = enc ? m.ecb_encrypt(data,false) : m.ecb_decrypt(data,false);
        else if (name == "cbc") out = enc ? m.cbc_encrypt(data,v,false) : m.cbc_decrypt(data,v,false);
        else if (name == "cbc-raw") out = enc ? m.cbc_encrypt(data,v,false,false) : m.cbc_decrypt(data,v,false,false);
        else if (name == "cfb") out = enc ? m.cfb_encrypt(data,v,parameter,false) : m.cfb_decrypt(data,v,false,parameter);
        else if (name == "ofb") out = enc ? m.ofb_encrypt(data,v,false) : m.ofb_decrypt(data,v,false);
        else if (name == "ctr") out = enc ? m.ctr_encrypt(data,v,false) : m.ctr_decrypt(data,v,false);
        else if (name == "gcm") out = enc ? m.gcm_encrypt(data,aad,v,false) : m.gcm_decrypt(data,aad,v,false);
        else if (name == "gmac") {
            if (enc) out = m.gmac(data,v,false);
            else { if (!m.gmac_verify(aad,data,v,false)) throw std::runtime_error("Authentication failed."); }
        }
        else if (name == "ccm") out = enc ? m.ccm_encrypt(data,aad,v,parameter,false) : m.ccm_decrypt(data,aad,v,false,13,parameter);
        else if (name == "gcm-siv") out = enc ? m.gcm_siv_encrypt(data,aad,v,false) : m.gcm_siv_decrypt(data,aad,v,false);
        else if (name == "xts") out = enc ? m.xts_encrypt(data,key,v) : m.xts_decrypt(data,key,v);
        else if (name == "kw" || name == "kwp") out = enc ? m.key_wrap(data,name=="kwp") : m.key_unwrap(data,name=="kwp");
        else throw std::invalid_argument("Unknown mode.");

return out;
}
}

