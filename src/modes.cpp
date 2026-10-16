// C++17, chi dung thu vien chuan va AES.cpp tu cai dat.
// Bien dich: g++ -std=c++17 -Wall -Wextra -O2 modes.cpp -o modes.exe
#ifndef AES_NO_MAIN
#define AES_NO_MAIN
#endif
#include "AES.h"
#include <algorithm>
#include <functional>
#include <limits>
#include <utility>

class modes {
public:
    using Byte = AES::Byte;
    using Bytes = AES::Bytes;
    using RandomBytes = std::function<Bytes(std::size_t)>;
    static constexpr std::size_t BLOCK_SIZE = 16;
    Bytes iv; // IV/counter gan nhat, KHONG tu dong tai su dung.

    // Khởi tạo AES bằng khóa 16/24/32 byte; rng là nguồn byte do người gọi cấp.
    // C++ standard không bảo đảm CSPRNG, nên thiếu IV và rng sẽ báo lỗi.
    explicit modes(const Bytes& key, bool verbose = false, RandomBytes rng = {})
        : key_(key), aes_(key), verbose_(verbose), rng_(std::move(rng)) {}

    // Đổi string chứa UTF-8 thành byte; kiểm tra UTF-8 trước khi trả dữ liệu.
    static Bytes utf8_to_bytes(const std::string& text) {
        Bytes b(text.begin(), text.end());
        validate_utf8(b);
        return b;
    }
    // Đổi byte UTF-8 hợp lệ thành string, giữ cả byte NUL ở giữa chuỗi.
    static std::string bytes_to_utf8(const Bytes& b) {
        validate_utf8(b);
        return std::string(b.begin(), b.end());
    }
    // Chuỗi bắt đầu 0b được hiểu là bit; chuỗi khác được hiểu là UTF-8 như Python.
    static Bytes ensure_bytes(const std::string& text) {
        return text.rfind("0b", 0) == 0 ? binary_to_bytes(text) : utf8_to_bytes(text);
    }
    // Đổi bit thành byte, thêm bit 1 rồi các bit 0 để bảo toàn độ dài và số 0 đầu.
    static Bytes binary_to_bytes(std::string bits) {
        if (bits.rfind("0b", 0) == 0) bits.erase(0, 2);
        for (char c : bits) if (c != '0' && c != '1')
            throw std::invalid_argument("Binary string must contain only 0 and 1.");
        bits += '1';
        while (bits.size() % 8) bits += '0';
        Bytes out(bits.size() / 8);
        for (std::size_t i = 0; i < bits.size(); ++i)
            out[i / 8] = static_cast<Byte>((out[i / 8] << 1) | (bits[i] - '0'));
        return out;
    }
    // Đảo binary_to_bytes: bỏ marker 1 cuối và tối đa 7 bit 0, trả chuỗi 0b... .
    static std::string bytes_to_binary(const Bytes& data) {
        if (data.empty() || data.back() == 0)
            throw std::invalid_argument("Invalid reversible bit padding.");
        std::string bits;
        for (Byte b : data) for (int j = 7; j >= 0; --j)
            bits += ((b >> j) & 1) ? '1' : '0';
        bits.resize(bits.rfind('1'));
        return "0b" + bits;
    }
    // Thêm n byte cùng giá trị n (1..16); khối đã đủ vẫn thêm 16 byte 0x10.
    static Bytes pkcs7_padding(Bytes data) {
        const Byte n = static_cast<Byte>(16 - data.size() % 16);
        data.insert(data.end(), n, n);
        return data;
    }
    // Kiểm tra đủ khối và TOÀN BỘ byte padding, sau đó bỏ phần đệm.
    static Bytes pkcs7_unpadding(Bytes data) {
        require_blocks(data);
        const Byte n = data.back();
        if (n == 0 || n > 16) throw std::invalid_argument("Invalid PKCS#7 padding.");
        unsigned difference = 0;
        for (std::size_t i = data.size() - n; i < data.size(); ++i) difference |= data[i] ^ n;
        if (difference) throw std::invalid_argument("Invalid PKCS#7 padding.");
        data.resize(data.size() - n);
        return data;
    }

    // ECB: mã hóa từng khối độc lập C_i=E(P_i); pad=false yêu cầu đủ khối.
    Bytes ecb_encrypt(const Bytes& plain, bool pad = true) const {
        Bytes data = pad ? pkcs7_padding(plain) : plain;
        require_blocks(data);
        Bytes out;
        for (std::size_t i = 0; i < data.size(); i += 16) append(out, aes_.encrypt(part(data, i, 16)));
        return out;
    }
    // ECB: P_i=D(C_i); trả byte, tùy chọn kiểm tra và bỏ PKCS#7.
    Bytes ecb_decrypt(const Bytes& data, bool unpad = true) const {
        require_blocks(data);
        Bytes out;
        for (std::size_t i = 0; i < data.size(); i += 16) append(out, aes_.decrypt(part(data, i, 16)));
        return unpad ? pkcs7_unpadding(out) : out;
    }
    // CBC: C_i=E(P_i XOR C_{i-1}), C_0=IV; có thể ghép IV vào đầu bản mã.
    Bytes cbc_encrypt(const Bytes& plain, const Bytes& initial = {}, bool prepend_iv = true, bool pad = true) {
        Bytes previous = fresh(initial, 16, true);
        Bytes out = prepend_iv ? previous : Bytes{};
        Bytes data = pad ? pkcs7_padding(plain) : plain;
        require_blocks(data);
        for (std::size_t i = 0; i < data.size(); i += 16) {
            previous = aes_.encrypt(xor_bytes(part(data, i, 16), previous));
            append(out, previous);
        }
        return out;
    }
    // CBC: P_i=D(C_i) XOR C_{i-1}; lấy IV đầu bản mã hoặc từ tham số initial.
    Bytes cbc_decrypt(const Bytes& input, const Bytes& initial = {}, bool has_iv = true, bool unpad = true) const {
        auto packet = split_prefix(input, initial, has_iv, 16);
        Bytes previous = packet.first, out;
        const Bytes& data = packet.second;
        require_blocks(data);
        for (std::size_t i = 0; i < data.size(); i += 16) {
            Bytes block = part(data, i, 16);
            append(out, xor_bytes(aes_.decrypt(block), previous));
            previous = block;
        }
        return unpad ? pkcs7_unpadding(out) : out;
    }
    // CFB: dùng E(register) làm dòng khóa, phản hồi BẢN MÃ; segment_size tính bằng bit.
    Bytes cfb_encrypt(const Bytes& plain, const Bytes& initial = {}, int segment_size = 128, bool prepend_iv = true) {
        check_segment(segment_size);
        Bytes v = fresh(initial, 16, true);
        return package(v, cfb_core(plain, v, segment_size, false), prepend_iv);
    }
    // CFB giải mã vẫn dùng AES.encrypt; phản hồi đoạn bản mã đầu vào, không phản hồi bản rõ.
    Bytes cfb_decrypt(const Bytes& input, const Bytes& initial = {}, bool has_iv = true, int segment_size = 128) const {
        check_segment(segment_size);
        auto p = split_prefix(input, initial, has_iv, 16);
        return cfb_core(p.second, p.first, segment_size, true);
    }
    // OFB: feedback=E(feedback), XOR dòng khóa với dữ liệu; không cần padding.
    Bytes ofb_encrypt(const Bytes& plain, const Bytes& initial = {}, bool prepend_iv = true) {
        Bytes v = fresh(initial, 16, true);
        return package(v, ofb_core(plain, v), prepend_iv);
    }
    // OFB mã hóa và giải mã cùng phép XOR với cùng dòng khóa.
    Bytes ofb_decrypt(const Bytes& input, const Bytes& initial = {}, bool has_iv = true) const {
        auto p = split_prefix(input, initial, has_iv, 16);
        return ofb_core(p.second, p.first);
    }
    // CTR: XOR E(counter) với dữ liệu, tăng toàn bộ counter 128-bit big-endian sau mỗi khối.
    Bytes ctr_encrypt(const Bytes& plain, const Bytes& initial = {}, bool prepend_iv = true) {
        Bytes v = fresh(initial, 16, true);
        return package(v, ctr_core(aes_, plain, v, 0), prepend_iv);
    }
    // CTR giải mã dùng cùng phép biến đổi; counter ban đầu phải khớp bên mã hóa.
    Bytes ctr_decrypt(const Bytes& input, const Bytes& initial = {}, bool has_iv = true) const {
        auto p = split_prefix(input, initial, has_iv, 16);
        return ctr_core(aes_, p.second, p.first, 0);
    }

    // GCM: CTR mã hóa, GHASH xác thực AAD và bản mã; trả [nonce ||] ciphertext || tag16.
    Bytes gcm_encrypt(const Bytes& plain, const Bytes& aad = {}, const Bytes& nonce = {}, bool prepend_nonce = true) {
        gcm_limits(plain.size(), aad.size());
        Bytes n = fresh(nonce, 12, false), j0 = n;
        append(j0, Bytes{0,0,0,1});
        Bytes counter = j0;
        increment(counter, 12, 16, false);
        Bytes body = ctr_core(aes_, plain, counter, 1);
        append(body, gcm_tag(j0, aad, body));
        return package(n, body, prepend_nonce);
    }
    // GCM: kiểm tra tag trước khi trả bản rõ; sai AAD/nonce/tag/bản mã sẽ ném lỗi.
    Bytes gcm_decrypt(const Bytes& input, const Bytes& aad = {}, const Bytes& nonce = {}, bool has_nonce = true) const {
        auto p = split_prefix(input, nonce, has_nonce, 12);
        auto ct = split_tag(p.second, 16);
        gcm_limits(ct.first.size(), aad.size());
        Bytes j0 = p.first;
        append(j0, Bytes{0,0,0,1});
        authenticate(gcm_tag(j0, aad, ct.first), ct.second);
        increment(j0, 12, 16, false);
        return ctr_core(aes_, ct.first, j0, 1);
    }
    // GMAC là GCM với bản rõ rỗng: chỉ tạo tag xác thực authenticated_data.
    Bytes gmac(const Bytes& authenticated_data, const Bytes& nonce = {}, bool prepend_nonce = true) {
        return gcm_encrypt({}, authenticated_data, nonce, prepend_nonce);
    }
    // Kiểm tra token GMAC đúng kích thước; trả false khi xác thực thất bại.
    bool gmac_verify(const Bytes& data, const Bytes& token, const Bytes& nonce = {}, bool has_nonce = true) const {
        require_size(token, has_nonce ? 28 : 16, "GMAC token");
        try { return gcm_decrypt(token, data, nonce, has_nonce).empty(); }
        catch (const std::exception&) { return false; }
    }
    // CCM: CBC-MAC xác thực bản rõ/AAD, CTR mã hóa bản rõ và che tag; nonce 7..13 byte.
    Bytes ccm_encrypt(const Bytes& plain, const Bytes& aad = {}, const Bytes& nonce = {}, int tag_length = 16, bool prepend_nonce = true) {
        Bytes n = nonce.empty() ? fresh({}, 13, false) : nonce;
        ccm_validate(n, tag_length, plain.size());
        Bytes tag = ccm_tag(plain, aad, n, tag_length);
        Bytes body = ccm_stream(plain, n);
        append(body, tag);
        return package(n, body, prepend_nonce);
    }
    // CCM: khôi phục vào bộ nhớ cục bộ, chỉ trả dữ liệu sau khi tag hợp lệ.
    Bytes ccm_decrypt(const Bytes& input, const Bytes& aad = {}, const Bytes& nonce = {}, bool has_nonce = true, int nonce_length = 13, int tag_length = 16) const {
        if (nonce_length < 7 || nonce_length > 13) throw std::invalid_argument("CCM nonce length must be 7..13.");
        auto p = split_prefix(input, nonce, has_nonce, has_nonce ? static_cast<std::size_t>(nonce_length) : nonce.size());
        ccm_validate(p.first, tag_length, 0);
        auto ct = split_tag(p.second, static_cast<std::size_t>(tag_length));
        ccm_validate(p.first, tag_length, ct.first.size());
        Bytes plain = ccm_stream(ct.first, p.first);
        authenticate(ccm_tag(plain, aad, p.first, tag_length), ct.second);
        return plain;
    }
    // GCM-SIV: sinh khóa theo nonce, POLYVAL trên bản rõ/AAD, tag làm counter cho CTR.
    Bytes gcm_siv_encrypt(const Bytes& plain, const Bytes& aad = {}, const Bytes& nonce = {}, bool prepend_nonce = true) {
        siv_limits(plain.size(), aad.size());
        Bytes n = fresh(nonce, 12, false);
        auto keys = siv_keys(n);
        AES cipher(keys.second);
        Bytes tag = siv_tag(cipher, keys.first, n, plain, aad), counter = tag;
        counter[15] |= 0x80;
        Bytes body = ctr_core(cipher, plain, counter, 2);
        append(body, tag);
        return package(n, body, prepend_nonce);
    }
    // GCM-SIV: giải mã tạm bằng tag rồi tính lại tag; không trả bản rõ chưa xác thực.
    Bytes gcm_siv_decrypt(const Bytes& input, const Bytes& aad = {}, const Bytes& nonce = {}, bool has_nonce = true) const {
        auto p = split_prefix(input, nonce, has_nonce, 12);
        auto ct = split_tag(p.second, 16);
        siv_limits(ct.first.size(), aad.size());
        auto keys = siv_keys(p.first);
        AES cipher(keys.second);
        Bytes counter = ct.second;
        counter[15] |= 0x80;
        Bytes plain = ctr_core(cipher, ct.first, counter, 2);
        authenticate(siv_tag(cipher, keys.first, p.first, plain, aad), ct.second);
        return plain;
    }
    // XTS: mã hóa data unit >=16 byte bằng hai khóa; hỗ trợ khối cuối lẻ qua ciphertext stealing.
    Bytes xts_encrypt(const Bytes& plain, const Bytes& xts_key = {}, const Bytes& tweak = {}, std::uint64_t data_unit_number = 0) const {
        return xts_core(plain, xts_key, tweak, data_unit_number, false);
    }
    // XTS: đảo XEX và ciphertext stealing; tweak phải khớp và XTS không có tag xác thực.
    Bytes xts_decrypt(const Bytes& data, const Bytes& xts_key = {}, const Bytes& tweak = {}, std::uint64_t data_unit_number = 0) const {
        return xts_core(data, xts_key, tweak, data_unit_number, true);
    }
    // KW/KWP: dùng khóa của đối tượng làm KEK; pad=true cho phép khóa đích dài bất kỳ >0.
    Bytes key_wrap(const Bytes& data, bool pad = false) const {
        if (!pad) {
            if (data.size() < 16 || data.size() % 8) throw std::invalid_argument("KW input must be >=16 bytes and multiple of 8.");
            return wrap_core(data, Bytes(8, 0xa6));
        }
        if (data.empty() || data.size() > 0xffffffffULL) throw std::invalid_argument("KWP input length must be 1..2^32-1.");
        Bytes a = {0xa6,0x59,0x59,0xa6};
        append(a, integer_bytes(data.size(), 4, false));
        Bytes padded = data;
        while (padded.size() % 8) padded.push_back(0);
        if (padded.size() == 8) return aes_.encrypt(package(a, padded, true));
        return wrap_core(padded, a);
    }
    // KW/KWP: đảo sáu lượt trộn và kiểm tra IV/AIV, độ dài và zero padding trước khi trả khóa.
    Bytes key_unwrap(const Bytes& wrapped, bool pad = false) const {
        if (wrapped.size() % 8 || wrapped.size() < (pad ? 16U : 24U))
            throw std::invalid_argument("Invalid wrapped key length.");
        std::pair<Bytes,Bytes> p;
        if (pad && wrapped.size() == 16) {
            Bytes b = aes_.decrypt(wrapped);
            p = {part(b, 0, 8), part(b, 8, 8)};
        } else p = unwrap_core(wrapped);
        if (!pad) { authenticate(p.first, Bytes(8, 0xa6)); return p.second; }
        authenticate(part(p.first, 0, 4), Bytes{0xa6,0x59,0x59,0xa6});
        std::uint64_t size = 0;
        for (std::size_t i = 4; i < 8; ++i) size = (size << 8) | p.first[i];
        if (size <= p.second.size() - 8 || size > p.second.size()) throw std::runtime_error("Authentication failed.");
        unsigned difference = 0;
        for (std::size_t i = static_cast<std::size_t>(size); i < p.second.size(); ++i) difference |= p.second[i];
        if (difference) throw std::runtime_error("Authentication failed.");
        p.second.resize(static_cast<std::size_t>(size));
        return p.second;
    }

private:
    Bytes key_;
    AES aes_;
    bool verbose_;
    RandomBytes rng_;

    // Nối thêm một vector byte vào cuối vector đích.
    static void append(Bytes& out, const Bytes& data) { out.insert(out.end(), data.begin(), data.end()); }
    // Lấy một đoạn trong vector, tự rút ngắn ở cuối và kiểm tra offset.
    static Bytes part(const Bytes& b, std::size_t offset, std::size_t count) {
        if (offset > b.size()) throw std::out_of_range("Invalid byte offset.");
        count = std::min(count, b.size() - offset);
        return Bytes(b.begin() + static_cast<std::ptrdiff_t>(offset), b.begin() + static_cast<std::ptrdiff_t>(offset + count));
    }
    // XOR hai dãy cùng độ dài; trả dãy mới để không sửa đầu vào.
    static Bytes xor_bytes(Bytes a, const Bytes& b) {
        require_size(b, a.size(), "XOR operand");
        for (std::size_t i = 0; i < a.size(); ++i) a[i] ^= b[i];
        return a;
    }
    // Kiểm tra độ dài chính xác của IV, nonce, tweak hoặc tag.
    static void require_size(const Bytes& b, std::size_t size, const char* name) {
        if (b.size() != size) throw std::invalid_argument(std::string(name) + " has invalid length.");
    }
    // ECB/CBC không padding yêu cầu ít nhất một khối và độ dài chia hết 16.
    static void require_blocks(const Bytes& b) {
        if (b.empty() || b.size() % 16) throw std::invalid_argument("Data must be a nonzero multiple of 16 bytes.");
    }
    // Nhận IV/nonce hoặc gọi nguồn byte được truyền vào; không tái dùng iv cũ.
    Bytes fresh(const Bytes& supplied, std::size_t size, bool save_iv) {
        Bytes value = supplied;
        if (value.empty()) {
            if (!rng_) throw std::invalid_argument("Supply IV/nonce or a RandomBytes callback; no standard CSPRNG is assumed.");
            value = rng_(size);
        }
        require_size(value, size, "IV/nonce");
        if (save_iv) iv = value;
        if (verbose_) std::cout << "IV/nonce: " << to_hex(value) << '\n';
        return value;
    }
    // Ghép prefix vào trước body nếu requested=true; nếu không chỉ trả body.
    static Bytes package(const Bytes& prefix, const Bytes& body, bool requested) {
        Bytes out = requested ? prefix : Bytes{};
        append(out, body);
        return out;
    }
    // Tách IV/nonce khỏi gói hoặc dùng giá trị bên ngoài; trả {prefix, body}.
    static std::pair<Bytes,Bytes> split_prefix(const Bytes& input, const Bytes& external, bool included, std::size_t size) {
        if (included) {
            if (input.size() < size) throw std::invalid_argument("Missing IV/nonce prefix.");
            return {part(input, 0, size), part(input, size, input.size() - size)};
        }
        if (external.empty()) throw std::invalid_argument("External IV/nonce is required.");
        require_size(external, size, "IV/nonce");
        return {external, input};
    }
    // Tách tag nằm ở cuối; từ chối gói ngắn hơn tag.
    static std::pair<Bytes,Bytes> split_tag(const Bytes& input, std::size_t size) {
        if (input.size() < size) throw std::invalid_argument("Missing authentication tag.");
        return {part(input, 0, input.size() - size), part(input, input.size() - size, size)};
    }
    // So sánh mọi byte tag bằng XOR/OR, không dừng ở byte khác đầu tiên.
    // Không tuyên bố toàn bộ chương trình là constant-time (AES dùng bảng tra).
    static void authenticate(const Bytes& expected, const Bytes& actual) {
        unsigned difference = expected.size() == actual.size() ? 0U : 1U;
        for (std::size_t i = 0; i < std::min(expected.size(), actual.size()); ++i) difference |= expected[i] ^ actual[i];
        if (difference) throw std::runtime_error("Authentication failed.");
    }
    // Kiểm tra CFB segment 8,16,...,128 bit; không hỗ trợ CFB1.
    static void check_segment(int bits) {
        if (bits < 8 || bits > 128 || bits % 8) throw std::invalid_argument("CFB segment must be 8..128 bits, byte-aligned.");
    }
    // Lõi CFB dùng chung: giải mã đưa ciphertext đầu vào vào thanh ghi phản hồi.
    Bytes cfb_core(const Bytes& data, Bytes reg, int bits, bool decrypt) const {
        const std::size_t step = static_cast<std::size_t>(bits / 8);
        Bytes out;
        for (std::size_t i = 0; i < data.size(); i += step) {
            Bytes segment = part(data, i, step);
            Bytes result = xor_bytes(segment, part(aes_.encrypt(reg), 0, segment.size()));
            append(out, result);
            if (segment.size() == step) {
                reg = part(reg, step, 16 - step);
                append(reg, decrypt ? segment : result);
            }
        }
        return out;
    }
    // Lõi OFB chỉ phản hồi đầu ra AES, không phản hồi bản rõ/bản mã.
    Bytes ofb_core(const Bytes& data, Bytes feedback) const {
        Bytes out;
        for (std::size_t i = 0; i < data.size(); i += 16) {
            feedback = aes_.encrypt(feedback);
            Bytes b = part(data, i, 16);
            append(out, xor_bytes(b, part(feedback, 0, b.size())));
        }
        return out;
    }
    // Tăng số nguyên trên khoảng [begin,end), truyền carry; tràn quay vòng trong khoảng đó.
    static void increment(Bytes& b, std::size_t begin, std::size_t end, bool little) {
        for (std::size_t j = 0; j < end - begin; ++j) {
            const std::size_t i = little ? begin + j : end - 1 - j;
            b[i] = static_cast<Byte>(b[i] + 1);
            if (b[i] != 0) break;
        }
    }
    // CTR dùng chung: kind=0 tăng 128-bit BE; 1 tăng 32-bit BE cuối; 2 tăng 32-bit LE đầu.
    static Bytes ctr_core(const AES& cipher, const Bytes& data, Bytes counter, int kind) {
        Bytes out;
        for (std::size_t i = 0; i < data.size(); i += 16) {
            Bytes b = part(data, i, 16);
            append(out, xor_bytes(b, part(cipher.encrypt(counter), 0, b.size())));
            if (kind == 2) increment(counter, 0, 4, true);
            else increment(counter, kind == 1 ? 12 : 0, 16, false);
        }
        return out;
    }
    // Mã hóa số nguyên 64-bit thành count byte theo endian yêu cầu, báo lỗi nếu không vừa.
    static Bytes integer_bytes(std::uint64_t value, std::size_t count, bool little) {
        Bytes out(count);
        for (std::size_t i = 0; i < count; ++i) {
            out[little ? i : count - 1 - i] = static_cast<Byte>(value & 0xff);
            value >>= 8;
        }
        if (value) throw std::invalid_argument("Integer does not fit field.");
        return out;
    }
    // Tính độ dài bit bằng uint64_t, kiểm tra tràn trước khi nhân 8.
    static std::uint64_t bit_length(std::size_t size) {
        if (size > std::numeric_limits<std::uint64_t>::max() / 8) throw std::length_error("Bit length overflow.");
        return static_cast<std::uint64_t>(size) * 8;
    }
    // Nhân x trong biểu diễn GHASH: dịch phải, XOR 0xe1 khi bit thấp bị đẩy ra.
    static Bytes ghash_x(Bytes v) {
        const bool low = (v[15] & 1) != 0;
        for (int j = 15; j > 0; --j) v[j] = static_cast<Byte>((v[j] >> 1) | ((v[j-1] & 1) << 7));
        v[0] >>= 1;
        if (low) v[0] ^= 0xe1;
        return v;
    }
    // Nhân GF(2^128) cho GHASH; khác GF(2^8) của MixColumns trong AES.
    static Bytes ghash_mul(const Bytes& x, Bytes v) {
        Bytes z(16);
        for (int bit = 0; bit < 128; ++bit) {
            if ((x[bit / 8] >> (7 - bit % 8)) & 1) z = xor_bytes(z, v);
            v = ghash_x(v);
        }
        return z;
    }
    // Cập nhật GHASH trên dữ liệu, đệm zero riêng cho phần cuối của dữ liệu đó.
    static void hash_update(Bytes& state, const Bytes& h, const Bytes& data, bool reverse = false) {
        for (std::size_t i = 0; i < data.size(); i += 16) {
            Bytes b = part(data, i, 16);
            b.resize(16, 0);
            if (reverse) std::reverse(b.begin(), b.end());
            state = ghash_mul(xor_bytes(state, b), h);
        }
    }
    // Giới hạn GCM: bản rõ tối đa 2^36-32 byte và AAD biểu diễn được độ dài bit 64-bit.
    static void gcm_limits(std::size_t text, std::size_t aad) {
        if (text > (1ULL << 36) - 32) throw std::length_error("GCM text too long.");
        (void)bit_length(aad);
    }
    // Tag GCM = E(J0) XOR GHASH(AAD || pad || ciphertext || pad || bit_lengths).
    Bytes gcm_tag(const Bytes& j0, const Bytes& aad, const Bytes& ciphertext) const {
        Bytes h = aes_.encrypt(Bytes(16)), state(16);
        hash_update(state, h, aad);
        hash_update(state, h, ciphertext);
        Bytes lengths = integer_bytes(bit_length(aad.size()), 8, false);
        append(lengths, integer_bytes(bit_length(ciphertext.size()), 8, false));
        hash_update(state, h, lengths);
        return xor_bytes(aes_.encrypt(j0), state);
    }
    // Kiểm tra tag CCM chẵn 4..16, nonce 7..13; độ dài dữ liệu phải vừa L=15-|nonce| byte.
    static void ccm_validate(const Bytes& nonce, int tag, std::size_t size) {
        if (nonce.size() < 7 || nonce.size() > 13 || tag < 4 || tag > 16 || tag % 2)
            throw std::invalid_argument("Invalid CCM nonce/tag length.");
        (void)integer_bytes(size, 15 - nonce.size(), false);
    }
    // Tạo counter CCM: flags(L-1) || nonce || số đếm L byte big-endian.
    static Bytes ccm_counter(const Bytes& nonce, std::uint64_t value) {
        Bytes b{static_cast<Byte>(14 - nonce.size())};
        append(b, nonce);
        append(b, integer_bytes(value, 15 - nonce.size(), false));
        return b;
    }
    // Sinh dòng CTR của CCM từ counter 1; counter 0 được dành để che tag.
    Bytes ccm_stream(const Bytes& data, const Bytes& nonce) const {
        Bytes out;
        std::uint64_t counter = 1;
        for (std::size_t i = 0; i < data.size(); i += 16, ++counter) {
            Bytes b = part(data, i, 16);
            append(out, xor_bytes(b, part(aes_.encrypt(ccm_counter(nonce, counter)), 0, b.size())));
        }
        return out;
    }
    // CBC-MAC trên B0, AAD có mã hóa độ dài, bản rõ; XOR tag với E(counter0).
    Bytes ccm_tag(const Bytes& plain, const Bytes& aad, const Bytes& nonce, int tag_length) const {
        Bytes b0{static_cast<Byte>((aad.empty() ? 0 : 0x40) | (((tag_length - 2) / 2) << 3) | (14 - nonce.size()))};
        append(b0, nonce);
        append(b0, integer_bytes(plain.size(), 15 - nonce.size(), false));
        Bytes mac = aes_.encrypt(b0);
        if (!aad.empty()) {
            Bytes encoded;
            if (aad.size() < 0xff00) encoded = integer_bytes(aad.size(), 2, false);
            else {
                encoded = {0xff, static_cast<Byte>(aad.size() <= 0xffffffffULL ? 0xfe : 0xff)};
                append(encoded, integer_bytes(aad.size(), aad.size() <= 0xffffffffULL ? 4 : 8, false));
            }
            append(encoded, aad);
            cbc_mac_update(mac, encoded);
        }
        cbc_mac_update(mac, plain);
        return xor_bytes(part(mac, 0, tag_length), part(aes_.encrypt(ccm_counter(nonce, 0)), 0, tag_length));
    }
    // CBC-MAC cập nhật state=E(state XOR block), zero-pad phần cuối của từng trường.
    void cbc_mac_update(Bytes& state, const Bytes& data) const {
        for (std::size_t i = 0; i < data.size(); i += 16) {
            Bytes b = part(data, i, 16);
            b.resize(16, 0);
            state = aes_.encrypt(xor_bytes(state, b));
        }
    }
    // RFC 8452 giới hạn mỗi phần bản rõ/AAD không quá 2^36 byte.
    static void siv_limits(std::size_t text, std::size_t aad) {
        if (text > (1ULL << 36) || aad > (1ULL << 36)) throw std::length_error("GCM-SIV input too long.");
    }
    // Sinh auth key và encryption key bằng nửa đầu E(counter32LE || nonce) theo RFC 8452.
    std::pair<Bytes,Bytes> siv_keys(const Bytes& nonce) const {
        if (key_.size() != 16 && key_.size() != 32) throw std::invalid_argument("GCM-SIV supports only AES-128/256.");
        Bytes auth, encryption;
        for (unsigned i = 0; i < (key_.size() == 16 ? 4U : 6U); ++i) {
            Bytes b = integer_bytes(i, 4, true);
            append(b, nonce);
            Bytes half = part(aes_.encrypt(b), 0, 8);
            append(i < 2 ? auth : encryption, half);
        }
        return {auth, encryption};
    }
    // POLYVAL qua quan hệ byte-reverse/GHASH trong RFC 8452, rồi AES tạo synthetic IV/tag.
    static Bytes siv_tag(const AES& cipher, Bytes h, const Bytes& nonce, const Bytes& plain, const Bytes& aad) {
        std::reverse(h.begin(), h.end());
        h = ghash_x(h);
        Bytes state(16);
        hash_update(state, h, aad, true);
        hash_update(state, h, plain, true);
        Bytes lengths = integer_bytes(bit_length(aad.size()), 8, true);
        append(lengths, integer_bytes(bit_length(plain.size()), 8, true));
        hash_update(state, h, lengths, true);
        std::reverse(state.begin(), state.end());
        for (std::size_t i = 0; i < 12; ++i) state[i] ^= nonce[i];
        state[15] &= 0x7f;
        return cipher.encrypt(state);
    }
    // Nhân tweak XTS với alpha trong GF(2^128), biểu diễn little-endian, đa thức đuôi 0x87.
    static void xts_next(Bytes& tweak) {
        unsigned carry = 0;
        for (Byte& b : tweak) {
            unsigned next = b >> 7;
            b = static_cast<Byte>((b << 1) | carry);
            carry = next;
        }
        if (carry) tweak[0] ^= 0x87;
    }
    // XEX trên một khối: XOR tweak, AES mã hóa/giải mã, rồi XOR tweak lần nữa.
    static Bytes xex(const AES& cipher, const Bytes& block, const Bytes& tweak, bool decrypt) {
        Bytes b = xor_bytes(block, tweak);
        return xor_bytes(decrypt ? cipher.decrypt(b) : cipher.encrypt(b), tweak);
    }
    // Lõi XTS: chia khóa K1/K2, sinh tweak E_K2, xử lý khối đầy và hoán đổi phần cuối lẻ.
    Bytes xts_core(const Bytes& data, const Bytes& supplied_key, const Bytes& supplied_tweak, std::uint64_t number, bool decrypt) const {
        const Bytes& key = supplied_key.empty() ? key_ : supplied_key;
        if (key.size() != 32 && key.size() != 64) throw std::invalid_argument("XTS key must have 32 or 64 bytes.");
        if (data.size() < 16 || data.size() > (1ULL << 24)) throw std::invalid_argument("XTS data unit must have 16..2^24 bytes.");
        Bytes k1 = part(key, 0, key.size() / 2), k2 = part(key, key.size() / 2, key.size() / 2);
        if (k1 == k2) throw std::invalid_argument("XTS key halves must be different.");
        AES cipher(k1), tweak_cipher(k2);
        Bytes tweak_input = supplied_tweak.empty() ? integer_bytes(number, 16, true) : supplied_tweak;
        require_size(tweak_input, 16, "XTS tweak");
        Bytes tweak = tweak_cipher.encrypt(tweak_input), out;
        const std::size_t full = data.size() / 16, tail = data.size() % 16;
        const std::size_t normal = tail ? full - 1 : full;
        for (std::size_t i = 0; i < normal; ++i) {
            append(out, xex(cipher, part(data, 16*i, 16), tweak, decrypt));
            xts_next(tweak);
        }
        if (tail) {
            Bytes next = tweak;
            xts_next(next);
            Bytes cc = xex(cipher, part(data, 16*normal, 16), decrypt ? next : tweak, decrypt);
            Bytes pp = part(data, 16*full, tail);
            append(pp, part(cc, tail, 16-tail));
            append(out, xex(cipher, pp, decrypt ? tweak : next, decrypt));
            append(out, part(cc, 0, tail));
        }
        return out;
    }
    // KW forward: sáu lượt, mỗi lượt mã hóa A||R_i và XOR bộ đếm t vào A.
    Bytes wrap_core(Bytes data, Bytes a) const {
        const std::size_t n = data.size() / 8;
        if (n > std::numeric_limits<std::uint64_t>::max() / 6) throw std::length_error("KW input too long.");
        for (unsigned j = 0; j < 6; ++j) for (std::size_t i = 0; i < n; ++i) {
            Bytes b = aes_.encrypt(package(a, part(data, i*8, 8), true));
            a = xor_bytes(part(b, 0, 8), integer_bytes(n*j + i + 1, 8, false));
            std::copy(b.begin()+8, b.end(), data.begin()+static_cast<std::ptrdiff_t>(i*8));
        }
        return package(a, data, true);
    }
    // KW inverse: đảo thứ tự i và j, XOR t trước AES.decrypt; trả {A, dữ liệu} để kiểm tra.
    std::pair<Bytes,Bytes> unwrap_core(const Bytes& wrapped) const {
        Bytes a = part(wrapped, 0, 8), data = part(wrapped, 8, wrapped.size()-8);
        const std::size_t n = data.size()/8;
        if (n > std::numeric_limits<std::uint64_t>::max() / 6) throw std::length_error("KW input too long.");
        for (int j = 5; j >= 0; --j) for (std::size_t i = n; i > 0; --i) {
            Bytes block = xor_bytes(a, integer_bytes(n*static_cast<unsigned>(j)+i, 8, false));
            append(block, part(data, (i-1)*8, 8));
            Bytes b = aes_.decrypt(block);
            a = part(b, 0, 8);
            std::copy(b.begin()+8, b.end(), data.begin()+static_cast<std::ptrdiff_t>((i-1)*8));
        }
        return {a, data};
    }
    // Kiểm tra UTF-8: byte tiếp diễn, overlong, surrogate và code point >U+10FFFF.
    static void validate_utf8(const Bytes& b) {
        for (std::size_t i = 0; i < b.size();) {
            unsigned c = b[i++], count = 0, minimum = 0;
            if (c < 0x80) continue;
            if (c >= 0xc2 && c <= 0xdf) { c &= 0x1f; count=1; minimum=0x80; }
            else if (c >= 0xe0 && c <= 0xef) { c &= 0x0f; count=2; minimum=0x800; }
            else if (c >= 0xf0 && c <= 0xf4) { c &= 7; count=3; minimum=0x10000; }
            else throw std::invalid_argument("Invalid UTF-8.");
            if (count > b.size()-i) throw std::invalid_argument("Truncated UTF-8.");
            while (count--) {
                unsigned next = b[i++];
                if ((next & 0xc0) != 0x80) throw std::invalid_argument("Invalid UTF-8 continuation.");
                c = (c << 6) | (next & 0x3f);
            }
            if (c < minimum || c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff)) throw std::invalid_argument("Invalid UTF-8 code point.");
        }
    }
};
using AESModes = modes;

#ifndef MODES_NO_MAIN
// Demo/CLI nhập hex để giữ nguyên dữ liệu nhị phân, không phụ thuộc encoding terminal.
// Usage: modes.exe MODE enc|dec KEY_HEX DATA_HEX [IV_OR_NONCE_HEX] [AAD_HEX] [PARAM]
// CLI dùng IV/nonce ngoài, không ghép prefix. PARAM: CFB bits hoặc CCM tag bytes.
int main(int argc, char* argv[]) {
    try {
        if (argc == 1) {
            AESModes m(from_hex("000102030405060708090a0b0c0d0e0f"));
            auto plain = AESModes::utf8_to_bytes("Hello AES modes!");
            // IV cố định chỉ để demo có kết quả lặp lại, không dùng làm mặc định thực tế.
            auto iv = from_hex("000102030405060708090a0b0c0d0e0f");
            auto encrypted = m.cbc_encrypt(plain, iv);
            std::cout << "CBC packet (IV || ciphertext): " << to_hex(encrypted) << '\n';
            std::cout << "Restored: " << AESModes::bytes_to_utf8(m.cbc_decrypt(encrypted)) << '\n';
            return 0;
        }
        if (argc < 5 || argc > 8) throw std::invalid_argument("Usage: modes.exe MODE enc|dec KEY_HEX DATA_HEX [IV_NONCE_HEX] [AAD_HEX] [PARAM]");
        const std::string name = argv[1], operation = argv[2];
        if (operation != "enc" && operation != "dec") throw std::invalid_argument("Operation must be enc or dec.");
        const bool enc = operation == "enc";
        const auto key = from_hex(argv[3]), data = from_hex(argv[4]);
        const auto v = argc > 5 ? from_hex(argv[5]) : AES::Bytes{};
        const auto aad = argc > 6 ? from_hex(argv[6]) : AES::Bytes{};
        int parameter = name == "cfb" ? 128 : 16;
        if (argc > 7) {
            std::size_t used = 0;
            const std::string value = argv[7];
            parameter = std::stoi(value, &used);
            if (used != value.size()) throw std::invalid_argument("Invalid numeric parameter.");
        }
        // XTS dùng khóa kép 32/64 byte; constructor AES nhận nửa đầu để khởi tạo đối tượng.
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
        std::cout << to_hex(out) << '\n';
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }
}
#endif
