#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

class AES {
public:
    //Kiểu dữ liệu, độ dài khóa và số vòng.
    using Byte = std::uint8_t; // Môtj byte không dấu: 0..255.
    using Bytes = std::vector<Byte>; // Dãy byte có độ dài thay đổi.
    static constexpr std::size_t BLOCK_SIZE = 16; // Khối AES luôn dài 128 bit.

    // Khởi tạo AES từ khóa gồm 16, 24 hoặc 32 byte.
    explicit AES(const Bytes& key, int key_length = 0) {
        if (key.size() != 16 && key.size() != 24 && key.size() != 32)
            throw std::invalid_argument("AES key must contain 16, 24, or 32 bytes.");
        if (key_length == 0) key_length = static_cast<int>(key.size() * 8);
        if (key_length != 128 && key_length != 192 && key_length != 256)
            throw std::invalid_argument("AES key length must be 128, 192, or 256 bits.");
        if (key.size() != static_cast<std::size_t>(key_length / 8))
            throw std::invalid_argument("Key bytes do not match the specified key length.");
        nk_ = key_length / 32; // Số word khóa gốc: 4, 6 hoặc 8.
        nr_ = nk_ + 6; // Số vòng AES: 10, 12 hoặc 14.
        key_expansion(key); // Sinh toàn bộ khóa vòng một lần.
    }

    // [10] Mã hóa: XOR ban đầu, các vòng đầy đủ, vòng cuối.
    // Mã hóa đúng một khối 16 byte và trả về 16 byte bản mã.
    Bytes encrypt(const Bytes& data) const {
        State state = bytes_to_state(data); // Xếp bản rõ thành ma trận 4x4.
        add_round_key(state, 0); // XOR với khóa gốc.
        for (int round = 1; round < nr_; ++round) {
            sub_bytes(state); // Thay byte qua S-box (phi tuyến).
            shift_rows(state); // Dịch vòng các hàng sang trái.
            mix_columns(state); // Trộn bốn byte trong từng cột.
            add_round_key(state, round); // XOR khóa của vòng hiện tại.
        }
        // Vòng cuối bỏ bước MixColumns.
        sub_bytes(state);
        shift_rows(state);
        add_round_key(state, nr_); // XOR khóa vòng cuối.
        return state_to_bytes(state); // Đọc state theo cột về dãy 16 byte.
    }

    // [11] Giải mã với khóa vòng theo thứ tự ngược.
    // Giải mã đúng một khối 16 byte và trả về 16 byte bản rõ.
    Bytes decrypt(const Bytes& ciphertext) const {
        State state = bytes_to_state(ciphertext); // Xếp bản mã thành state.
        add_round_key(state, nr_); // Bắt đầu từ khóa vòng cuối.
        for (int round = nr_ - 1; round > 0; --round) {
            inv_shift_rows(state); // Dịch vòng các hàng sang phải.
            inv_sub_bytes(state); // Tra S-box ngược để khôi phục byte.
            add_round_key(state, round); // XOR khóa của vòng hiện tại.
            inv_mix_columns(state); // Đảo phép trộn cột.
        }
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, 0); // XOR với khóa gốc.
        return state_to_bytes(state); // Đọc state theo cột về dãy 16 byte.
    }

private:
    using Word = std::array<Byte, 4>; // Một word gồm 4 byte.
    using State = std::array<Word, 4>; // Ma trận 4x4: state[hàng][cột].
    int nk_ = 0;
    int nr_ = 0;
    std::vector<Word> round_keys_; // Mỗi word là một cột của khóa vòng.

    // [2] Bảng S-box: 4 bit cao chọn hàng, 4 bit thấp chọn cột.
    // Ví dụ: S_BOX[0x53] = hàng 5, cột 3 = 0xed.
    inline static constexpr std::array<Byte, 256> S_BOX = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };
    // Bảng đảo: INV_S_BOX[S_BOX[x]] = x.
    inline static constexpr std::array<Byte, 256> INV_S_BOX = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };
    // Byte đầu của hằng số vòng dùng trong mở rộng khóa.
    inline static constexpr std::array<Byte, 10> RCON = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

    // Chuyển đổi giữa dãy byte và ma trận state theo cột.
    // Đổi dãy 16 byte thành ma trận state[4][4], điền theo từng cột.
    static State bytes_to_state(const Bytes& block) {
        if (block.size() != BLOCK_SIZE)
            throw std::invalid_argument("AES block must contain exactly 16 bytes.");
        State state{}; // Khởi tạo toàn bộ phần tử bằng 0.
        for (int row = 0; row < 4; ++row)
            for (int col = 0; col < 4; ++col)
                state[row][col] = block[4 * col + row]; // Mỗi cột lấy 4 byte liên tiếp.
        return state;
    }

    // Đọc ma trận state theo từng cột để trả về dãy 16 byte.
    static Bytes state_to_bytes(const State& state) {
        Bytes block(BLOCK_SIZE);
        for (int col = 0; col < 4; ++col)
            for (int row = 0; row < 4; ++row)
                block[4 * col + row] = state[row][col];
        return block;
    }

    // SubBytes và phép thay thế ngược.
    // Thay mỗi byte của state bằng S_BOX[byte], cập nhật trực tiếp state.
    static void sub_bytes(State& state) {
        for (auto& row : state)
            for (auto& byte : row) byte = S_BOX[byte]; // & giúp sửa trực tiếp byte trong state.
    }
    // Dùng INV_S_BOX để đảo ngược SubBytes khi giải mã.
    static void inv_sub_bytes(State& state) {
        for (auto& row : state)
            for (auto& byte : row) byte = INV_S_BOX[byte];
    }
    // ShiftRows: hàng r dịch vòng r vị trí.
    // Dịch vòng hàng r sang trái r byte; hàng 0 giữ nguyên.
    static void shift_rows(State& state) {
        const State old = state; // Giữ bản gốc để tránh ghi đè dữ liệu cần đọc.
        for (int row = 1; row < 4; ++row)
            for (int col = 0; col < 4; ++col)
                state[row][col] = old[row][(col + row) % 4];
    }
    // Dịch vòng hàng r sang phải r byte, đảo ngược ShiftRows.
    static void inv_shift_rows(State& state) {
        const State old = state; // Giữ bản gốc để tránh ghi đè dữ liệu cần đọc.
        for (int row = 1; row < 4; ++row)
            for (int col = 0; col < 4; ++col)
                state[row][col] = old[row][(col - row + 4) % 4];
    }

    // Nhân GF(2^8), rút gọn theo đa thức 0x11b.
    // Trả về tích của hai byte trong trường hữu hạn GF(2^8).
    static Byte gmul(Byte a, Byte b) {
        Byte product = 0;
        for (int i = 0; i < 8; ++i) {
            if ((b & 1) != 0) product ^= a; // Bit hiện tại bằng 1 thì cộng bằng XOR.
            const bool high_bit = (a & 0x80) != 0; // Lưu bit cao trước khi dịch.
            a = static_cast<Byte>(a << 1); // Giữ 8 bit thấp sau khi dịch trái.
            // Bit x^8 đã bị loại bởi ép kiểu; XOR 0x1b là phần còn lại của 0x11b.
            if (high_bit) a ^= 0x1b;
            b = static_cast<Byte>(b >> 1); // Xét bit tiếp theo của b.
        }
        return product;
    }

    // Trộn cột và đảo trộn cột trong GF(2^8).
    // Nhân từng cột state với ma trận AES có hàng đầu [02,03,01,01].
    static void mix_columns(State& state) {
        for (int col = 0; col < 4; ++col) {
            // Lưu đủ bốn byte cũ trước khi tính cột mới.
            const Byte a = state[0][col], b = state[1][col];
            const Byte c = state[2][col], d = state[3][col];
            state[0][col] = gmul(0x02,a) ^ gmul(0x03,b) ^ c ^ d;
            state[1][col] = a ^ gmul(0x02,b) ^ gmul(0x03,c) ^ d;
            state[2][col] = a ^ b ^ gmul(0x02,c) ^ gmul(0x03,d);
            state[3][col] = gmul(0x03,a) ^ b ^ c ^ gmul(0x02,d);
        }
    }
    // Nhân từng cột với ma trận nghịch đảo có hàng đầu [0e,0b,0d,09].
    static void inv_mix_columns(State& state) {
        for (int col = 0; col < 4; ++col) {
            // Lưu đủ bốn byte cũ trước khi tính cột mới.
            const Byte a = state[0][col], b = state[1][col];
            const Byte c = state[2][col], d = state[3][col];
            state[0][col] = gmul(0x0e,a)^gmul(0x0b,b)^gmul(0x0d,c)^gmul(0x09,d);
            state[1][col] = gmul(0x09,a)^gmul(0x0e,b)^gmul(0x0b,c)^gmul(0x0d,d);
            state[2][col] = gmul(0x0d,a)^gmul(0x09,b)^gmul(0x0e,c)^gmul(0x0b,d);
            state[3][col] = gmul(0x0b,a)^gmul(0x0d,b)^gmul(0x09,c)^gmul(0x0e,d);
        }
    }

    // AddRoundKey: XOR state với bốn word của khóa vòng.
    // XOR state với khóa của vòng round (0..Nr).
    void add_round_key(State& state, int round) const {
        for (int col = 0; col < 4; ++col)
            for (int row = 0; row < 4; ++row)
                state[row][col] ^= round_keys_[4 * round + col][row];
    }

    //  Mở rộng khóa chung cho AES-128/192/256.
    // Trả về word dịch vòng trái một byte: [a,b,c,d] -> [b,c,d,a].
    static Word rot_word(const Word& word) {
        return {word[1], word[2], word[3], word[0]};
    }
    // Áp dụng S_BOX cho bốn byte của một word và trả về word mới.
    static Word sub_word(Word word) {
        for (auto& byte : word) byte = S_BOX[byte];
        return word;
    }
    // Mở rộng khóa ban đầu thành 4*(Nr+1) word, mỗi word gồm bốn byte.
    void key_expansion(const Bytes& key) {
        const int total_words = 4 * (nr_ + 1); // 44, 52 hoặc 60 word.
        round_keys_.resize(total_words);
        for (int i = 0; i < nk_; ++i)
            for (int j = 0; j < 4; ++j)
                round_keys_[i][j] = key[4 * i + j]; // Các word đầu lấy từ khóa gốc.
        for (int i = nk_; i < total_words; ++i) {
            Word temp = round_keys_[i - 1]; // Bắt đầu bằng word ngay trước.
            if (i % nk_ == 0) {
                temp = sub_word(rot_word(temp)); // Xoay một byte rồi tra S-box.
                // Rcon là word [rc,0,0,0], nên chỉ byte đầu cần XOR.
                temp[0] ^= RCON[i / nk_ - 1];
            } else if (nk_ == 8 && i % nk_ == 4) {
                temp = sub_word(temp); // Bước bổ sung riêng của AES-256.
            }
            for (int j = 0; j < 4; ++j)
                round_keys_[i][j] = round_keys_[i - nk_][j] ^ temp[j]; // w[i] = w[i-Nk] XOR temp.
        }
    }
};

//Đổi hex và chạy demo; không thuộc các vòng AES.
// Đổi chuỗi hex thành byte: "0011ff" -> {0x00,0x11,0xff}.
AES::Bytes from_hex(const std::string& hex) {
    if (hex.size() % 2 != 0)
        throw std::invalid_argument("Hex string must have an even number of characters.");
    // Hàm lambda: đổi một ký tự hex thành giá trị 0..15, báo lỗi nếu không hợp lệ.
    auto digit = [](char c) -> unsigned {
        if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<unsigned>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return static_cast<unsigned>(c - 'A' + 10);
        throw std::invalid_argument("Invalid hexadecimal character.");
    };
    AES::Bytes bytes;
    bytes.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2)
        bytes.push_back(static_cast<AES::Byte>((digit(hex[i]) << 4) | digit(hex[i+1])));
    return bytes;
}
// Đổi dãy byte thành chuỗi hex chữ thường, mỗi byte luôn có hai ký tự.
std::string to_hex(const AES::Bytes& bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string hex;
    for (AES::Byte byte : bytes) {
        hex += digits[byte >> 4]; // Ký tự hex của 4 bit cao.
        hex += digits[byte & 0x0f]; // Ký tự hex của 4 bit thấp.
    }
    return hex;
}

#ifndef AES_NO_MAIN 
int main(int argc, char* argv[]) {
    try {
        if (argc == 1) {
            const auto plaintext = from_hex("00112233445566778899aabbccddeeff");
            const std::array<std::string, 3> keys = {
                "000102030405060708090a0b0c0d0e0f",
                "000102030405060708090a0b0c0d0e0f1011121314151617",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            };
            const std::array<std::string, 3> expected = {
                "69c4e0d86a7b0430d8cdb78070b4c55a",
                "dda97ca4864cdfe06eaf70a0ec0d7191",
                "8ea2b7ca516745bfeafc49904b496089"
            };
            for (std::size_t i = 0; i < keys.size(); ++i) {
                const AES aes(from_hex(keys[i]));
                const auto encrypted = aes.encrypt(plaintext);
                if (to_hex(encrypted) != expected[i] ||
                    aes.decrypt(from_hex(expected[i])) != plaintext)
                    throw std::runtime_error("Known-answer test failed.");
                std::cout << "AES-" << keys[i].size() * 4 << " PASS: "
                          << to_hex(encrypted) << '\n';
            }
            return 0;
        }
        if (argc != 4)
            throw std::invalid_argument("Usage: AES.exe enc|dec KEY_HEX BLOCK_HEX");
        const std::string operation = argv[1];
        if (operation != "enc" && operation != "dec")
            throw std::invalid_argument("Operation must be enc or dec.");
        const AES aes(from_hex(argv[2]));
        const auto block = from_hex(argv[3]);
        std::cout << to_hex(operation == "enc" ? aes.encrypt(block) : aes.decrypt(block)) << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}
#endif
