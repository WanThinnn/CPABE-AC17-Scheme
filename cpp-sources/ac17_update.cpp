#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include "rabe/rabe.h"
#include "cryptopp/hex.h"
#include "cryptopp/base64.h"
#include "cryptopp/files.h"
#include <cryptopp/sha3.h>

using namespace std;
using namespace CryptoPP;
// Các hàm hỗ trợ đọc/ghi file, và các hàm liên quan đến RABE ở đây...

// function to split a string into a vector of strings
std::vector<std::string> splitAttributes(const std::string &input)
{
    std::vector<std::string> result;
    std::stringstream ss(input);
    std::string item;

    while (std::getline(ss, item, ' '))
    {
        result.push_back(item);
    }

    return result;
}

// Function to convert a string to lowercase
char* toLowerCase(const char* str) {
    size_t len = std::strlen(str);
    char* lowerStr = new char[len + 1];
    std::strcpy(lowerStr, str);

    // Convert to lowercase
    std::transform(lowerStr, lowerStr + len, lowerStr, [](unsigned char c) { return std::tolower(c); });

    return lowerStr;
}

// ensureJsonString function
char *ensureJsonString(const char *input)
{
    std::string lowerInput = toLowerCase(input); // convert to lower case
    std::istringstream iss(lowerInput);
    std::string token;
    std::vector<std::string> tokens;
    std::string output;

    // split the input string into tokens
    while (iss >> token)
    {
        size_t start = 0;
        size_t end = 0;
        while (end < token.size())
        {
            if (token[end] == '(' || token[end] == ')')
            {
                if (start != end)
                {
                    tokens.push_back("\"" + token.substr(start, end - start) + "\"");
                }
                tokens.push_back(std::string(1, token[end]));
                start = end + 1;
            }
            end++;
        }
        if (start != end)
        {
            tokens.push_back("\"" + token.substr(start, end - start) + "\"");
        }
    }

    for (const auto &t : tokens)
    {
        output += t + " ";
    }

    if (!output.empty() && output.back() == ' ')
    {
        output.pop_back();
    }

    char *result = new char[output.length() + 1];
    std::strcpy(result, output.c_str());
    return result;
}

// savefile function with different formats
void SaveFile(const std::string &filename, const char *data, const std::string &format)
{
    if (data == nullptr)
    {
        std::cerr << "Error: Null data passed to SaveFile" << std::endl;
        return;
    }

    size_t data_len = strlen(data); // Đảm bảo đây là chuỗi kết thúc bằng NULL

    try
    {
        if (format == "JsonText")
        {
            // Lưu dữ liệu như văn bản
            CryptoPP::FileSink file(filename.c_str(), true); // true: nghĩa là "binary mode"
            file.Put(reinterpret_cast<const CryptoPP::byte *>(data), data_len);
            file.MessageEnd(); // Đảm bảo file đã ghi đầy đủ dữ liệu
        }
        else if (format == "Base64")
        {
            CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte *>(data), data_len, true,
                                      new CryptoPP::Base64Encoder(
                                          new CryptoPP::FileSink(filename.c_str()), false));
        }
        else if (format == "HEX")
        {
            CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte *>(data), data_len, true,
                                      new CryptoPP::HexEncoder(
                                          new CryptoPP::FileSink(filename.c_str()), false));
        }
        else
        {
            std::cerr << "Unsupported format. Please choose 'JsonText', 'Base64', or 'HEX'\n";
        }
    }
    catch (const CryptoPP::Exception &ex)
    {
        std::cerr << "Crypto++ exception: " << ex.what() << std::endl;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Standard exception: " << ex.what() << std::endl;
    }
}

// loadfile function with different formats
void LoadFile(const std::string &filename, std::string &data, const std::string &format)
{
    try
    {
        std::string encodedData;
        CryptoPP::FileSource fs(filename.c_str(), true, new CryptoPP::StringSink(encodedData));

        if (format == "Base64")
        {
            CryptoPP::StringSource ss(encodedData, true,
                                      new CryptoPP::Base64Decoder(
                                          new CryptoPP::StringSink(data)));
        }
        else if (format == "HEX")
        {
            CryptoPP::StringSource ss(encodedData, true,
                                      new CryptoPP::HexDecoder(
                                          new CryptoPP::StringSink(data)));
        }
        else if (format == "JsonText")
        {
            data = encodedData; // Với định dạng JsonText, sử dụng dữ liệu như đã đọc
        }
        else
        {
            std::cerr << "Unsupported format. Please choose 'JsonText', 'Base64', or 'HEX'\n";
        }
    }
    catch (const CryptoPP::Exception &e)
    {
        std::cerr << "CryptoPP Exception: " << e.what() << std::endl;
    }
}

std::string SHA256Hash(const std::string &input)
{
    CryptoPP::SHA256 hash;
    std::string output;

    CryptoPP::StringSource ss(input, true, new CryptoPP::HashFilter(hash, new CryptoPP::StringSink(output)));
    return output;
}

// Hàm để mã hóa plaintext và đóng gói tất cả vào một file ciphertext duy nhất
void AC17encrypt(const char *publicKeyFile, const char *plaintextFile, const char *policy, const char *ciphertextFile)
{
    try
    {
        std::string strPublicKeyFile(publicKeyFile);
        std::string strPlaintextFile(plaintextFile);
        std::string strCiphertextFile(ciphertextFile);

        // Tạo khóa ngẫu nhiên siêu dài
        int keyBitSize = 12288; // 12288-bit = 1536-byte
        AutoSeededRandomPool prng;
        CryptoPP::Integer randomKey(prng, keyBitSize);

        // Mã hóa số nguyên thành chuỗi nhị phân để dùng cho hàm băm
        std::string binaryKey;
        randomKey.Encode(StringSink(binaryKey).Ref(), randomKey.MinEncodedSize());

        // Băm binaryKey bằng SHA3-256
        std::string hashDigest;
        CryptoPP::SHA3_512 hash;
        hash.Update(reinterpret_cast<const CryptoPP::byte *>(binaryKey.data()), binaryKey.size());

        // Lấy kết quả băm
        hashDigest.resize(hash.DigestSize());
        hash.Final(reinterpret_cast<CryptoPP::byte *>(&hashDigest[0]));

        // Chia kết quả băm SHA3-256 thành key và IV (256-bit mỗi cái)
        std::string aesKey(hashDigest.begin(), hashDigest.begin() + 32); // 256-bit AES key
        std::string iv(hashDigest.begin() + 32, hashDigest.end());       // 256-bit IV

        // Chuyển key và IV sang Base64
        std::string keyBase64, ivBase64;
        StringSource(aesKey, true, new Base64Encoder(new StringSink(keyBase64), false));
        StringSource(iv, true, new Base64Encoder(new StringSink(ivBase64), false));

        // read public key from file based on format
        std::string publicKeyStr;
        std::string publicKeyData;
        LoadFile(strPublicKeyFile, publicKeyData, "Base64");
        publicKeyStr = publicKeyData;

        const void *publicKey = rabe_ac17_public_key_from_json(publicKeyStr.c_str());
        if (!publicKey)
        {
            std::cerr << "Failed to load public key." << std::endl;
        }

        // read plaintext from file
        std::ifstream file(strPlaintextFile);
        if (!file)
        {
            std::cerr << "Failed to open plaintext file." << std::endl;
        }
        std::string plaintext((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

        // Encrypt random_key using CP-ABE
        const char *jsonPolicy = ensureJsonString(policy);

        // encrypt the plaintext
        std::string randomKeyStr;
        randomKeyStr.resize(randomKey.MinEncodedSize());
        randomKey.Encode(reinterpret_cast<CryptoPP::byte *>(&randomKeyStr[0]), randomKeyStr.size());

        const void *encryptedKey = rabe_cp_ac17_encrypt(publicKey, jsonPolicy, randomKeyStr.c_str(), randomKeyStr.size());
        if (!encryptedKey)
        {
            cerr << "Failed to encrypt the key." << endl;
            throw runtime_error("Encryption failed.");
        }

        // Serialize to JSON
        stringstream encryptedKeyStream;
        encryptedKeyStream << rabe_cp_ac17_cipher_to_json(encryptedKey);
        string encryptedKeyB = encryptedKeyStream.str();

        // Setup AES-GCM
        GCM<AES>::Encryption aesGcm;
        CryptoPP::SecByteBlock key(reinterpret_cast<const CryptoPP::byte*>(aesKey.data()), aesKey.size());
        CryptoPP::SecByteBlock ivBlock(reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());
        aesGcm.SetKeyWithIV(key, key.size(), ivBlock, ivBlock.size());

        // Encrypt the plaintext
        string ciphertext;
        AuthenticatedEncryptionFilter ef(aesGcm, new StringSink(ciphertext));
        ef.ChannelPut(DEFAULT_CHANNEL, reinterpret_cast<const CryptoPP::byte *>(plaintext.data()), plaintext.size());
        ef.ChannelMessageEnd(DEFAULT_CHANNEL);

        // Combine nonce, ciphertext, and authTag
        string combined;
        combined.append(reinterpret_cast<const char *>(iv.data()), iv.size());
        combined.append(ciphertext);

        // Encode Base64 for encrypted key and ciphertext
        stringstream finalOutputStream;
        uint64_t lenEncryptedKey = encryptedKeyB.size();
        finalOutputStream.write(reinterpret_cast<const char *>(&lenEncryptedKey), sizeof(lenEncryptedKey));
        finalOutputStream << encryptedKeyB;
        finalOutputStream << combined;

        // Encode to Base64
        string base64Output;
        stringstream base64Stream;
        StringSource(finalOutputStream.str(), true, new Base64Encoder(new StringSink(base64Output), false));

        // Save final output to file
        SaveFile(strCiphertextFile, base64Output.c_str(), "Base64");

        std::cout << base64Output;
    }
    catch (const CryptoPP::Exception &ex)
    {
        cerr << "Crypto++ exception: " << ex.what() << endl;
        throw;
    }
    catch (const std::exception &ex)
    {
        cerr << "Standard exception: " << ex.what() << endl;
        throw;
    }
}

int main()
{
    AC17encrypt("test_file/public_key.key", "test_file/plaintext.txt", "(A and B)", "test_file/ciphertext.txt");
    return 0;
}