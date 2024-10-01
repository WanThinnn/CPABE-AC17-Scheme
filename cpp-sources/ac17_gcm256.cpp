#include "ac17_gcm256.h"
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
#include <iomanip>

#include <winsock2.h>
#include "rabe/rabe.h"
#include "cryptopp/hex.h"
#include "cryptopp/base64.h"
#include "cryptopp/files.h"
#include <cryptopp/sha3.h>
#include "ac17gcm.h"

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
char *toLowerCase(const char *str)
{
    size_t len = std::strlen(str);
    char *lowerStr = new char[len + 1];
    std::strcpy(lowerStr, str);

    // Convert to lowercase
    std::transform(lowerStr, lowerStr + len, lowerStr, [](unsigned char c)
                   { return std::tolower(c); });

    return lowerStr;
}
std::vector<uint8_t> convertToByteArray(const void *encryptedKey, size_t length)
{
    const uint8_t *bytePtr = static_cast<const uint8_t *>(encryptedKey);
    std::vector<uint8_t> byteArray(bytePtr, bytePtr + length);
    return byteArray;
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
bool SaveFile(const std::string &filename, const char *data, const std::string &format)
{
    if (data == nullptr)
    {
        std::cerr << "Error: Null data passed to SaveFile" << std::endl;
        return false;
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
        else if (format == "Original")
        {
            CryptoPP::FileSink file(filename.c_str(), true); // true: nghĩa là "binary mode"
            file.Put(reinterpret_cast<const CryptoPP::byte *>(data), data_len);
            file.MessageEnd(); // Đảm bảo file đã ghi đầy đủ dữ liệu
        }
        else
        {
            std::cerr << "Unsupported format. Please choose 'JsonText', 'Base64', 'HEX' or 'Original'\n";
            return false;
        }
    }
    catch (const CryptoPP::Exception &ex)
    {
        std::cerr << "Crypto++ exception: " << ex.what() << std::endl;
        return false;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Standard exception: " << ex.what() << std::endl;
        return false;
    }
    return true;
}

// loadfile function with different formats
bool LoadFile(const std::string &filename, std::string &data, const std::string &format)
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
        else if (format == "Original")
        {
            data = encodedData; // Với định dạng Original, sử dụng dữ liệu như đã đọc
        }
        else
        {
            std::cerr << "Unsupported format. Please choose 'Base64', 'HEX', 'JsonText', or 'Original'\n";
        }
    }
    catch (const CryptoPP::Exception &e)
    {
        std::cerr << "CryptoPP Exception: " << e.what() << std::endl;
        return false;
    }
    return true;
}


// Phương thức setup
int AC17::setup(const char *path)
{
    std::string strPath(path);
    std::string strFileFormat = "Base64";

    try
    {
        // Khởi tạo và lấy kết quả setup
        Ac17SetupResult setupResult = rabe_ac17_init();
        char *masterKeyJson = rabe_ac17_master_key_to_json(setupResult.master_key);
        char *publicKeyJson = rabe_ac17_public_key_to_json(setupResult.public_key);

        if (!masterKeyJson || !publicKeyJson)
        {
            throw std::runtime_error("Failed to convert master key or public key to JSON.");
        }

        // Lưu Master Key và Public Key theo định dạng
        if (strFileFormat == "JsonText" || strFileFormat == "HEX" || strFileFormat == "Base64")
        {
            SaveFile(strPath + "/master_key.key", masterKeyJson, strFileFormat);
            SaveFile(strPath + "/public_key.key", publicKeyJson, strFileFormat);
            std::cout << "Setup completed successfully." << std::endl;

            // Giải phóng bộ nhớ và trả về 0 để chỉ ra thành công
            free(masterKeyJson);
            free(publicKeyJson);
            rabe_ac17_free_master_key(setupResult.master_key);
            rabe_ac17_free_public_key(setupResult.public_key);
            return 1;
        }
        else
        {
            throw std::invalid_argument("Unsupported key format. Please choose 'JsonText', 'Base64', or 'HEX'.");
        }
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Setup failed: " << ex.what() << std::endl;
        return -1;
    }
}

// Phương thức generateSecretKey
int AC17::generateSecretKey(const char* publicKeyFile, const char* masterKeyFile, const char* attributes, const char* privateKeyFile) {
std::string strFileFormat = "Base64";
    std::string strPublicKeyFile(publicKeyFile);
    std::string strMasterKeyFile(masterKeyFile);
    std::string strAttributes(attributes);
    std::string strPrivateKeyFile(privateKeyFile);
    std::string masterKeyStr;
    try
    {
        if (strFileFormat == "JsonText" || strFileFormat == "HEX" || strFileFormat == "Base64")
        {
            std::string masterKeyData;
            LoadFile(masterKeyFile, masterKeyData, strFileFormat);
            masterKeyStr = masterKeyData;
        }
        else
        {
            throw std::invalid_argument("Unsupported key format. Please choose 'JsonText', 'Base64', or 'HEX'.");
        }

        const void *masterKey = rabe_ac17_master_key_from_json(masterKeyStr.c_str());
        if (!masterKey)
        {
            throw std::runtime_error("Failed to convert master key from JSON.");
        }

        attributes = toLowerCase(attributes);
        // std::cout << "Attributes: " << attributes << std::endl; // Debug
        std::vector<std::string> attrVec = splitAttributes(attributes);

        std::vector<const char *> attrList;

        for (const auto &attr : attrVec)
        {
            attrList.push_back(attr.c_str());
        }

        const void *secretKey = rabe_cp_ac17_generate_secret_key(masterKey, attrList.data(), attrList.size());
        if (!secretKey)
        {
            throw std::runtime_error("Failed to generate private key.");
        }

        char *secretKeyJson = rabe_cp_ac17_secret_key_to_json(secretKey);
        if (!secretKeyJson)
        {
            throw std::runtime_error("Failed to convert private key to JSON.");
        }

        if (strFileFormat == "JsonText" || strFileFormat == "HEX" || strFileFormat == "Base64")
        {
            SaveFile(privateKeyFile, secretKeyJson, strFileFormat);
            std::cout << "Private key generated successfully." << std::endl;
            return 1;
        }
        else
        {
            throw std::invalid_argument("Unsupported key format. Please choose 'JsonText', 'Base64', or 'HEX'.");
        }

        rabe_cp_ac17_free_secret_key(secretKey);
        free(secretKeyJson);
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Error generating private key: " << ex.what() << std::endl;
        return -1;
    }
}

// Phương thức encrypt
int AC17::encrypt(const char* publicKeyFile, const char* plaintextFile, const char* policy, const char* ciphertextFile) {
try
    {
        std::string strPublicKeyFile(publicKeyFile);
        std::string strPlaintextFile(plaintextFile);
        std::string strCiphertextFile(ciphertextFile);

        // Generate a large random key (12288 bits)
        AutoSeededRandomPool prng;
        CryptoPP::Integer randomKey(prng, 12288);

        // Encode random_key to string
        std::string randomKeyStr;
        randomKey.Encode(CryptoPP::StringSink(randomKeyStr).Ref(), randomKey.MinEncodedSize());

        // Encrypt random_key using CP-ABE
        std::string publicKeyData;
        LoadFile(strPublicKeyFile, publicKeyData, "Base64");
        const void *publicKey = rabe_ac17_public_key_from_json(publicKeyData.c_str());
        const char *jsonPolicy = ensureJsonString(policy);
        const void *encryptedKey = rabe_cp_ac17_encrypt(publicKey, jsonPolicy, randomKeyStr.c_str(), randomKeyStr.size());

        // Serialize encryptedKey to JSON
        std::string encryptedKeyB = rabe_cp_ac17_cipher_to_json(encryptedKey);

        // Create AES key by hashing the random key
        CryptoPP::SHA3_256 hash;
        std::string aesKey(hash.DigestSize(), 0);
        hash.Update(reinterpret_cast<const CryptoPP::byte *>(randomKeyStr.data()), randomKeyStr.size());
        hash.Final(reinterpret_cast<CryptoPP::byte *>(&aesKey[0]));

        // Read plaintext from file
        std::ifstream file(strPlaintextFile);
        if (!file)
        {
            throw std::runtime_error("Failed to open plaintext file.");
            return -1;
        }
        std::string plaintext((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

        // AES-GCM encryption
        CryptoPP::GCM<CryptoPP::AES>::Encryption aes_gcm;
        CryptoPP::SecByteBlock key(reinterpret_cast<const CryptoPP::byte *>(aesKey.data()), aesKey.size());
        CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
        prng.GenerateBlock(iv, sizeof(iv));
        aes_gcm.SetKeyWithIV(key, key.size(), iv);

        // Encrypt plaintext
        std::string ciphertext;
        CryptoPP::AuthenticatedEncryptionFilter ef(aes_gcm, new CryptoPP::StringSink(ciphertext));
        ef.ChannelPut(CryptoPP::DEFAULT_CHANNEL, reinterpret_cast<const CryptoPP::byte *>(plaintext.data()), plaintext.size());
        ef.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

        // Combine nonce (IV), encrypted key length, encrypted key, and ciphertext
        std::string combined;
        combined.append(reinterpret_cast<const char *>(iv), sizeof(iv));
        uint64_t lenEncryptedKey = encryptedKeyB.size();
        combined.append(reinterpret_cast<const char *>(&lenEncryptedKey), sizeof(lenEncryptedKey));
        combined.append(encryptedKeyB);
        combined.append(ciphertext);

        // Final output in HEX
        std::string finalOutput;
        CryptoPP::StringSource(combined, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(finalOutput)));

        // Save to file
        if (SaveFile(strCiphertextFile, finalOutput.c_str(), "Original"))
        {
            std::cout << "Encryption successful!" << std::endl;
            return 1;
        }
        else
        {
            throw std::runtime_error("Failed to save ciphertext to file.");
            return -1;
        };
    }
    catch (const CryptoPP::Exception &ex)
    {
        std::cerr << "Error exception: " << ex.what() << std::endl;
        return -1;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Standard exception: " << ex.what() << std::endl;
        return -1;
    }
}

// Phương thức decrypt
int AC17::decrypt(const char* publicKeyFile, const char* privateKeyFile, const char* ciphertextFile, const char* recovertextFile) {
try
    {
        // Load Base64-encoded ciphertext from file
        std::string strCiphertextFile(ciphertextFile);
        std::string encodedCiphertext;
        CryptoPP::FileSource fileSource(strCiphertextFile.c_str(), true, new CryptoPP::StringSink(encodedCiphertext));

        // Decode from Base64
        std::string decodedCiphertext;
        CryptoPP::StringSource(encodedCiphertext, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedCiphertext)));

        // Extract nonce (IV)
        if (decodedCiphertext.size() < CryptoPP::AES::BLOCKSIZE)
        {
            throw std::runtime_error("Invalid ciphertext: too small to contain IV.");
        }

        CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
        std::memcpy(iv, decodedCiphertext.data(), sizeof(iv));
        
        // Khởi tạo offset sau IV
        uint64_t offset = sizeof(iv);

        // Đảm bảo kích thước còn lại đủ để chứa kích thước khóa mã hóa
        if (decodedCiphertext.size() < offset + sizeof(uint64_t))
        {
            throw std::runtime_error("Invalid ciphertext: too small to contain encrypted key length.");
        }

        // Đọc chiều dài của khóa mã hóa
        uint64_t lenEncryptedKey; // Sử dụng uint64_t
        std::memcpy(&lenEncryptedKey, decodedCiphertext.data() + offset, sizeof(lenEncryptedKey));
        offset += sizeof(lenEncryptedKey); // Cập nhật offset

        // Kiểm tra kích thước còn lại có đủ cho khóa mã hóa và ciphertext không
        if (decodedCiphertext.size() < offset + lenEncryptedKey)
        {
            throw std::runtime_error("Invalid ciphertext: insufficient size for encrypted key.");
        }

        // Trích xuất khóa mã hóa
        std::string encryptedKeyB = decodedCiphertext.substr(offset, lenEncryptedKey);
        offset += lenEncryptedKey;

        // Trích xuất ciphertext còn lại
        std::string ciphertext = decodedCiphertext.substr(offset);

        // Load private key
        std::string secretKeyData;
        if (!LoadFile(privateKeyFile, secretKeyData, "Base64"))
        {
            throw std::runtime_error("Failed to load private key.");
        }
        const void *secretKey = rabe_cp_ac17_secret_key_from_json(secretKeyData.c_str());

        // Decrypt the random key using CP-ABE
        const void *encryptedKey = rabe_cp_ac17_cipher_from_json(encryptedKeyB.c_str());
        if (!encryptedKey)
        {
            std::cerr << "Failed to load cipher." << std::endl;
            rabe_cp_ac17_free_secret_key(secretKey);
            return -1;
        }

        // Decrypt the ciphertext
        CBoxedBuffer recoveredKey = rabe_cp_ac17_decrypt(encryptedKey, secretKey);
        if (!recoveredKey.buffer)
        {
            const char *error = rabe_get_thread_last_error();
            std::cerr << "CP-ABE Decryption failed: " << (error ? error : "Unknown error") << std::endl;
            rabe_cp_ac17_free_secret_key(secretKey);
            rabe_cp_ac17_free_cipher(encryptedKey);
            return -1;
        }

        // Convert recovered key to CryptoPP::Integer
        CryptoPP::Integer recoveredRandomKey(reinterpret_cast<const CryptoPP::byte *>(recoveredKey.buffer), recoveredKey.len);

        // Derive AES key from recovered random key
        CryptoPP::SHA3_256 hash;
        std::string aesKey(hash.DigestSize(), 0);
        std::string recoveredKeyStr;
        recoveredRandomKey.Encode(CryptoPP::StringSink(recoveredKeyStr).Ref(), recoveredRandomKey.MinEncodedSize());
        hash.Update(reinterpret_cast<const CryptoPP::byte *>(recoveredKeyStr.data()), recoveredKeyStr.size());
        hash.Final(reinterpret_cast<CryptoPP::byte *>(&aesKey[0]));

        // Decrypt using AES-GCM
        std::string recovered;
        CryptoPP::GCM<CryptoPP::AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(reinterpret_cast<const CryptoPP::byte *>(aesKey.data()), aesKey.size(), iv);

        CryptoPP::AuthenticatedDecryptionFilter df(decryptor, new CryptoPP::StringSink(recovered),
                                                   CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS);

        CryptoPP::StringSource ss2(ciphertext, true, new CryptoPP::Redirector(df));

        if (!df.GetLastResult())
        {
            throw std::runtime_error("Decryption failed: MAC not valid.");
        }

        // Save the decrypted message to file
        CryptoPP::FileSink fileSink(recovertextFile);
        fileSink.Put(reinterpret_cast<const CryptoPP::byte *>(recovered.data()), recovered.size());

        std::cout << "Decryption successful!" << std::endl;
        return 1;
    }
    catch (const CryptoPP::Exception &ex)
    {
        std::cerr << "Crypto++ exception: " << ex.what() << std::endl;
        return -1;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Standard exception: " << ex.what() << std::endl;
        return -1;
    }
}
