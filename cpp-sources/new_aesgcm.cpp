#include <assert.h>
#include <iostream>
#include <stdio.h>
#include <sstream>
#include <stdexcept>
#include <chrono>
#include <string>
#include <exception>
#include <windows.h>
#include "aes_gcm.h"

using namespace std;
using namespace CryptoPP;
using std::cerr;
using std::cin;
using std::cout;
using std::endl;
using std::exception;
using std::runtime_error;
using std::string;

// Crypto++ Libraries
#include "cryptopp/base64.h"
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "cryptopp/cryptlib.h"
using CryptoPP::AuthenticatedSymmetricCipher;
using CryptoPP::BufferedTransformation;
using CryptoPP::DecodingResult;
using CryptoPP::Exception;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/filters.h"
using CryptoPP::ArraySink;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::HashVerificationFilter;
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::Redirector;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/queue.h"
using CryptoPP::ByteQueue;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

// AES Libary
#include "cryptopp/aes.h"
using CryptoPP::AES;

// Confidentiality and Authentication modes
#include "cryptopp/gcm.h"
using CryptoPP::GCM;

#include <cryptopp/integer.h>
#include <cryptopp/sha3.h>


// savefile function with different formats

void SaveFile(const std::string &filename, const CryptoPP::SecByteBlock &data, const std::string &format)
{
    if (data.size() == 0)
    {
        std::cerr << "Error: Empty data passed to SaveFile" << std::endl;
        return;
    }

    size_t data_len = data.size();

    try
    {
        if (format == "DER")
        {
            CryptoPP::FileSink file(filename.c_str(), true);
            file.Put(data, data_len);
            file.MessageEnd();
        }
        else if (format == "Base64")
        {
            CryptoPP::StringSource ss(data, data_len, true,
                                      new CryptoPP::Base64Encoder(
                                          new CryptoPP::FileSink(filename.c_str()), false));
        }
        else if (format == "HEX")
        {
            CryptoPP::StringSource ss(data, data_len, true,
                                      new CryptoPP::HexEncoder(
                                          new CryptoPP::FileSink(filename.c_str()), false));
        }
        else
        {
            std::cerr << "Unsupported format. Please choose 'DER', 'Base64', or 'HEX'\n";
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
// Định nghĩa LoadFile cho SecByteBlock
void LoadFile(const string& filename, SecByteBlock& data, const string& format)
{
    // Đọc toàn bộ dữ liệu từ file vào string
    string fileData;
    ifstream file(filename, ios::binary);
    if (!file)
    {
        cerr << "Failed to open file: " << filename << endl;
        throw runtime_error("Failed to open file.");
    }
    file.seekg(0, ios::end);
    fileData.resize(file.tellg());
    file.seekg(0, ios::beg);
    file.read(&fileData[0], fileData.size());
    file.close();

    // Chuyển đổi dữ liệu dựa trên định dạng
    if (format == "Base64")
    {
        StringSource ss(fileData, true);
        StringSink sink(fileData);
        Base64Decoder decoder(&sink);
        ss.CopyTo(decoder);
        decoder.MessageEnd();
        data.Assign((const byte*)fileData.data(), fileData.size());
    }
    else if (format == "HEX")
    {
        StringSource ss(fileData, true);
        StringSink sink(fileData);
        HexDecoder decoder(&sink);
        ss.CopyTo(decoder);
        decoder.MessageEnd();
        data.Assign((const byte*)fileData.data(), fileData.size());
    }
    else
    {
        cerr << "Unsupported format: " << format << endl;
        throw runtime_error("Unsupported format.");
    }
}


size_t GetKeySizeFromFile(const std::string &filename, const std::string &format)
{
    size_t keySize = 0;

    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open())
    {
        std::cerr << "Failed to open file: " << filename << std::endl;
        exit(1);
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();

    // Xác định độ dài của key dựa trên định dạng
    if (format == "Base64")
    {
        std::string key;
        StringSource(buffer.str(), true, new Base64Decoder(new StringSink(key)));
        keySize = key.size() * 8; // Đổi từ byte sang bit
    }
    else if (format == "HEX")
    {
        keySize = buffer.str().size() * 4; // Mỗi ký tự HEX biểu diễn 4 bit
    }
    else if (format == "DER")
    {
        keySize = buffer.str().size() * 8; // Đổi từ byte sang bit
    }
    else
    {
        cerr << "Unsupported format: " << format << std::endl;
        exit(1);
    }

    return keySize;
}



// Hàm tạo randomKey với số bit lớn (ví dụ: 24576-bit)
CryptoPP::Integer generateRandomKey(const int keyBitSize)
{
    AutoSeededRandomPool prng;
    CryptoPP::Integer randomKey(prng, keyBitSize); // Tạo ra một số ngẫu nhiên với keyBitSize bit
    return randomKey; // Trả về randomKey
}

// Hàm hỗ trợ tách key và IV từ file chung
void LoadKeyAndIV(const string& fileName, SecByteBlock& key, SecByteBlock& iv)
{
    string keyAndIVData;
    LoadFile(fileName, keyAndIVData, "Base64"); // Assuming key and IV are base64 encoded

    // Tách key và IV từ dữ liệu đọc được
    string keyData = keyAndIVData.substr(0, 32); // 256-bit key
    string ivData = keyAndIVData.substr(32);     // 256-bit IV

    key.Assign((const CryptoPP::byte*)keyData.data(), keyData.size());
    iv.Assign((const CryptoPP::byte*)ivData.data(), ivData.size());
}



// Hàm băm key lớn thành SHA3-256 để tạo key AES và IV
void genAESKeyFromRandom(const std::string& filename, const CryptoPP::Integer& randomKey)
{
    // Mã hóa số nguyên thành chuỗi nhị phân để dùng cho hàm băm
    std::string binaryKey;
    randomKey.Encode(StringSink(binaryKey).Ref(), randomKey.MinEncodedSize());

    // Băm binaryKey bằng SHA3-256
    std::string hashDigest;
    CryptoPP::SHA3_512 hash;
    hash.Update(reinterpret_cast<const CryptoPP::byte*>(binaryKey.data()), binaryKey.size());

    // Lấy kết quả băm
    hashDigest.resize(hash.DigestSize());
    hash.Final(reinterpret_cast<CryptoPP::byte*>(&hashDigest[0]));

    // Chia kết quả băm SHA3-256 thành key và IV (256-bit mỗi cái)
    std::string aesKey(hashDigest.begin(), hashDigest.begin() + 32);  // 256-bit AES key
    std::string iv(hashDigest.begin() + 32, hashDigest.end());        // 256-bit IV

    // Chuyển key và IV sang Base64
    std::string keyBase64, ivBase64;
    StringSource(aesKey, true, new Base64Encoder(new StringSink(keyBase64), false));
    StringSource(iv, true, new Base64Encoder(new StringSink(ivBase64), false));

    // Mở file và ghi key và IV vào
    std::ofstream outFile(filename);
    if (outFile.is_open())
    {
        outFile << keyBase64 << ivBase64 << std::endl;
        outFile.close();
        std::cout << "Key and IV have been hashed and saved to file: " << filename << std::endl;
    }
    else
    {
        std::cerr << "Failed to open file: " << filename << std::endl;
    }
}


// Hàm chính cho mã hóa
int Encryption(const char *KeyFile, const string& message, const char *CipherFormat, const char *CipherFile)
{
    try
    {
        string strKeyFile(KeyFile);
        string strCipherFormat(CipherFormat);

        // Đọc key và iv từ file
        const size_t KEY_SIZE = AES::DEFAULT_KEYLENGTH;  // 256-bit
        const size_t IV_SIZE = AES::BLOCKSIZE;            // 256-bit (32 bytes)
        SecByteBlock key(KEY_SIZE);
        SecByteBlock iv(IV_SIZE);

        LoadKeyAndIV(strKeyFile, key, iv);

        try
        {
            // Mã hóa thông điệp
            string cipher;
            GCM<AES>::Encryption encryptor;

            const int TAG_SIZE = 12;
            encryptor.SetKeyWithIV(key, key.size(), iv);
            StringSource ss1(message, true,
                             new AuthenticatedEncryptionFilter(encryptor,
                                                               new StringSink(cipher), false, TAG_SIZE) // AuthenticatedEncryptionFilter
            );                                                                                          // StringSource

            // Lưu cipher
            SaveFile(CipherFile, SecByteBlock((const byte *)cipher.data(), cipher.size()), strCipherFormat);
            cout << "Successfully encrypted!" << endl;
            return 1;
        }
        catch (const CryptoPP::Exception &ex)
        {
            cerr << "Error encrypting: " << ex.what() << endl;
            return -1;
        }
        catch (const std::exception &ex)
        {
            cerr << "Standard exception: " << ex.what() << endl;
            return -1;
        }
    }
    catch (const CryptoPP::Exception &ex)
    {
        cerr << "Error encrypting: " << ex.what() << endl;
        return -1;
    }
    catch (const std::exception &ex)
    {
        cerr << "Standard exception: " << ex.what() << endl;
        return -1;
    }
}


int main()
{
    // Tạo một randomKey lớn (24576-bit)
    CryptoPP::Integer randomKey = generateRandomKey(24576);

    // Sử dụng randomKey để tạo AES-256 key và IV, sau đó lưu vào file "aes_key_iv.txt"
    genAESKeyFromRandom("aes_key_iv.txt", randomKey);

    return 0;
}