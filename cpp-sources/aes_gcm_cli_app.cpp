// C/C++ Standard Libraries

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
void LoadFile(const std::string &filename, CryptoPP::SecByteBlock &data, const std::string &format)
{
    try
    {
        std::string encodedData;
        CryptoPP::FileSource fs(filename.c_str(), true, new CryptoPP::StringSink(encodedData));

        if (format == "Base64")
        {
            CryptoPP::StringSource ss(encodedData, true,
                                      new CryptoPP::Base64Decoder(
                                          new CryptoPP::ArraySink(data, data.size())));
        }
        else if (format == "HEX")
        {
            CryptoPP::StringSource ss(encodedData, true,
                                      new CryptoPP::HexDecoder(
                                          new CryptoPP::ArraySink(data, data.size())));
        }
        else if (format == "DER")
        {
            std::memcpy(data, encodedData.data(), encodedData.size());
        }
        else
        {
            std::cerr << "Unsupported format. Please choose 'DER', 'Base64', or 'HEX'\n";
        }
    }
    catch (const CryptoPP::Exception &e)
    {
        std::cerr << "CryptoPP Exception: " << e.what() << std::endl;
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

int GenerateAndSaveIV_Keys(const int KeySize, const char *KeyFormat, const char *KeyFileName, const char *IVFileName)
{

    AutoSeededRandomPool prng;
    string strKeyFormat(KeyFormat);
    string strKeyFileName(KeyFileName);
    string strIVFileName(IVFileName);

    // Generate key & iv
    CryptoPP::SecByteBlock key(KeySize);
    prng.GenerateBlock(key, key.size());

    CryptoPP::SecByteBlock iv(AES::BLOCKSIZE);
    prng.GenerateBlock(iv, iv.size());

    try
    {
        // Save key & iv
        if (strKeyFormat == "DER" || strKeyFormat == "HEX" || strKeyFormat == "Base64") // Save key & iv
        {
            SaveFile(strKeyFileName, key, strKeyFormat);
            SaveFile(IVFileName, iv, strKeyFormat);
        }
        else
        {
            cerr << "Unsupported key format. Please choose 'DER', 'Base64', or 'HEX'\n";
            exit(1);
        }
    }
    catch (const CryptoPP::Exception &ex)
    {
        cerr << "Error saving key: " << ex.what() << endl;
        return -1;
    }
    cout << "Successfully generate Key and IV!" << endl;

    return 1;
}

// Encryption
int Encryption(const char *KeyFormat, const char *KeyFile, const char *IVFile, const char *PlaintextFile, const char *CipherFormat, const char *CipherFile)
{
    try
    {
        string strKeyFormat(KeyFormat);
        string strKeyFile(KeyFile);
        string strCipherFormat(CipherFormat);

        size_t KeySize = GetKeySizeFromFile(strKeyFile, strKeyFormat);
        KeySize /= 8;

        // Load key & iv
        SecByteBlock key(KeySize);
        SecByteBlock iv(AES::BLOCKSIZE);

        if (strKeyFormat == "DER" || strKeyFormat == "Base64" || strKeyFormat == "HEX")
        {
            LoadFile(strKeyFile, key, strKeyFormat);
            LoadFile(IVFile, iv, strKeyFormat);
        }
        else
        {
            cerr << "Unsupported key format. Please choose 'DER', 'Base64' or 'HEX'!\n";
            return -1;
        }

        try
        {
            // Load plaintext
            string plain;
            FileSource fs(PlaintextFile, true, new StringSink(plain), false);

            // Encryption
            string cipher;
            GCM<AES>::Encryption encryptor;

            const int TAG_SIZE = 12;
            encryptor.SetKeyWithIV(key, key.size(), iv);
            StringSource ss1(plain, true,
                             new AuthenticatedEncryptionFilter(encryptor,
                                                               new StringSink(cipher), false, TAG_SIZE) // AuthenticatedEncryptionFilter
            );                                                                                          // StringSource

            // Save cipher
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

// Decryption
int Decryption(const char *KeyFormat, const char *KeyFile, const char *IVFile, const char *CipherFormat, const char *CipherFile, const char *RecoveredFile)
{
    string strKeyFile(KeyFile);
    string strCipherFormat(CipherFormat);
    string strKeyFormat(KeyFormat);

    // get size of key
    size_t KeySize = GetKeySizeFromFile(strKeyFile, strKeyFormat);

    // Load key & iv
    CryptoPP::SecByteBlock key(KeySize / 8);
    CryptoPP::SecByteBlock iv(AES::BLOCKSIZE);

    if (strKeyFormat == "DER" || strKeyFormat == "Base64" || strKeyFormat == "HEX")
    {
        LoadFile(strKeyFile, key, strKeyFormat);
        LoadFile(IVFile, iv, strKeyFormat);
    }

    else
    {
        cerr << "Unsupported key format. Please choose 'DER', 'Base64' or 'HEX'!\n";
        return -1;
    }

    // Load cipher
    string cipher;
    try
    {

        if (strCipherFormat == "DER" || strCipherFormat == "Base64" || strCipherFormat == "HEX")
        {
            // Load ciphertext from file with the specified format
            string encodedCipher;
            FileSource fs(CipherFile, true, new StringSink(encodedCipher));

            if (strCipherFormat == "Base64")
            {
                // Decode Base64 ciphertext
                StringSource(encodedCipher, true,
                             new Base64Decoder(new StringSink(cipher)));
            }
            else if (strCipherFormat == "HEX")
            {
                // Decode HEX ciphertext
                StringSource(encodedCipher, true,
                             new HexDecoder(new StringSink(cipher)));
            }
            else
            {
                // Use ciphertext as is (DER format)
                cipher = encodedCipher;
            }
        }
        else
        {
            cerr << "Unsupported cipher format. Please choose 'DER', 'Base64' or 'HEX'\n";
            return -1;
        }
    }
    catch (const CryptoPP::Exception &ex)
    {
        cerr << "Error loading cipher: " << ex.what() << endl;
        return -1;
    }

    // Decryption
    string recovered;
    GCM<AES>::Decryption decryptor;
    try
    {
        const int TAG_SIZE = 12;
        decryptor.SetKeyWithIV(key, key.size(), iv);

        AuthenticatedDecryptionFilter df(decryptor,
                                         new StringSink(recovered),
                                         AuthenticatedDecryptionFilter::DEFAULT_FLAGS, TAG_SIZE); // AuthenticatedDecryptionFilter

        StringSource ss2(cipher, true,
                         new Redirector(df)); // StringSource

        if (true == df.GetLastResult())
        {
        }
        else
        {
            cout << "Failed to verify data." << endl;
            return -1;
        }
        // Save recovered
        StringSource(recovered, true,
                     new FileSink(RecoveredFile, false));
        cout << "Successfully decrypted!" << endl;
        return 1;
    }
    catch (const CryptoPP::Exception &ex)
    {
        cerr << "Error decrypting: " << ex.what() << endl;
        return -1;
    }
}


// comment the main function if you want to build this as a static library or shared library
int main(int argc, char *argv[])
{
#ifdef _linux_
    std::locale::global(std::locale("C.utf8"));
#endif
#ifdef _WIN32

#ifndef CP_UTF8
#define CP_UTF8 65001
#endif
    // Set console code page to UTF-8 on Windows C.utf8, CP_UTF8
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    std::ios_base::sync_with_stdio(false);

    if (argc < 2)
    {
        std::cout << "Usage: " << argv[0] << " [genkey|encrypt|decrypt]" << std::endl;
        return 1;
    }
    std::string mode = argv[1];
    try
    {
        if (mode == "genkey")
        {
            if (argc != 6)
            {
                cerr << "Usage: " << argv[0] << " genkey <KeySize> <KeyFileFormat> <KeyFile> <ivfile>" << endl;
                return -1;
            }
            int KeySize = std::stoi(argv[2]);
            GenerateAndSaveIV_Keys(KeySize / 8, argv[3], argv[4], argv[5]);
        }
        else if (mode == "encrypt")
        {
            if (argc != 8)
            {
                cerr << "Usage: " << argv[0] << " encrypt <KeyFileFormat> <KeyFile> <IVFile> <PlaintextFile> <CipherFormat> <CipherFile>" << endl;
                return -1;
            }
            Encryption(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7]);
        }
        else if (mode == "decrypt")
        {
            if (argc != 8)
            {
                cerr << "Usage: " << argv[0] << " decrypt <KeyFileFormat> <KeyFile> <IVFile> <CipherFormat> <CipherFile> <RecoveredFile>" << endl;
                return -1;
            }
            Decryption(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7]);
        }
        else
        {
            std::cerr << "Invalid command: " << mode << std::endl;
            std::cerr << "Usage: " << argv[0] << " [genkey|encrypt|decrypt]" << std::endl;
            return 1;
        }
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Exception: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}