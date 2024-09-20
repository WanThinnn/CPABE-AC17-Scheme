

#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <regex>
#include "rabe/rabe.h"

#include "cryptopp/hex.h"
#include "cryptopp/base64.h"
#include "cryptopp/files.h"

#ifdef _WIN32
#ifdef BUILD_DLL
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT __declspec(dllimport)
#endif
#else
#define DLL_EXPORT __attribute__((visibility("default")))
#endif

extern "C" {
    DLL_EXPORT int setup(const char *path, const char *format);
    DLL_EXPORT int generateSecretKey(const char *publicKeyFile, const char *masterKeyFile, const char *attributes, const char *privateKeyFile, const char *format);
    DLL_EXPORT int encryptMessage(const char *publicKeyFile, const char *plaintextFile, const char *policy, const char *ciphertextFile, const char *format);
    DLL_EXPORT int decryptMessage(const char *publicKeyFile, const char *privateKeyFile, const char *ciphertextFile, const char *recovertextFile, const char *format);
}


// Hàm tách chuỗi dựa trên dấu cách
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

char *ensureJsonString(const std::string &str)
{
    // Thêm dấu ngoặc kép quanh các chữ cái
    std::regex re(R"(\b[A-Za-z]\b)");
    std::string result = std::regex_replace(str, re, "\"$&\"");

    // Cấp phát bộ nhớ cho char*
    char *cstr = new char[result.length() + 1]; // +1 để chứa ký tự kết thúc '\0'
    std::strcpy(cstr, result.c_str());

    return cstr;
    delete[] cstr;
}
// Hàm SaveFile đã được cải thiện với try-catch
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

int setup(const char *path, const char *format)
{
    std::string strPath(path);
    std::string strFileFormat(format);

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

// Hàm generateSecretKey đã được cải thiện với try-catch
int generateSecretKey(const char* publicKeyFile, const char* masterKeyFile, const  char* attributes, const  char* privateKeyFile, const char *format)
{
    std::string strFileFormat(format);
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

        // Tách các thuộc tính từ chuỗi đầu vào
        std::vector<std::string> attrVec = splitAttributes(attributes);
        std::vector<const char *> attrList;

        for (const auto &attr : attrVec)
        {
            attrList.push_back(attr.c_str());
        }

        // Sử dụng số lượng thuộc tính từ attrList.size()
        const void *secretKey = rabe_cp_ac17_generate_secret_key(masterKey, attrList.data(), attrList.size());
        if (!secretKey)
        {
            throw std::runtime_error("Failed to generate secret key.");
        }

        char *secretKeyJson = rabe_cp_ac17_secret_key_to_json(secretKey);
        if (!secretKeyJson)
        {
            throw std::runtime_error("Failed to convert secret key to JSON.");
        }

        // Ghi Secret Key ra file theo định dạng đã chọn
        if (strFileFormat == "JsonText" || strFileFormat == "HEX" || strFileFormat == "Base64")
        {
            SaveFile(privateKeyFile, secretKeyJson, strFileFormat);
            std::cout << "Secret key generated successfully." << std::endl;
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
        std::cerr << "Error generating secret key: " << ex.what() << std::endl;
        return -1;
    }
}

int encryptMessage(const char *publicKeyFile, const char *plaintextFile, const char *policy, const char *ciphertextFile, const char *format)
{
    try
    {
        std::string strPublicKeyFile(publicKeyFile);
        std::string strPlaintextFile(plaintextFile);
        std::string strPolicy(policy);
        std::string strCiphertextFile(ciphertextFile);
        std::string strFileFormat(format);

        // Đọc Public Key từ file theo định dạng
        std::string publicKeyStr;
        if (strFileFormat == "JsonText" || strFileFormat == "HEX" || strFileFormat == "Base64")
        {
            std::string publicKeyData;
            LoadFile(strPublicKeyFile, publicKeyData, strFileFormat);
            publicKeyStr = publicKeyData;
        }
        else
        {
            std::cerr << "Unsupported key format. Please choose 'JsonText', 'Base64', or 'HEX'\n";
            return -1;
        }

        const void *publicKey = rabe_ac17_public_key_from_json(publicKeyStr.c_str());
        if (!publicKey)
        {
            std::cerr << "Failed to load public key." << std::endl;
            return -1;
        }

        // Đọc plaintext từ file
        std::ifstream file(strPlaintextFile);
        if (!file)
        {
            std::cerr << "Failed to open plaintext file." << std::endl;
            return -1;
        }
        std::string plaintext((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

        const char *jsonPolicy = ensureJsonString(strPolicy);

        // Mã hóa dữ liệu
        const void *cipher = rabe_cp_ac17_encrypt(publicKey, jsonPolicy, plaintext.c_str(), plaintext.length());
        if (!cipher)
        {
            const char *error = rabe_get_thread_last_error();
            std::cerr << "Encryption failed: " << (error ? error : "Unknown error") << std::endl;
            return -1;
        }

        char *cipherJson = rabe_cp_ac17_cipher_to_json(cipher);
        if (!cipherJson)
        {
            std::cerr << "Failed to convert cipher to JSON." << std::endl;
            rabe_cp_ac17_free_cipher(cipher);
            return -1;
        }

        // Ghi cipher ra file theo định dạng đã chọn
        if (strFileFormat == "JsonText" || strFileFormat == "HEX" || strFileFormat == "Base64")
        {
            SaveFile(strCiphertextFile, cipherJson, strFileFormat);
            std::cout << "Encryption completed successfully." << std::endl;
            return 1;
        }
        else
        {
            std::cerr << "Unsupported ciphertext format. Please choose 'JsonText', 'Base64', or 'HEX'\n";
            return -1;
        }

        free(cipherJson);
        rabe_cp_ac17_free_cipher(cipher);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Exception: " << e.what() << std::endl;
        return -1;
    }
}

int decryptMessage(const char *publicKeyFile, const char *privateKeyFile, const char *ciphertextFile, const char *recovertextFile, const char *format)
{
    try
    {
        std::string strPublicKeyFile(publicKeyFile);
        std::string strPrivateKeyFile(privateKeyFile);
        std::string strCiphertextFile(ciphertextFile);
        std::string strRecovertextFile(recovertextFile);
        std::string strFileFormat(format);

        // Đọc Secret Key từ file theo định dạng
        std::string secretKeyStr;
        if (strFileFormat == "JsonText" || strFileFormat == "HEX" || strFileFormat == "Base64")
        {
            std::string secretKeyData;
            LoadFile(strPrivateKeyFile, secretKeyData, strFileFormat);
            secretKeyStr = secretKeyData;
        }
        else
        {
            std::cerr << "Unsupported key format. Please choose 'JsonText', 'Base64', or 'HEX'\n";
            return -1;
        }

        const void *secretKey = rabe_cp_ac17_secret_key_from_json(secretKeyStr.c_str());
        if (!secretKey)
        {
            std::cerr << "Failed to load secret key." << std::endl;
            return -1;
        }

        // Đọc Cipher từ file theo định dạng
        std::string cipherStr;
        if (strFileFormat == "JsonText" || strFileFormat == "HEX" || strFileFormat == "Base64")
        {
            std::string cipherData;
            LoadFile(strCiphertextFile, cipherData, strFileFormat);
            cipherStr = cipherData;
        }
        else
        {
            std::cerr << "Unsupported ciphertext format. Please choose 'JsonText', 'Base64', or 'HEX'\n";
            rabe_cp_ac17_free_secret_key(secretKey);
            return -1;
        }

        const void *cipher = rabe_cp_ac17_cipher_from_json(cipherStr.c_str());
        if (!cipher)
        {
            std::cerr << "Failed to load cipher." << std::endl;
            rabe_cp_ac17_free_secret_key(secretKey);
            return -1;
        }

        // Giải mã dữ liệu
        CBoxedBuffer decryptedBuffer = rabe_cp_ac17_decrypt(cipher, secretKey);
        if (!decryptedBuffer.buffer)
        {
            const char *error = rabe_get_thread_last_error();
            std::cerr << "Decryption failed: " << (error ? error : "Unknown error") << std::endl;
            rabe_cp_ac17_free_secret_key(secretKey);
            rabe_cp_ac17_free_cipher(cipher);
            return -1;
        }

        // Ghi dữ liệu giải mã ra file
        std::ofstream outputFile(strRecovertextFile, std::ios::binary);
        if (!outputFile)
        {
            std::cerr << "Failed to open output file for writing." << std::endl;
            rabe_cp_ac17_free_secret_key(secretKey);
            rabe_cp_ac17_free_cipher(cipher);
            rabe_free_boxed_buffer(decryptedBuffer);
            return -1;
        }

        outputFile.write(reinterpret_cast<const char *>(decryptedBuffer.buffer), decryptedBuffer.len);
        outputFile.close();
        std::cout << "Decryption completed successfully." << std::endl;
        return 1;

        rabe_free_boxed_buffer(decryptedBuffer);
        rabe_cp_ac17_free_secret_key(secretKey);
        rabe_cp_ac17_free_cipher(cipher);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Exception: " << e.what() << std::endl;
        return -1;
    }
}


// Hàm main xử lý CLI
int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cout << "Usage: " << argv[0] << " [setup|genkey|encrypt|decrypt]" << std::endl;
        return 1;
    }

    std::string mode = argv[1];

    try
    {
        if (mode == "setup")
        {
            if (argc < 3)
            {
                std::cerr << "Usage: " << argv[0] << " setup <path_to_save_file> <format:HEX/Base64/JsonText>" << std::endl;
                return 1;
            }
            std::string path = argv[2];
            std::string format = argv[3];
            setup(argv[2], argv[3]);
        }
        else if (mode == "genkey")
        {
            if (argc < 6)
            {
                std::cerr << "Usage: " << argv[0] << " genkey <public_key_file> <master_key_file> <attributes> <private_key_file> <format:HEX/Base64/JsonText>" << std::endl;
                return 1;
            }
            std::string publicKeyFile = argv[2];
            std::string masterKeyFile = argv[3];
            std::string attributes = argv[4];
            std::string privateKeyFile = argv[5];
            std::string format = argv[6];

            generateSecretKey(argv[2], argv[3], argv[4], argv[5], argv[6]);
        }
        else if (mode == "encrypt")
        {
            if (argc < 5)
            {
                std::cerr << "Usage: " << argv[0] << " encrypt <public_key_file> <plaintext_file> <policy> <ciphertext_file> <format:HEX/Base64/JsonText>" << std::endl;
                return 1;
            }
            std::string publicKeyFile = argv[2];
            std::string plaintextFile = argv[3];
            std::string policy = argv[4];
            std::string ciphertextFile = argv[5];
            std::string format = argv[6];
            encryptMessage(argv[2], argv[3], argv[4], argv[5], argv[6]);
        }
        else if (mode == "decrypt")
        {
            if (argc < 6)
            {
                std::cerr << "Usage: " << argv[0] << " decrypt <public_key_file> <private_key_file> <ciphertext_file> <recovertext_file> <format:HEX/Base64/JsonText>" << std::endl;
                return 1;
            }
            std::string publicKeyFile = argv[2];
            std::string privateKeyFile = argv[3];
            std::string ciphertextFile = argv[4];
            std::string recovertextFile = argv[5];
            std::string format = argv[6];
            decryptMessage(argv[2], argv[3], argv[4], argv[5], argv[6]);
        }
        else
        {
            std::cerr << "Invalid command: " << mode << std::endl;
            std::cerr << "Usage: " << argv[0] << " [setup|genkey|encrypt|decrypt]" << std::endl;
            return 1;
        }
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Exception: " << ex.what() << std::endl;
        return 1;
    }

    return 1;
}