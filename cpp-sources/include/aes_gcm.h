#ifndef AES_GCM__H
#define AES_GCM__H

#include <string>
#include <vector>

#ifdef _WIN32
    #ifdef BUILD_DLL
        // Khi xây dựng (export) thư viện DLL
        #define LIB_API __declspec(dllexport)
    #elif defined(USE_DLL)
        // Khi sử dụng (import) thư viện DLL
        #define LIB_API __declspec(dllimport)
    #else
        // Khi sử dụng thư viện tĩnh
        #define LIB_API
    #endif
#else
    // Với các hệ điều hành khác không cần định nghĩa đặc biệt
    #define LIB_API
#endif

extern "C" {
    // Function declarations với LIB_API cho phù hợp với DLL hoặc static lib
    LIB_API int GenerateAndSaveIV_Keys(const int KeySize, const char *KeyFormat, const char *KeyFileName, const char *IVFileName);
    LIB_API int Encryption(const char *KeyFormat, const char *KeyFile, const char *IVFile, const char *PlaintextFile, const char *CipherFormat, const char *CipherFile);
    LIB_API int Decryption(const char *KeyFormat, const char *KeyFile, const char *IVFile, const char *CipherFormat, const char *CipherFile, const char *RecoveredFile);
}

#endif // AES_GCM_H
