#ifndef AC17_H
#define AC17__H

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
    LIB_API int setup(const char *path, const char *format);
    LIB_API int generateSecretKey(const char *publicKeyFile, const char *masterKeyFile, const char *attributes, const char *privateKeyFile, const char *format);
    LIB_API int encryptMessage(const char *publicKeyFile, const char *plaintextFile, const char *policy, const char *ciphertextFile, const char *format);
    LIB_API int decryptMessage(const char *publicKeyFile, const char *privateKeyFile, const char *ciphertextFile, const char *recovertextFile, const char *format);
}

#endif 