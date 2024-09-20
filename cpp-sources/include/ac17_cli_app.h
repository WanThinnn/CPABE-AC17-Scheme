#ifndef AC17_CLI_APP_H
#define AC17_CLI_APP_H

#ifdef _WIN32
    #ifdef BUILD_DLL
        #define DLL_EXPORT __declspec(dllexport)
    #else
        #define DLL_EXPORT __declspec(dllimport)
    #endif
#else
    #define DLL_EXPORT
#endif

extern "C" {
    DLL_EXPORT int setup(const char *path, const char *format);
    DLL_EXPORT int generateSecretKey(const char *publicKeyFile, const char *masterKeyFile, const char *attributes, const char *privateKeyFile, const char *format);
    DLL_EXPORT int encryptMessage(const char *publicKeyFile, const char *plaintextFile, const char *policy, const char *ciphertextFile, const char *format);
    DLL_EXPORT int decryptMessage(const char *publicKeyFile, const char *privateKeyFile, const char *ciphertextFile, const char *recovertextFile, const char *format);
}

#endif // AC17_CLI_APP_H