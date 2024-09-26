#ifndef AC17GCM_H
#define AC17GCM_H

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

extern "C"
{
    // Function declarations với LIB_API cho phù hợp với DLL hoặc static lib
    LIB_API int setup(const char *path);
    LIB_API int generateSecretKey(const char *publicKeyFile, const char *masterKeyFile, const char *attributes, const char *privateKeyFile);
    LIB_API int AC17encrypt(const char *publicKeyFile, const char *plaintextFile, const char *policy, const char *ciphertextFile);
    LIB_API int AC17decrypt(const char *publicKeyFile, const char *privateKeyFile, const char *ciphertextFile, const char *recovertextFile);
}
#endif // AC17GCM_H
