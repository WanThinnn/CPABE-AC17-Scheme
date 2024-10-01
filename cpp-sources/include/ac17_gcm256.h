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
    class LIB_API AC17
    {
    public:
        // Constructor và destructor
        AC17() = default;
        ~AC17() = default;

        // Phương thức setup
        int setup(const char *path);

        // Phương thức generateSecretKey
        int generateSecretKey(const char *publicKeyFile, const char *masterKeyFile, const char *attributes, const char *privateKeyFile);

        // Phương thức AC17encrypt
        int encrypt(const char *publicKeyFile, const char *plaintextFile, const char *policy, const char *ciphertextFile);

        // Phương thức AC17decrypt
        int decrypt(const char *publicKeyFile, const char *privateKeyFile, const char *ciphertextFile, const char *recovertextFile);
    };
}
#endif // AC17GCM_H
