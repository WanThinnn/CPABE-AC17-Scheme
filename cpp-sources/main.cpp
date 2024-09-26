#include <cryptopp/cryptlib.h>
#include <integer.h>
#include <osrng.h>
#include <iostream>

int main() {
    // Khai báo một số Integer siêu lớn
    CryptoPP::Integer largeNumber("1234567890123456789012345678901234567890");

    // In ra số Integer
    std::cout << "Large Integer: " << largeNumber << std::endl;

    // Hoặc bạn có thể sử dụng Encode để chuyển đổi thành chuỗi
    std::string encoded;
    largeNumber.Encode(CryptoPP::StringSink(encoded), largeNumber.MinEncodedSize());
    std::cout << "Encoded Integer: " << encoded << std::endl;

    return 0;
}
