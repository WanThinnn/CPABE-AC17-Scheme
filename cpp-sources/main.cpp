#include <iostream>
#include <string>

int main() {
    std::string text = "Hello, World!";

    // Chuyển đổi sang mảng byte
    const unsigned char *byte_array = reinterpret_cast<const unsigned char *>(text.data());

    // In từng byte ra màn hình
    for (size_t i = 0; i < text.size(); ++i) {
        std::cout << std::hex << static_cast<int>(byte_array[i]) << "";
    }

    // Xuất độ dài của chuỗi
    std::cout << "\nĐộ dài của chuỗi (tính theo byte): " << text.size() << " bytes" << std::endl;

    return 0;
}
