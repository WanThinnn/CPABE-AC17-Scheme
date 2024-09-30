#include <iostream>
#include <fstream>
#include "lzma/LzmaDec.h"
#include "lzma/LzmaLib.h"

void decompressFile(const char* inputFile, const char* outputFile) {
    std::ifstream in(inputFile, std::ios::binary);
    std::ofstream out(outputFile, std::ios::binary);

    // Đọc thuộc tính LZMA từ file
    unsigned char props[LZMA_PROPS_SIZE];
    in.read((char*)props, LZMA_PROPS_SIZE);

    // Đọc phần dữ liệu nén còn lại
    in.seekg(0, std::ios::end);
    size_t compressedSize = in.tellg() - LZMA_PROPS_SIZE;
    in.seekg(LZMA_PROPS_SIZE, std::ios::beg);
    std::vector<unsigned char> compressedData(compressedSize);
    in.read((char*)compressedData.data(), compressedSize);

    // Giải nén bằng LZMA
    size_t decompressedSize = compressedSize * 10; // Đặt ước tính kích thước đầu ra
    std::vector<unsigned char> decompressedData(decompressedSize);

    int res = LzmaUncompress(decompressedData.data(), &decompressedSize, compressedData.data(), &compressedSize, props, LZMA_PROPS_SIZE);

    if (res == SZ_OK) {
        // Ghi dữ liệu giải nén vào file output
        out.write((const char*)decompressedData.data(), decompressedSize);
        std::cout << "Giải nén thành công!" << std::endl;
    } else {
        std::cerr << "Lỗi giải nén!" << std::endl;
    }
}

int main() {
    decompressFile("output.lzma", "decompressed.txt");
    return 0;
}
