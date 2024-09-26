# CPABE-AC17-Scheme
Ciphertext Policy Attribute Based Encryption - AC17 Scheme Library for C/C++ in Windows

## Prerequisites

- [CryptoPP Library](https://github.com/weidai11/cryptopp)
- [CP-ABE AC17 Scheme](https://eprint.iacr.org/2017/807)
- [Rabe-ffi](https://github.com/Aya0wind/Rabe-ffi)


## Building for Windows

1. Clone the repository:
    ```sh
    git clone https://github.com/WanThinnn/CPABE-AC17-Scheme.git
    ```
2. Navigate to the project directory:
    ```sh
    cd CPABE-AC17-Scheme/cpp-sources
    code . #for open projects Visual Studio Code
    ```
3. Configure `tasks.json` to build the project using `cl.exe`:
    - Create or open the `.vscode` folder in your project directory.
    - Create a `tasks.json` file inside the `.vscode` folder with the following content:

  ```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "type": "shell",
            "label": "C/C++: cl.exe build executable",
            "command": "cl.exe",
            "args": [
                "/MD",
                "/GS",
                "/O2",
                "/Zi",
                "/EHsc",
                "/Fe:${fileDirname}\\${fileBasenameNoExtension}.exe",
                "${file}",
                "/I${workspaceFolder}\\include",
                "/link",
                "/LIBPATH:${workspaceFolder}\\lib\\static-lib",
                "librabe_ffi.lib", // Rabe FFI Library
                "cryptlib.lib", //CryptoPP890 Library
                "bcrypt.lib", // Provides cryptographic functions (Windows system libraries)
                "advapi32.lib", // Provides advanced API services including security and registry functions (Windows system libraries)
                "ntdll.lib", // Windows system libraries
                "/MACHINE:X64"
            ],
            "problemMatcher": ["$msCompile"],
            "group": {
                "kind": "build",
                "isDefault": true
            },
            "detail": "Task to build executable."
        },
        {
            "type": "shell",
            "label": "C/C++: cl.exe build static library",
            "command": "cl.exe",
            "args": [
                "/MD",  // Use static runtime
                "/GS",
                "/O2",
                "/Zi",
                "/EHsc",
                "/c",  // Compile without linking
                "${file}",
                "/I${workspaceFolder}\\include"
            ],
            "problemMatcher": ["$msCompile"],
            "group": {
                "kind": "build",
                "isDefault": false
            },
            "detail": "Task to build static library."
        },
        {
            "type": "shell",
            "label": "C/C++: lib.exe create static library",
            "command": "lib.exe",
            "args": [
                "/OUT:${fileDirname}\\${fileBasenameNoExtension}.lib",
                "${fileDirname}\\${fileBasenameNoExtension}.obj",
                "/LIBPATH:${workspaceFolder}\\lib\\static-lib",
                "librabe_ffi.lib",
                "cryptlib.lib",
                "bcrypt.lib",
                "advapi32.lib",
                "ntdll.lib"
            ],
            "problemMatcher": ["$msCompile"],
            "group": {
                "kind": "build",
                "isDefault": false
            },
            "detail": "Task to create static library."
        },
        {
            "type": "shell",
            "label": "C/C++: cl.exe build dynamic linking library (DLL)",
            "command": "cl.exe",
            "args": [
                "/MD",
                "/GS",
                "/O2",
                "/Zi",
                "/EHsc",
                "/LD",  // for build DLL
                "/DBUILD_DLL", // define macro BUILD_DLL
                "/Fe:${fileDirname}\\${fileBasenameNoExtension}.dll",
                "${file}",
                "/I${workspaceFolder}\\include",
                "/link",
                "/LIBPATH:${workspaceFolder}\\lib\\static-lib",
                "librabe_ffi.lib", // Rabe FFI Library
                "cryptlib.lib", //CryptoPP890 Library
                "bcrypt.lib", // Provides cryptographic functions (Windows system libraries)
                "advapi32.lib", // Provides advanced API services including security and registry functions (Windows system libraries)
                "ntdll.lib", // Windows system libraries
                "/MACHINE:X64"
            ],
            "problemMatcher": ["$msCompile"],
            "group": {
                "kind": "build",
                "isDefault": false
            },
            "detail": "C/C++: cl.exe build dynamic linking library (DLL)"
        },
    ]
}
  ```

4. Build the project:
    - Open Visual Studio Code and open your project.
    - Press `Ctrl+Shift+B` to run the configured build task.
    - If everything is configured correctly, your program will be compiled using `cl.exe`.

## Usage

### Using the Executable

To use the pre-built executable, navigate to the `CPABE-AC17-Scheme/demo` directory and run the `ac17_cli_app.exe` file:

```sh
cd CPABE-AC17-Scheme/demo
.\ac17_cli_app.exe
```


The usage of the executable is as follows:
```sh
Usage: ac17_cli_app.exe [setup|genkey|encrypt|decrypt]
Usage: ac17_cli_app.exe setup <path_to_save_file> <format:HEX/Base64/JsonText>
Usage: ac17_cli_app.exe genkey <public_key_file> <master_key_file> <attributes> <private_key_file> <format:HEX/Base64/JsonText>
Usage: ac17_cli_app.exe encrypt <public_key_file> <plaintext_file> <policy> <ciphertext_file> <format:HEX/Base64/JsonText>
Usage: ac17_cli_app.exe decrypt <public_key_file> <private_key_file> <ciphertext_file> <recovertext_file> <format:HEX/Base64/JsonText>
```

Example commands:
```sh
.\ac17_cli_app.exe setup "test_case" Base64
.\ac17_cli_app.exe genkey "test_case/public_key.key" "test_case/master_key.key" "A B C" "test_case/private_key.key" Base64
.\ac17_cli_app.exe encrypt "test_case/public_key.key" "test_case/plaintext.txt" "((A and C) or E)" "test_case/ciphertext.txt" Base64
.\ac17_cli_app.exe decrypt "test_case/public_key.key" "test_case/private_key.key" "test_case/ciphertext.txt" "test_case/recovertext.txt" Base64
```
### Integrating the Library
After building the library, you can integrate it into any program on Windows. Here are the steps to include the library in your project.
Please go to <b>python-sources</b> folder to see more.

## Acknowledgements
Special thanks to [Aya0wind](https://github.com/Aya0wind) for the [Rabe-ffi](https://github.com/Aya0wind/Rabe-ffi) project and the [CryptoPP](https://github.com/weidai11/cryptopp) Library for helping me build this library.
## License

This project is open-source and available for anyone to use, modify, and distribute. We encourage you to clone, fork, and contribute to this project to help improve and expand its capabilities.
By contributing to this project, you agree that your contributions will be available under the same open terms.
