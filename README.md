# File Backup Application
This is my solution for exersice 15 in the course Defensive Systems Programming (20937) in the Open University of Israel.</br>
I tried to create the most robust program as possible, using the concepts I learned in this course.

## General description
This is a client-server application which allows clients to store files in a remote server. The files are encrypted before they are being transfered. </br>
The server's job is to constantly listen to client's requests, and the client works with a pre-defined set of instructions, as follows:
* The client reads two files called **transfer.info** and **me.info** which hold the following information:
  * Backup information
  * Credentials
  * Private key
* If me.info is not present, then the client needs to register to the server. Otherwise he logs in.
* A client registers or logs in to the server.
* Client and server exchange encryption keys, using this scheme:
  * The client loads/creates a pair of private and public key.
  * The publik key is sent to the server.
  * Meanwhile, the server creates a session key (AES) and encrypts it with the public key.
  * The encrypted session key is sent to the client, and he decrypts it with the private key.
* After exchaning the keys, the client encrypts the file and sends it to the server.
* a CRC32 checksum is used to verify that the file was received correctly on the server.

## Technical details
* The client is written in C++11, and the server in Python 3.9.
* Compiler and target is MSVC 14.3 (Visual Studio 2022) on 64-bit Windows 11.
* I used Boost (v1.81.0) and CryptoPP (v8.7.0) libraries on the client.
* I used PyCryptoDome and SQLite on the server.
* The servers maintains a database using SQLite 3.
* The servers supports multiple clients at the same time using threading. </br>

## Build instructions (client) on Visual Studio 2022:
1. Download Boost library: https://www.boost.org/
2. Compile with: ```b2.exe variant=debug link=static threading=multi address-model=64 toolset=msvc-14.3 runtime-link=static```
3. Download CryptoPP library: https://cryptopp.com/
4. Compile cryptlib project using **x64 Debug configuration**.
5. Change the following settings in **client** project properties (right click 'client' project -> Properties):
   * C/C++ -> General -> Additional Include Directories, and add Boost and CryptoPP
   * C/C++ -> Code Generation -> Runtime Library, and select 'Multi-threaded Debug (/MTd)'
   * Linker -> General -> Additional Library Directories, and add 'boost_1_81_0\stage\lib' and 'cryptopp870\x64\Output\Debug'
   * Linker -> Input -> Additional Dependencies, and add cryptlib.lib
6. All set! The solution is ready. </br>

## Installations for server:
1. ```pip install pycryptodome```
2. All set!

## Additional resources:
More info about the exersice, such as protocol, requirements etc. can be found in 'maman15.pdf' (file is written in hebrew).
