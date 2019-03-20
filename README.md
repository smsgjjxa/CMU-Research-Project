# Research-Project

A Simple Bitcoin System

This is a simple simulation of bitcoin system.

First, we use C/C++ to build a single miner system. We generate a random 32-bits secret key at first and use it to generate 33-bits public key via ECDSA algorithm. We use this pair of key to represent the miner’s e-wallet. We also create a data structure like the block head of bitcoin to mine. We set the block size to 128 bytes, which is for us to do twice SHA256 to get hash value of the block, just like bitcoin.

Mining is similar with bitcoin too. If the program finds a block which it’s hash value accords with target (number of front 0), it has mined a block. For simplification, at first of the program, we will input the mining target and a string as the information which miners want to write in block of all the block. In addition, we set the program will stop after mining a certain number of blocks.
 
Then, we use multithreading to achieve multiple miner system. To prevent interactions among threads, we use critical area to solve the problem. Therefore, the system doesn’t have any fork. Besides, we output all information of the block mined in program to the screen and a binary file (will be generated in the same directory as blockchain.exe after executing the program and it is named bitcoin.bin). We output the total time and the number of blocks that every miner has mined, too. We record (append) it in time.txt.
 
Finally, we write a program which can read the block’s information from the binary file. We can input the absolute path of the binary file and rebuild the blockchain from it so that we can output and verify them.

We use Visual Studio 2017 to program with Open-SSL. The Open-SSL version we use is win64 v1.1.1a.
To compile or debug the program, you need to:
1.	Download Open-SSL from http://slproweb.com/products/Win32OpenSSL.html and install it.
2.	Download all the file from GitHub
3.	Create a Visual C++ empty project and add bh.h and eckey.h to the Header File. If you want to execute mining program, then add blockchain.cpp to the Source File; If you want to execute read program, then add readcoin.cpp to the Source File.
4.	Enter Properties setting of the project.  Set the Platform to x64.
5.	In setting add ID\include to VC++ Directory-->Include Directory and add ID\lib to VC++ Directory-->Include Directory. ID means your install directory of Open-SSL.
6.	Add libssl.lib and libcrypto.lib to Linker-->Input-->Additional Dependencies.
7.	Copy libcrypto-1_1-x64.dll and libssl-1_1-x64.dll in ID\bin to the project directory.
8.	Now you can compile, debug and execute the program.
If you just want to execute the program, please just put libcrypto-1_1-x64.dll and libssl-1_1-x64.dll in the same directory with blockchain.exe or readcoin.exe and execute them.
