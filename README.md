# Research-Project
A simple bitcoin system
This a simple simulation of bitcoin system.
First, I use C++ to build a single miner system. I generate a random secret key first and use it to generate public key via ecdsa algorithm. I use this pair of key to represent the miner’s e-wallet. I also create a data structure like the block head of bitcoin to mine. I set the block size 128 bytes, which is for me to do twice sha256 to get hash value of the block, just like bitcoin. Mining is similar with bitcoin too. If the program find a block which it’s hash value accords with target(the number of front 0), it has mined a block. For simplification, at first of the program, I will input a string as the information which miners want to write in block of all the block. In addition, I set the program will stop after having mined a certain number of blocks.
Then, I use multithreading to achieve multiple miner system. To prevent interactions among threads, I use critical area to solve the problem. Besides, I output all information of the block mined in program to the screen and a binary file (will be generated in the same directory as bitcoin.exe after executing the program and it is named bitcoin.bin). I output the total time, too.
Finally, I write a program which can read the block’s information from the binary file. I can input the absolute path of the binary file and rebuild the blockchain from it so that I can output and verify them.

I use Visual Studio 2017 to program with Open-SSL. The Open-SSL version I use is win64 v1.1.1a.
To compile or debug the program, you need to:
1.	Download Open-SSL from http://slproweb.com/products/Win32OpenSSL.html and install it.
2.	Download all the file I upload to my github
3.	Create a Visual C++ empty project and add bh.h and eckey.h to the Header File. If you want to execute mining program, then add bitcoin.cpp to the Source File; If you want to execute read program, then add read.cpp to the Source File.
4.	Enter Properties setting of the project.  Set the Platform to x64.
5.	In setting add ID\include to VC++ Directory-->Include Directory and add ID\lib to VC++ Directory-->Include Directory. ID means your install directory of Open-SSL.
6.	Add libssl.lib and libcrypto.lib to Linker-->Input-->Additional Dependencies.
7.	Copy libcrypto-1_1-x64.dll and libssl-1_1-x64.dll in ID\bin to the project directory.
8.	Now you can compile, debug, execute the program.
If you just want to execute the program, please just put libcrypto-1_1-x64.dll and libssl-1_1-x64.dll in the same directory with bitcoin.exe and execute it.
