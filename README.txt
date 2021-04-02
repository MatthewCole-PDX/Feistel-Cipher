PSU-CRYPT Program - Grad Version - CS585 Cryptography

Created By:
Matthew Cole

Email:
macole@pdx.edu

C++ 11 program

Program performs the following:
1. Opens a file called "key.txt", containing an 80 bit key.
2. Asks the user whether to perform encryption or decryption:
	
	Encryption:
	a. Opens and reads a plaintext file called "plaintext.txt".
	b. Performs encryption algorithm
	c. Creates and stores resulting ciphertext to "ciphertext.txt"

	Decryption:
	a. Opens and reads a ciphertext file called "ciphertext.txt"
	b. Performs decryption algorithm.
	c. Creates and stores resulting plaintext to "plaintext.txt"

Instructions:
Ensure all files are kept together in the same directory. 
From inside directory, you may compile using provided makefile by typing "make" in the command line.
Otherwise you may compile using your own command line input, however it is recommended you use -std=c++11.
Once compiled, type "./PSU-CRYPT" in command line to execute program.
To wipe compilation, type "make clean" in command line.
There are many bits inside encryption and decryption process that may be printed to the  
	console by uncommenting the provided iostream statements throughout PSU-CRYPT.cpp.

Necessary files: 
"PSU-CRYPT.h": Header File, contains declaration of PSU_CRYPT class and all subsequent public and private function prototypes.
"PSU-CRYPT.cpp": C++ File, contains main function as well as all implementations of PSU_CRYPT.
"key.txt": Text File, contains desired encryption key. You are free to edit (see file specifications)
Either "plaintext.txt" or "ciphertext.txt", depending on the desired input. (see file specifications)
makefile

File specifications:
Key in key.txt must begin with "0x" followed by a string of 20 uppercase or lowercase hexadecimal digits, or current function will terminate.
"Plaintext.txt" may be any combination of ASCII characters within character limit.
"Ciphertext.txt" may be any combination of uppercase or lowercase hexadecimal digits and newline characters within character limit.
Character limit for both "plaintext.txt" and "ciphertext.txt" files is set to 5000, for larger files, adjust buffersize at top of PSU-CRYPT.cpp.


