#ifndef PSU_CRYPT_H
#define PSU_CRYPT_H
#include <string>
#include <fstream>

using namespace std;

class PSU_CRYPT {
public:
	int blockcount = 0;
	bool encryption;
	uint64_t K80[2] = { NULL };
	uint64_t key64 = NULL;
	uint16_t key16[5] = { NULL };
	int key8[10] = { NULL };
	uint16_t inputText[200][4] = { {NULL} };
	uint16_t outputText[200][4] = { {NULL} };
	bool readKey();
	bool readText(string filename);
	bool writeText(string filename);
	bool encrypt();

	private:
		char* int_to_char(uint16_t n);
		char* int16_to_char(uint16_t n16);
		int hex_char_to_int(char c);
		int hex_ascii_to_int(int c);
		int ints_to_int8(int i0, int i1);
		int* int80_to_int8(uint64_t* n);
		uint16_t ascii_to_int16(int i0, int i1);
		uint16_t ints_to_int16(int i0, int i1, int i2, int i3);
		uint64_t* chars_to_int80(int * hex_to_int);
		uint16_t* F(uint16_t R_0, uint16_t R_1, int round);
		uint16_t G(uint16_t w, int round, int k1, int k2, int k3, int k4);
		int K(int k);
		uint64_t * leftRotate(uint64_t* n);
		uint64_t * rightRotate(uint64_t* n);
		int Ftable(int f);
};

#endif // !"PSU-CRPT_H"
#pragma once
