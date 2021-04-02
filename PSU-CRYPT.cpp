#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <cmath>
#include <limits>
#include <cstring>
#include <bitset> //used for testing bit rotation
#include "PSU_CRYPT.h"

using namespace std;

const int bufferSize = 5000;

int main() {
	PSU_CRYPT psu_crypt;
	string input;
	string output;
	int option = 1;
	while (option != 3) {
		cout << "Options:" << endl;
		cout << "1 - Encrypt" << endl;
		cout << "2 - Decrypt" << endl;
		cout << "3 - Quit" << endl;
		do {
			//https://stackoverflow.com/questions/10349857/how-to-handle-wrong-data-type-input
			while (std::cout << "Enter option #: " && !(std::cin >> option)) {
				std::cin.clear(); //clear bad input flag
				std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); //discard input
				std::cout << "Invalid input; please re-enter.\n";
			} 
			cout << endl;
		} while (option < 1 || option > 3);

		if (psu_crypt.readKey()) {
			if (option == 1) {
				psu_crypt.encryption = true;
				if (psu_crypt.readText("plaintext.txt"))
					if(psu_crypt.encrypt())
						psu_crypt.writeText("ciphertext.txt");
			}
			else if (option == 2) {
				psu_crypt.encryption = false;
				if(psu_crypt.readText("ciphertext.txt"))
					if(psu_crypt.encrypt())
						psu_crypt.writeText("plaintext.txt");
			}
		}
		else {
			cout << "error: cannot read/find key.txt";
			return 0;
		}
	}
	return 0;
}

bool PSU_CRYPT::readKey() {
	cout << setfill('-') << "----------" << setw(24) << " 80 bit Key " << setw(24) << "--" << endl << endl;
	char buffer[bufferSize] = { NULL };
	//https://stackoverflow.com/questions/4807025/in-c-how-do-i-correctly-load-a-file-into-an-array-of-wider-than-char-data-typ
	ifstream* pStream = new ifstream("key.txt");
	if (pStream->is_open() == true){
		pStream->read(buffer, bufferSize);
	}
	cout << endl << "Key: " << buffer << endl;

	const size_t strLength = strlen(buffer);

	if (buffer[0] != '0' || buffer[1] != 'x') {
		cout << "error: key must begin with '0x'";
		return false;
	}
	if (strLength != 22) {
		cout << "error: key must be 80 bit hex (20 characters)";
		return false;
	}

	int* hex_to_int = new int[strLength - 2];
	for (int i = 2; i < strLength; i++) {
		hex_to_int[i - 2] = hex_char_to_int(buffer[i]);
	}
	
	int j = 0;
	cout << "Whitening Bits: ";
	for (int i = 0; i < 5; i++) {
		key16[i] = ints_to_int16(hex_to_int[j++], hex_to_int[j++], hex_to_int[j++], hex_to_int[j++]);
		cout << "K[" << i << "]: 0x" << hex << key16[i];
		if (i != 4) cout << ", ";
		else cout << " ";
	}
	cout << endl;
	
	j = 0;
	cout << "Key Bits: " << endl;
	for (int i = 9; i >= 0; i--) {
		key8[i] = ints_to_int8(hex_to_int[j++], hex_to_int[j++]);
		cout << "K[" << i << "]: 0x" << key8[i];
		if (i != 0 && i != 5) cout << ", ";
		else cout << endl;
	}
	cout << endl;
	
	chars_to_int80(hex_to_int);
	delete [] hex_to_int;
	return true;
}

bool PSU_CRYPT::readText(string filename) {
	cout << setfill('-') << "----------" << setw(24) << " Input Text " << setw(24) << "--" << endl;
	char buffer[bufferSize] = { NULL };
	ifstream* pStream = new ifstream(filename);
	if (pStream->is_open() == true) {
		pStream->read(buffer, bufferSize);
	}
	size_t strLength = strlen(buffer);
	int nl = 0;
	if (encryption) cout << endl << "Plaintext: " << endl << endl << buffer << endl;
	else{
		cout << endl << "Ciphertext: " << endl << endl;
		int j = 0;
		bool newline = false;
		for (int i = 0; i < strLength; i++) {
			if (j % 16 == 0 && newline == false) {
				if (j > 0) {
					if (j % 80 != 0)
						cout << " | ";
					else
						cout << endl;
				}
				if(buffer[i+1] != NULL) cout << "0x";
			}
			if (buffer[i] != '\n') {
				cout << buffer[i];
				j++;
				newline = false;
			}
			else {
				nl++;
				newline = true;
			}
		}
		cout << endl;
		int* hex_to_int = new int[strLength];
		for (int i = 2; i < strLength; i++) {
			hex_to_int[i - 2] = hex_char_to_int(buffer[i]);
		}
	}
	
	int block = 0, j = 0;
	if (!encryption) {
		int* hex_to_int = new int[strLength - nl];
		int k = 0;
		for (int i = 0; i < strLength; i++) {
			if(buffer[i] != '\n') hex_to_int[k++] = hex_char_to_int(buffer[i]);
		}
		while (j < strLength - nl) {
			for (int i = 0; i < 4; i++) {
				inputText[block][i] = ints_to_int16(hex_to_int[j++], hex_to_int[j++], hex_to_int[j++], hex_to_int[j++]);
				//cout << "w[" << i << "]: 0x" << hex << inputText[block][i];
				//if (i != 3) cout << ", ";
				//else cout << endl;
			}
			block++;
		}
		delete[] hex_to_int;
	}else{
		int* char_to_int = new int[strLength];
		for (int i = 0; i < strLength; i++) {
			char_to_int[i] = int(buffer[i]);
		}
		while (j < strLength) {
			//cout << dec << block << ". ";
			for (int i = 0; i < 4; i++) {
				if (j + 1 >= strLength) {
					if (j >= strLength){
						j += 2;
						inputText[block][i] = ascii_to_int16(0, 0);
					} else {
						inputText[block][i] = ascii_to_int16(0, char_to_int[j++]);
						j++;
					}
				} else {
					inputText[block][i] = ascii_to_int16(char_to_int[j++], char_to_int[j++]);
				}
				//cout << "w[" << i << "]: 0x" << hex << inputText[block][i];
				//if (i != 3) cout << ", ";
				//else cout << endl;
			}
			block++;
		}
		delete[] char_to_int;
	}
	blockcount = block;
	cout << endl;
	cout << setfill('-') << "----------" << setw(48) << "--" << endl << endl;
	return true;
}

bool PSU_CRYPT::writeText(string filename) {
	ofstream outputTextFile(filename);
	cout << endl;
	cout << setfill('-') << "----------" << setw(24) << " Output Text " << setw(24) << "--" << endl << endl;
	int block = 0;
	if (encryption) {
		cout << "Ciphertext: " << endl << endl;
		while (block < blockcount) {
			if (block != 0 && (block % 5) != 0)
				cout << " | ";
			cout << "0x";
			for (int i = 0; i < 4; i++) {
				if (outputText[block][i] < 16) {
					cout << "000";
					outputTextFile << "000";
				}
				else if (outputText[block][i] < 256) {
					cout << "00";
					outputTextFile << "00";
				}
				else if (outputText[block][i] < 4096) {
					cout << "0";
					outputTextFile << "0";
				}
				cout << hex << outputText[block][i];
				outputTextFile << hex << outputText[block][i];
				outputText[block][i] = NULL;
			}
			outputTextFile << endl;
			if (block > 0 && (block + 1) % 5 == 0)
				cout << endl;
			block++;
		}
		cout << endl;
		cout << endl;
	}
	else {
		cout << "Plaintext: " << endl << endl;
		while (block < blockcount) {
			for (int i = 0; i < 4; i++) {
				char * c = int16_to_char(outputText[block][i]);
				cout << c[0] << c[1];
				outputTextFile << c[0] << c[1];
				outputText[block][i] = NULL;
			}
			block++;
		}
		cout << endl << endl;
	}
	outputTextFile.close();
	K80[0] = K80[1] = NULL;
	return true;
}

bool PSU_CRYPT::encrypt() {
	int block = 0;
	int round = 0;
	if (!encryption) {
		round = 19;
		cout << "Decrypting";
	}
	else cout << "Encrypting";
	while (block < blockcount) { //whitening
		cout << ".";
		/*if (inputText[1][0] != NULL) {
			cout << endl;
			cout << setfill('-') << "-----" << setw(24) << " Block " << dec << block << " ";
			cout << setw(24) << "----" << endl << endl;
		}
		cout << "After Whitening: ";*/
		for (int R = 0; R < 4; R++) {
			//cout << "R[" << R << "]: 0x";
			int K = R, w = R;
			inputText[block][w] ^= key16[K];
			//cout << inputText[block][R];
			//if (R != 3) cout << ", ";
			//else cout << " ";
		}
	if(!encryption){
			//cout << endl << endl << "Decryption:" << endl << endl;
			outputText[block][0] = inputText[block][2];
			outputText[block][1] = inputText[block][3];
			inputText[block][2] = inputText[block][0];
			inputText[block][3] = inputText[block][1];
			inputText[block][0] = outputText[block][0];
			inputText[block][1] = outputText[block][1];
		}
	//else cout << endl << endl << "Encryption:" << endl << endl; 
		for (int i = 0; i < 20; i++) {
			//cout << "Round " << dec << round << ":" << endl;
			uint16_t* f = new uint16_t[4]; 
			if (encryption) {
				f = F(inputText[block][0], inputText[block][1], round);
				outputText[block][0] = inputText[block][2] ^ f[0];
				outputText[block][1] = inputText[block][3] ^ f[1];
				inputText[block][2] = inputText[block][0];
				inputText[block][3] = inputText[block][1];
				inputText[block][0] = outputText[block][0];
				inputText[block][1] = outputText[block][1];
			}
			if(!encryption){
				f = F(inputText[block][2], inputText[block][3], round);
				outputText[block][0] = inputText[block][0] ^ f[0];
				outputText[block][1] = inputText[block][1] ^ f[1];
				inputText[block][0] = inputText[block][2];
				inputText[block][1] = inputText[block][3];
				inputText[block][2] = outputText[block][0];
				inputText[block][3] = outputText[block][1];

			}
			//cout << "Block: 0x";
			//for (int j = 0; j < 4; j++) { cout << hex << inputText[block][j]; }
			//cout << endl;
			//cout << endl;
			if (encryption) round++;
			else round--;
		}
		uint16_t* y = new uint16_t[4];
		if (encryption) {
			y[0] = inputText[block][2];
			y[1] = inputText[block][3];
			y[2] = inputText[block][0];
			y[3] = inputText[block][1];
		}
		else {
			y[0] = inputText[block][0];
			y[1] = inputText[block][1];
			y[2] = inputText[block][2];
			y[3] = inputText[block][3];
		}
		//cout << "Output Whitening: ";
		for (int i = 0; i < 4; i++) {
			outputText[block][i] = y[i] ^ key16[i];
			//cout << "C[" << i << "]: 0x" << outputText[block][i];
			//if (i != 3) cout << ", ";
			//else cout << " ";
		}
		//cout << endl;
		if (encryption) round = 0;
		else round = 19;
		delete y;
		block++;
	}
	cout << endl;
	for (int i = --block; i >= 0; i--)
		for (int j = 0; j < 4; j++) inputText[block][j] = NULL;
	return true;
}



uint16_t * PSU_CRYPT::F(uint16_t R_0, uint16_t R_1, int round){
	uint16_t* T = new uint16_t[2];
	uint16_t* f = new uint16_t[2];
	const unsigned int n = 65536;
	int* k = new int[12];
	if (encryption) {
		for (int i = 0; i < 12; i++) k[i] = K(4 * round + (i % 4));
		T[0] = G(R_0, round, k[0], k[1], k[2], k[3]);
		T[1] = G(R_1, round, k[4], k[5], k[6], k[7]);
		f[0] = (T[0] + (2 * T[1]) + (ints_to_int16((k[9] % 16), (k[9] / 16), (k[8] % 16), (k[8] / 16)))) % n;
		f[1] = ((2 * T[0]) + T[1] + (ints_to_int16((k[11] % 16), (k[11] / 16), (k[10] % 16), (k[10] / 16)))) % n;
	}
	else {
		for (int i = 11; i >= 0; i--) k[i] = K(4 * round + (i % 4));
		//cout << "keys: " << endl;
		//for (int i = 11; i > 5; i--) cout << hex << k[i] << " ";
		//cout << endl;
		//for (int i = 5; i >= 0; i--) cout << hex << k[i] << " ";
		//cout << endl;
		T[1] = G(R_1, round, k[4], k[5], k[6], k[7]);
		T[0] = G(R_0, round, k[0], k[1], k[2], k[3]);
		f[1] = ((2 * T[0]) + T[1] + (ints_to_int16((k[11] % 16), (k[11] / 16), (k[10] % 16), (k[10] / 16)))) % n;
		f[0] = (T[0] + (2 * T[1]) + (ints_to_int16((k[9] % 16), (k[9] / 16), (k[8] % 16), (k[8] / 16)))) % n;
	}
		//cout << hex << "T[0]: " << T[0] << ",   T[1]: " << T[1] << ",   f[0]: " << f[0] << ",   f[1]: " << f[1] << endl;
	return f;
}
uint16_t PSU_CRYPT::G(uint16_t w, int round, int k1, int k2, int k3, int k4) {
	int * g = new int[6];

	g[0] = ((w / (16 * 16 * 16)) * 16) + ((w % (16 * 16 * 16)) / (16 * 16));
	g[1] = ((((w % (16 * 16 * 16)) % (16 * 16)) / 16) * 16) + (((w % (16 * 16 * 16)) % (16 * 16)) % 16);
	g[2] = Ftable((g[1] ^ k1)) ^ g[0];
	g[3] = Ftable((g[2] ^ k2)) ^ g[1];
	g[4] = Ftable((g[3] ^ k3)) ^ g[2];
	g[5] = Ftable((g[4] ^ k4)) ^ g[3];
	//cout << hex << "g[1]: 0x" << g[0] << " g[2]: 0x" << g[1] << " g[3]: 0x" << g[2] << " g[4]: 0x" << g[3] << " g[5]: 0x" << g[4] << " g[6]: 0x" << g[5] << endl;
	return ints_to_int16((g[5] % 16), (g[5] / 16), (g[4] % 16), (g[4] / 16));
}	

int PSU_CRYPT::K(int k) {
	if (encryption) {
		uint64_t* left = leftRotate(K80);
		K80[0] = left[0];
		K80[1] = left[1];
		int* key = int80_to_int8(K80);
		return key[k % 10];
	}
	int* key = int80_to_int8(K80);
	uint64_t* right = rightRotate(K80);
	K80[0] = right[0];
	K80[1] = right[1];
	return key[k % 10];
}

int* PSU_CRYPT::int80_to_int8(uint64_t* k) {
	int* temp = new int[10];
	uint64_t m_16 = 1;
	uint64_t n_16 = 1;
	for (int i = 1; i >= 0; i--) {
		uint64_t tk = k[i];
		for (int j = 4; j >= 0; j--) {
			for (int m = 0; m < 2 * j; m++)
				m_16 *= 16;
			for (int n = 0; n < 2 * j + 1; n++)
				n_16 *= 16;
			int x = (tk / n_16);
			tk = tk % n_16;
			int y = (tk / m_16);
			tk = tk % m_16;
			temp[((-i + 1) * 5) + j] = (16 * x + y);
			n_16 = m_16 = 1;
		}
	}
	return temp;
}/*
char * PSU_CRYPT::int_to_char(uint16_t n) {
	char* c = int16_to_char(n);
	return c;
}*/
char* PSU_CRYPT::int16_to_char(uint16_t n16) {
	char * c = new char[2];
	c[0] = (n16 / (16 * 16 * 16))*16 + ((n16 % (16 * 16 * 16))/(16 * 16));
	c[1] = (((n16 % (16 * 16 * 16)) % (16 * 16)) / 16) * 16 + (((n16 % (16 * 16 * 16)) % (16 * 16)) % 16);
	return c;
}

int PSU_CRYPT::hex_char_to_int(char c) {
	c = tolower(c);
	if (int(c) < 58) //number
		return c - 48;
	else if (int(c) < 123) //letter
		return c - 87;
}
int PSU_CRYPT::hex_ascii_to_int(int c) {
	return ((c / 10) * 16) + (c % 10);
}
uint16_t PSU_CRYPT::ascii_to_int16(int i0, int i1) {
	return ((i1 / 16) * 16 * 16 * 16) + ((i1 % 16) * 16 * 16) + ((i0 / 16) * 16) + (i0 % 16);
}

uint64_t* PSU_CRYPT::chars_to_int80(int* hex_to_int) {
	uint64_t n_16 = 1;
	for (int i = 0; i < 20; i++) {
		for (int j = 0; j < ((19 - i) % 10); j++)
			n_16 *= 16;
		K80[i / 10] += (hex_to_int[i] * n_16);
		n_16 = 1;
	}
	return K80;
}

uint16_t PSU_CRYPT::ints_to_int16(int i0, int i1, int i2, int i3) {
	return (i3 * 16 * 16 * 16) + (i2 * 16 * 16) + (i1 * 16) + i0;
}

int PSU_CRYPT::ints_to_int8(int i0, int i1) {
	return (i1 * 16) + i0;
}

//https://www.geeksforgeeks.org/bitwise-operators-in-c-cpp/
//https://www.geeksforgeeks.org/how-to-turn-off-a-particular-bit-in-a-number/
uint64_t turnOffBit(uint64_t n) {
	string s = "1111111111111111111111110000000000000000000000000000000000000000";
	uint64_t x = (uint64_t)bitset<64>(s).to_ullong();
	return n & ~x;
}

//https://www.geeksforgeeks.org/rotate-bits-of-an-integer/
uint64_t * PSU_CRYPT::leftRotate(uint64_t* n){
	uint64_t temp0 = (n[0] << 1) | (n[1] >> 39);
	uint64_t temp1 = (n[1] << 1) | (n[0] >> 39);
	n[0] = temp0;
	n[1] = temp1;
	n[0] = turnOffBit(n[0]);
	n[1] = turnOffBit(n[1]);
	return n;
}

uint64_t * PSU_CRYPT::rightRotate(uint64_t* n) {
	uint64_t temp0 = (n[1] << 39) | (n[0] >> 1);
	uint64_t temp1 = (n[0] << 39) | (n[1] >> 1);
	n[0] = temp0;
	n[1] = temp1;
	n[0] = turnOffBit(n[0]);
	n[1] = turnOffBit(n[1]);
	return n;
}

//https://www.geeksforgeeks.org/converting-strings-numbers-cc/
int PSU_CRYPT::Ftable(int f) {
	string ftable[16][16] = {
			{"a3", "d7", "09", "83", "f8", "48", "f6", "f4", "b3", "21", "15", "78", "99", "b1", "af", "f9"},
			{"e7", "2d", "4d", "8a", "ce", "4c", "ca", "2e", "52", "95", "d9", "1e", "4e", "38", "44", "28"},
			{"0a", "df", "02", "a0", "17", "f1", "60", "68", "12", "b7", "7a", "c3", "e9", "fa", "3d", "53"},
			{"96", "84", "6b", "ba", "f2", "63", "9a", "19", "7c", "ae", "e5", "f5", "f7", "16", "6a", "a2"},
			{"39", "b6", "7b", "0f", "c1", "93", "81", "1b", "ee", "b4", "1a", "ea", "d0", "91", "2f", "b8"},
			{"55", "b9", "da", "85", "3f", "41", "bf", "e0", "5a", "58", "80", "5f", "66", "0b", "d8", "90"},
			{"35", "d5", "c0", "a7", "33", "06", "65", "69", "45", "00", "94", "56", "6d", "98", "9b", "76"},
			{"97", "fc", "b2", "c2", "b0", "fe", "db", "20", "e1", "eb", "d6", "e4", "dd", "47", "4a", "1d"},
			{"42", "ed", "9e", "6e", "49", "3c", "cd", "43", "27", "d2", "07", "d4", "de", "c7", "67", "18"},
			{"89", "cb", "30", "1f", "8d", "c6", "8f", "aa", "c8", "74", "dc", "c9", "5d", "5c", "31", "a4"},
			{"70", "88", "61", "2c", "9f", "0d", "2b", "87", "50", "82", "54", "64", "26", "7d", "03", "40"},
			{"34", "4b", "1c", "73", "d1", "c4", "fd", "3b", "cc", "fb", "7f", "ab", "e6", "3e", "5b", "a5"},
			{"ad", "04", "23", "9c", "14", "51", "22", "f0", "29", "79", "71", "7e", "ff", "8c", "0e", "e2"},
			{"0c", "ef", "bc", "72", "75", "6f", "37", "a1", "ec", "d3", "8e", "62", "8b", "86", "10", "e8"},
			{"08", "77", "11", "be", "92", "4f", "24", "c5", "32", "36", "9d", "cf", "f3", "a6", "bb", "ac"},
			{"5e", "6c", "a9", "13", "57", "25", "b5", "e3", "bd", "a8", "3a", "01", "05", "59", "2a", "46"} };
	string s;
	s = ftable[f / 16][f % 16];
	stringstream xy(s);
	int x = 0;
	xy >> hex >> x;
	s = { NULL };
	return x;
}

