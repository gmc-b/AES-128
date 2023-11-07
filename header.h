/* **** Arquivo: 	header.h
  ***** Autor:     	Guilherme Mattos Camargo
  ***** Matrícula: 	170104508 
  ***** Disciplina:	Segurança computacional
*/

#ifndef HEADER_H
#define HEADER_H


#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <float.h>

#define BLOCK_SIZE_BITS  128
#define BLOCK_SIZE_BYTES 16
#define KEY_SIZE_BYTES 16
#define BYTE_SIZE 8

typedef struct stc_block_128{
	uint8_t bytes[4][4];		
}Block_128;

typedef struct stc_block_array{
	Block_128* first;
	int size;
}Block_Array;

extern int printf_flag;

//////////////////////////////////////////////// constants ////////////////////////////////////////////////

extern const uint32_t RCON[15];

extern const uint8_t mult_matrix[4][4];            

extern const uint8_t mult_matrix_inverse[4][4];           

extern const uint8_t s_box[16][16];

extern const uint8_t s_box_inverse[16][16];

extern const uint8_t galois_e[16][16];

extern const uint8_t galois_l[16][16];



///////////////////////////////////////////// print functions /////////////////////////////////////////////

void print_expanded_key(uint32_t expanded_key[44]);

void print_key(uint32_t key[4], char* string);

void print_block_array(Block_Array block_array_stc, char* title);

void print_round(int round);

////////////////////////////////////////////// file functions //////////////////////////////////////////////


int max_int(int a, int b);

int min_int(int a, int b);

int file_size(FILE* file_ptr);

void ascci_to_hex(char ascii_key[32],uint32_t key[4]);

void file_to_hex(char* key_file_name, uint32_t key[4]);

Block_Array file_to_block_array(char* input_file_name);

int block_to_file(char* input_file_name,Block_Array block_array_stc, int inverse);



///////////////////////////////////////////////////////////////////////////////////////////////////////////

#endif
