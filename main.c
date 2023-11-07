/* **** Arquivo:    main.c
  ***** Autor:      Guilherme Mattos Camargo
  ***** Matrícula:  170104508 
  ***** Disciplina: Segurança Computacional
*/


#include "header.h"



void mensagem_inst(){
    printf("\n");
    printf(" Erro na utilização dos argumentos\n\n");
    printf(" 1º argumento - Modo de funcionamento:\n");
    printf("   - \"e\": Criptografa um arquivo\n");
    printf("   - \"d\": Descriptografa um arquivo\n");
    printf(" 2º argumento - Nome do arquivo de entrada\n");
    printf(" 3º argumento - Nome do arquivo de chave (arquivo .txt com a chave expressa em hexadecimal)\n");
    printf(" 4º argumento - (Opcional) digite -v para ver prints de cada etapa do processo  \n\n");
    
}



///////////////////////////////////////////// byte manipulation functions /////////////////////////////////////////////

uint8_t last_4_bits(uint8_t byte){
   return byte & 0b00001111;
}

uint8_t first_4_bits(uint8_t byte){
    return  byte>>4;
}

uint8_t byte_selector(uint32_t word, int byte_index){ 

    // de 0 a 3 
    uint8_t byte;
    uint32_t new_word = word>>(byte_index*8) & 0b11111111;

    memcpy(&byte, &new_word, sizeof(uint8_t));

    return byte;

}

//////////////////////////////////////////////// AES procces functions ////////////////////////////////////////////////

void shift_lines(Block_128* block, int inverse){
    uint8_t aux_line[4];
    int mult;
    int mult_inverse;
    int offset;

    if (inverse == 1 ){
        mult_inverse = 1;
        mult = 0;
    }
    else{
        mult_inverse = 0;
        mult = 1;
    }

    for (int line = 1; line < 4; line++){
        for (int col=0; col < 4; col++){
            offset = (col+line)%4;     

            aux_line[col*mult + offset*mult_inverse] = block->bytes[col*mult_inverse + mult*offset][line];
        }
        
        for (int c=0; c < 4; c++){
            block->bytes[c][line] = aux_line[c];
        }
    }

}



void substitute_s_box(Block_128* block, int inverse){
    uint8_t byte;
    uint8_t f4b;
    uint8_t l4b;

    const uint8_t (*box)[16];

    if(inverse == 1){
        box=s_box_inverse;
    }
    else{
        box=s_box;
    }

    for (int line = 0; line< 4; line++){
        for (int collum = 0; collum< 4; collum++){
            

            byte = block->bytes[line][collum];
            f4b = first_4_bits(byte);
            l4b = last_4_bits(byte);

            block->bytes[line][collum] = box[f4b][l4b];  


        }
    }

    return;
}







uint32_t rot_word(uint32_t word){

    uint8_t byte_array[4];
    uint32_t new_word = 0;

    for( int i = 0; i<4 ;i++){
        byte_array[i] = byte_selector(word,(i+3)%4) ; // rotaciona 3 bytes pra frente
    }

   
    memcpy(&new_word, byte_array, 4*sizeof(uint8_t));

    return new_word;
}


uint32_t sub_word(uint32_t word){

    uint8_t byte_array[4];
    uint32_t new_word = 0;

    uint8_t byte;
    uint8_t f4b;
    uint8_t l4b;

    for (int i = 0; i< 4; i++){       
        byte = byte_selector(word,i);
        f4b = first_4_bits(byte);
        l4b = last_4_bits(byte);
        byte_array[i] = s_box[f4b][l4b];
    }

    memcpy(&new_word, byte_array, 4*sizeof(uint8_t));

    return new_word;
}



uint8_t galois_mult(uint8_t byte, uint8_t mult){
    
    if (mult == 1){
        return byte;
    }
    if(byte ==  1){
        return mult;
    }
    if(byte ==  0){
        return 0;
    }

    uint8_t l_byte_f4b; 
    uint8_t l_byte_l4b;

    uint8_t l_mult_f4b;
    uint8_t l_mult_l4b;

    uint8_t s_byte_f4b;
    uint8_t s_byte_l4b;

    uint8_t result_byte;

    unsigned int sum;

    l_byte_f4b = first_4_bits(byte);
    l_byte_l4b = last_4_bits (byte);
    
    l_mult_f4b = first_4_bits(mult);
    l_mult_l4b = last_4_bits (mult);
    byte = galois_l[l_byte_f4b][l_byte_l4b];
    mult = galois_l[l_mult_f4b][l_mult_l4b];


    sum = (byte+mult)>0xFF ? (byte+mult-0xFF):(byte+mult);

    s_byte_f4b = first_4_bits((uint8_t)sum);
    s_byte_l4b = last_4_bits ((uint8_t)sum);

    result_byte = galois_e[s_byte_f4b][s_byte_l4b];
   

    
    return result_byte;
}


void mix_collum(Block_128* block,int inverse)
{
    Block_128 new_block;
    const uint8_t (* matrix)[4];

    

    if(inverse == 1){
        matrix = mult_matrix_inverse;
    }
    else{
        matrix = mult_matrix;
    }

        for (int collum = 0; collum< 4; collum++){
            for (int line = 0; line< 4; line++){
                
                
                new_block.bytes[collum][line] =  galois_mult(block->bytes[collum][0], matrix[line][0])  
                                                ^galois_mult(block->bytes[collum][1], matrix[line][1])  
                                                ^galois_mult(block->bytes[collum][2], matrix[line][2])  
                                                ^galois_mult(block->bytes[collum][3], matrix[line][3]);

            }
        }

    memcpy(block,&new_block,sizeof(Block_128));
    
    return ;
}


///////////////////////////////////////////////////// key functions /////////////////////////////////////////////////////

void key_expansion(uint32_t key[4],uint32_t expanded_key[44]){

    int rounds_number = 44;   
    int round = 0;

    int loop_size = 4;

    memcpy(expanded_key,key,4*sizeof(uint32_t)); // Rounds de 1 a 4


    for(round = 4; round<rounds_number;round++){
        
        if(round%loop_size == 0){
            expanded_key[round] =  sub_word( rot_word(expanded_key[round - 1]) )^ RCON[((round/4) - 1)] ^ expanded_key[round - 4];
        }
        else
        {
            expanded_key[round] = expanded_key[round - 1] ^ expanded_key[round - 4] ;
        }
        
    }

    print_expanded_key(expanded_key);


    return ;
}

void add_round_key(Block_128* block, uint32_t round_key[4]){
    
    uint8_t key_byte;

    for (int i = 0; i<4;i++){
        for(int j = 0; j<4; j++){
            

            key_byte = byte_selector(round_key[i],(3-j));
            block->bytes[i][j] = block->bytes[i][j] ^ key_byte ;

        }

    }

}


///////////////////////////////////////////// encrypt/decrypt functions /////////////////////////////////////////////

void aes_encrypt(uint32_t key[4],Block_Array block_array_stc){

    
    uint32_t expanded_key[44];   // Chave expandida de 176 bytes dividida em 44 blocos de 4 bytes
    uint32_t round_key[4];

    Block_128* block_array;
    Block_128* block_ptr;
    Block_128  block;
    int array_size;

    key_expansion(key,expanded_key);
    block_array = block_array_stc.first;
    array_size  = block_array_stc.size;

    for (int block_counter = 0; block_counter< array_size; block_counter++){

        print_block_array(block_array_stc,"Initial block\n");

        block_ptr = &block_array[block_counter];

        // Round 0 
        memcpy(&round_key,&expanded_key[0], 4*sizeof(uint32_t));
    
        
        add_round_key(block_ptr,round_key);
        print_key(round_key,"Round key");
        print_block_array(block_array_stc,"Add key (Round 0) \n");

        for (int round = 1; round < 10; round++){
            memcpy(&round_key,&expanded_key[round*4], 4*sizeof(uint32_t));
            
            print_round(round);

            print_block_array(block_array_stc,"Initial block: \n");

            substitute_s_box(block_ptr,0);
            print_block_array(block_array_stc,"s-box: \n");

            shift_lines     (block_ptr,0);
            print_block_array(block_array_stc,"shift lines: \n");

            mix_collum      (block_ptr,0); 
            print_block_array(block_array_stc,"mix-collumns: \n");

            add_round_key   (block_ptr,round_key);

            print_key(round_key,"Round key");
            print_block_array(block_array_stc,"Add key \n");
            
            
        }

        // Round 10
            print_round(10);
            memcpy(&round_key,&expanded_key[10*4], 4*sizeof(uint32_t));

            substitute_s_box(block_ptr,0);
            print_block_array(block_array_stc,"s-box: \n");

            shift_lines     (block_ptr,0);
            print_block_array(block_array_stc,"shift lines: \n");
            
            add_round_key   (block_ptr,round_key);
            print_key(round_key,"Round key");
            print_block_array(block_array_stc,"Add key\n");

    
    }
}

void aes_decrypt(uint32_t key[4],Block_Array block_array_stc){

    
    uint32_t expanded_key[44];   // Chave expandida de 176 bytes dividida em 44 blocos de 4 bytes
    uint32_t round_key[4];

    Block_128* block_array;
    Block_128* block_ptr;
    Block_128  block;
    int array_size;

    key_expansion(key,expanded_key);
    block_array = block_array_stc.first;
    array_size  = block_array_stc.size;

    for (int block_counter = 0; block_counter< array_size; block_counter++){

        block_ptr = &block_array[block_counter];

        // Round 0 
        memcpy(&round_key,&expanded_key[10*4], 4*sizeof(uint32_t));
    
        
        add_round_key(block_ptr,round_key);
        print_key(round_key,"Round key");
        print_block_array(block_array_stc,"Add key (Round 10) \n");

        for (int round = 9; round >= 1; round--){
            memcpy(&round_key,&expanded_key[round*4], 4*sizeof(uint32_t));
            
            print_round(round);

            print_block_array(block_array_stc,"Initial block: \n");

            shift_lines     (block_ptr,1); // INVERSE
            print_block_array(block_array_stc,"shift lines: \n");

            substitute_s_box(block_ptr,1); // INVERSE
            print_block_array(block_array_stc,"s-box: \n");

            print_key(round_key,"Round key");
            add_round_key   (block_ptr,round_key);
            print_block_array(block_array_stc,"Add key \n");
            
            mix_collum      (block_ptr,1);  // INVERSE
            print_block_array(block_array_stc,"mix-collumns: \n");


            
            
        }

        // Round 10
            print_round(0);
            memcpy(&round_key,&expanded_key[0], 4*sizeof(uint32_t));

            shift_lines     (block_ptr,1); // INVERSE
            print_block_array(block_array_stc,"shift lines: \n");

            substitute_s_box(block_ptr,1); // INVERSE
            print_block_array(block_array_stc,"s-box: \n");

            
            add_round_key   (block_ptr,round_key);
            print_key(round_key,"Round key");
            print_block_array(block_array_stc,"Add key\n");

    
    }
}



int main(int argc, char *argv[]){
    clock_t start_time = clock();

    // Variables
    uint32_t key[4];                // chave de 128 bits/16 bytes dividida em 4 blocos de 4 bytes
    Block_Array block_array_stc;
    printf_flag = 0;

    

    if ( argc<4){    
        mensagem_inst();
        return 0;
    }

    if(argc>=5){
        char* flag    = argv[4];
        char* verbose = "-v";
        if(strcmp(flag,verbose)==0){
            printf_flag = 1;
            printf("Verbose mode:\n\n");
        }
    }

    int   mode             = argv[1][0]; 
    char* input_file_name  = argv[2]; 
    char* key_file_name    = argv[3];

    block_array_stc  = file_to_block_array(input_file_name);
    file_to_hex(key_file_name,key);

    if (block_array_stc.size == 0){
        printf("Input vazio");
        return 1;
    }


    switch (mode)
    {
    case 'e':

        print_key(key,"key");

        aes_encrypt(key,block_array_stc);
        print_block_array(block_array_stc,"Final block\n");
    
        block_to_file(input_file_name,block_array_stc,0);

        break;
    
    case 'd':
        print_key(key,"key");

        aes_decrypt(key,block_array_stc);

        print_block_array(block_array_stc,"Final block\n");
    
        block_to_file(input_file_name,block_array_stc,1);

        break;
    
    default:
        mensagem_inst();
        break;
    }


    



    free(block_array_stc.first);
    
    clock_t stop_time = clock();
    double time_spent = (double)(stop_time - start_time) / CLOCKS_PER_SEC;

    printf("Execução: %f ms\n", time_spent*1000);
	return 0;
}
