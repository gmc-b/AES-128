# AES-128 bits
A aplicação implementa a criptografia pelo algorítmo AES com chave de 128 bits. O programa irá realizar a leitura de um arquivo de input e um de chave. Ele retorna um novo arquivo com o prefixo "encrypted"/"decrypted" + nome do arquivo de input original. 


## Plataforma utilizada
20.04.2 LTS (Focal Fossa) (WSL)


## Funções:
- e : Criptografa um arquivo de input com a chave no arquivo de chave
- d : Descriptografa um arquivo de input com a chave no arquivo de chave

## Opcionais:
- É possível utilizar como último argumento "-v" para ativar o modo verboso, de maneira que todas as tranformações em todas as etapas serão exibidas no terminal.

## Compilação e Execução
Para a compilação é necessário ter os arquivos main.c
source.c e header.h em uma mesmo diretório.

Comandos:
```
gcc -c source.c
```
```
gcc main.c source.o -lm
```

### Execução Linux:
```
./a.out <modo> <nome_arquivo_entrada> <nome_arquivo_chave> <parametro opcional>
```
### Execução Windows:
```
./a.exe <modo> <nome_arquivo_entrada> <nome_arquivo_chave> <parametro opcional>
```

substitua <modo> por "e", "d". <br>
Digite os parâmetros sem <>. <br>

### Exemplo:
1. Criptografando e descriptografando arquivos no modo padrão: <br>
Em uma pasta com os arquivos example_input.txt e example_key.txt 

```
gcc -c source.c

gcc main.c source.o -lm

./a.out e example_input.txt example_key.txt

cat encrypted_example_input.txt

./a.out d encrypted_example_input.txt example_key.txt

cat decrypted_encrypted_example_input.txt

```

2. Criptografando e descriptografando arquivos no modo verboso: <br>
Em uma pasta com os arquivos example_input.txt e example_key.txt 

```
gcc -c source.c

gcc main.c source.o -lm

./a.out e example_input.txt example_key.txt -v

cat encrypted_example_input.txt

./a.out d encrypted_example_input.txt example_key.txt -v

cat decrypted_encrypted_example_input.txt

```

## Bibliotecas
- <stdio.h>
- <stdlib.h>
- <math.h>
- <time.h>
- <ctype.h>
- <string.h>
- <stdint.h>
- <limits.h>
- <float.h>





