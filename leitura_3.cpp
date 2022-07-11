#include<stdio.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <iostream>
#include <cstring>
#include <cctype>
#include <sstream>
#include <vector>
#include <map>
#include <string>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509_vfy.h>

//para a bibliotaca lcrypto
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

using namespace std;

void init_lcrypto(){
     //para a biblioteca lcrypto
   /* Load the human readable error strings for libcrypto */
  ERR_load_crypto_strings();

  /* Load all digest and cipher algorithms */
  OpenSSL_add_all_algorithms();

  /* Load config file, and other important initialisation */
  OPENSSL_config(NULL);

  /* ... Do some crypto stuff here ... */

  /* Clean up */

  /* Removes all digests and ciphers */
  EVP_cleanup();

  /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
  CRYPTO_cleanup_all_ex_data();

  /* Remove error strings */
  ERR_free_strings();

}

void leitura_certificado(string &nome){
  FILE * arquivo;
  X509 *x;
  long long unsigned int tamanho;
  unsigned char * buffer;
  const unsigned char *dadosCertificado;
  char *resultado;
  int result;
  
 
  //cout<<"Digite o nome do arquivo com a extensão: "<<endl;
  //cin>>nome;
  //nome.c_str()
  arquivo = fopen (nome.c_str(), "rb" );
  if (arquivo==NULL) {fputs ("File error",stderr); exit (1);}

  //tamanho do arquivo
  fseek (arquivo , 0 , SEEK_END);
  tamanho = ftell (arquivo);
  //cout<<tamanho<<endl;
  rewind (arquivo);

  //alocação dinâmica de memória para o buffer
  buffer = (unsigned char*) malloc (sizeof(unsigned char)*(tamanho+1));
  if (buffer == NULL) {fputs ("Memory error",stderr); exit (2);}

  //copiar os dados para o buffer
  //função fread retorna o  tamanho do buffer
  result = fread (buffer,1,tamanho,arquivo);
  //cout<<result<<endl;
  //cout<<buffer<<endl;
  //tamanho do arquivo e tamanho do buffer devem ser iguais
  if (result != tamanho) {fputs ("Reading error",stderr); exit (3);}

  //dados do buffer redirecionado para o endereço de memória do ponteiro
  dadosCertificado= buffer;
  x = d2i_X509(NULL, &dadosCertificado,result);
  if (x == NULL){fputs ("Reading error",stderr); exit (4);}
      /* error */
  const X509_NAME* subject = X509_get_subject_name(x);
  if (subject == NULL){fputs ("Reading error",stderr); exit (5);}
      /* error */
  
  resultado= (char*) malloc (sizeof(char)*(result+1));
  if (resultado == NULL) {fputs ("Memory error",stderr); exit (6);}
  //impressão do subject representação ASCII
  resultado = X509_NAME_oneline(subject,(char *)buffer,result);
  cout<<"impressão do subject representação ASCII"<<endl;
  cout<<resultado<<endl;
  
  fclose (arquivo);
  free (buffer);

}


int main () {
    string nome_1 ="certificado-verisign.cer";
    string nome_2 ="certificado-ac-raiz-bry-v3.der";


    init_lcrypto();
    leitura_certificado(nome_1);
    leitura_certificado(nome_2);

  
  
  return 0;
}
