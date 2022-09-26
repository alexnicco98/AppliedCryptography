#ifndef CRYPTO_FUNCTIONS_H
#define CRYPTO_FUNCTIONS_H

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <unistd.h>
#include <openssl/bio.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/dh.h>
#include "openssl/bn.h"
#include <utility.h>

using std::cout;
using std::endl;
using std::stringstream;
using std::vector;
using std::string;

/* funzione usata dal client per mandare un nonce random insieme al proprio USERNAME
    -> restituisce il nonce mandato
*/
int send_random_nonce(long sock, string username);

/* funzione usata dal server per leggere il nonce e lo USERNAME del client
    -> restituisce lo username del client e salva nella variabile nonce quello letto
*/
string read_nonce(long sock, int* nonce);

/* funzione usata dal client per leggere il fattore Ys ed il certificato del server
   -> restituisce la chiave effimera se la verifica del certificato e della firma è andata bene,
      salva il nonce del server appena letto in nonceS
   -> NULL altrimenti
 */
EVP_PKEY* read_epk_server(long sock, int nonceC, int *nonceS);

/* funzione usata dal server per inviare il fattore Ys ed il certificato del server
    -> restituisce true se è andato tutto bene
    -> false altrimenti
*/
bool send_epk_server(long sock, EVP_PKEY* ephemeral_pub_key, int nonceC, int *nonceS, EVP_PKEY *server_privKey);

/* funzione usata dal client per inviare il fattore Yc
    -> restituisce true se è andato tutto bene
    -> false altrimenti
*/
bool send_epk_client(long sock, EVP_PKEY* ephemeral_pub_key, int nonce, EVP_PKEY *client_privKey);

/* funzione usata dal server per leggere il fattore Yc del client
   -> restituisce la chiave effimera se la verifica della firma è andata bene
   -> NULL altrimenti
 */
EVP_PKEY* read_epk_client(long sock, int nonceS, EVP_PKEY *public_key);

/* funzione usata dal client per notificare al server l'intenzione di terminare la chat
    -> restituisce true se è andato tutto bene
    -> false altrimenti
*/
bool send_quit_chat(long sock, unsigned char* session_key, unsigned int* counter);

/* funzione usata dal client per inoltrare al server il messaggio (chat) del mittente
    -> restituisce 0 se è andato tutto bene
    -> -1 altrimenti
*/
int send_in_chat(thread_args_t *thread_arg, string plaintext);

/* funzione usata dal client (colui che manda la richiesta di chat) per creare la chiave di sessione con il client destinatario
    -> restituisce 1 se è andato tutto bene
*/
int create_session_key_from_client1(long sock, unsigned char* session_key, unsigned int* count_client_server, unsigned int* count_server_client ,char* username, unsigned char *pk, int pk_len, thread_args_t *thread_arg, EVP_PKEY* priv_key);

/* funzione usata dal client (colui che riceve la richiesta di chat) per creare la chiave di sessione con il client destinatario
    -> restituisce 1 se è andato tutto bene
*/
int create_session_key_from_client2(long sock, unsigned char* session_key, unsigned int* count_client_server, unsigned int* count_server_client ,char* username, unsigned char *pk, int pk_len, thread_args_t *thread_arg, EVP_PKEY* priv_key);


#endif
