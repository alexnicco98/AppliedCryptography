#ifndef UTILITY_H
#define UTILITY_H

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
#include "openssl/bn.h"
#include <openssl/dh.h>

#include <signal.h>
#define BUFSIZE 4096           /* massima grandezza del payload */

using std::string;

/* argomenti da passare al thread di lettura */
typedef struct thread_arg_c
{
    char key[BUFSIZE];               /* chiave di sessione tra client e server */
    char key_with_client[BUFSIZE];   /* chiave di sessione tra client e client */
    unsigned char *client_to_chat;           /* nome del client che vuole chattare */
    unsigned int counter;             /* counter tra server e client */
    unsigned int counter_C;           /* counter tra client e client */
    int ret;                          /* int per controllare che cosa è successo all'interno della funzione */
    int key_len;                      /* lunghezza chiavi di sessione */
    int socket;                      /* socket */


} thread_args_t;

/* funzione per stampa di DEBUG*/
int handleErrors(string msg);

/* funzione per convertire un int in un unsigned char* */
void int_to_byte(int nonce, unsigned char *c);

/* funzione per convertire da unsigned int in unsigned char* */
void unsigned_int_to_byte(unsigned int num, unsigned char* c);

/* funzione usata per verificare un certificato
        -> restituisce 1 in caso di successo
        -> -1 se il certificato non è valido */
 int certificate_verification(char *cert_CA_path, char *crl_CA_path, X509* cert);

 /* funzione per trasformare una chiave pubblica dal formato EVP_PKEY* in bytes
        -> restituisce un buffer di bytes che rappresenta la chiave pubblica */
unsigned char* publicKey_to_byte(EVP_PKEY *pk, int* pk_len);

/* genera la chiave effimera pubblica e quella privata di Diffie-Hellman*/
void generate_ek(EVP_PKEY** eprivK, EVP_PKEY** epubK);

/* calcola il segreto condiviso tra client e server, applica la funzione hash
        -> restituisce la chiave di sessione */
unsigned char* derive_shared_secret(EVP_PKEY *eprivK, EVP_PKEY *peer_pubK, unsigned int *digest_len);

/* funzione per cifrare i messaggi tra client e server facendo uso della chiave
   di sessione generata tramite Diffie Hellman
        -> restituisce la lunghezza del ciphertext se è andato tutto bene
        -> -1 altrimenti */
int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag);

/* funzione per decifrare i messaggi tra client e server facendo uso della chiave
   di sessione generata tramite Diffie Hellman
        -> restituisce la lunghezza del plaintext se è andato tutto bene
        -> -1 altrimenti */
int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext);

/* legge la lista di utenti online
        -> restituisce il buffer contenente la lista di utenti online in bytes
        -> NULL altrimenti */
unsigned char* online_user_list(long sock, unsigned char* key, unsigned int *counter);

/* funzione per leggere la risposta del destinatario alla richiesta di chat
        -> restituisce l'opt corrispondente alla sclta */
char* chat_request_response(long sock, unsigned char *key, unsigned int *counter);

/* funzione per leggere la chiave pubblica mandata del client con cui vogliamo chattare
        -> restituisce lo username a cui corrisponde la chiave pubblica */
unsigned char* read_pub_key(long sock, unsigned char *key, unsigned int *counter, int *public_key_len);

/* funzione usata per leggere un certificato
        -> restituisce un buffer contenente il certificato in bytes */
unsigned char* read_cert(char *cert_path, int* cert_size);

/* funzione per mandare su un socket un certo numero di bytes a partire dal buffer
        -> restituisce il numero di bytes spediti */
int send_bytes(long sock, void *buf, size_t size);

/* funzione per leggere da una socket un certo numero di bytes del buffer
        -> restituisce il numero di bytes letti */
int read_bytes(long sock, void *buf, size_t size);

/* funzione usata dal client per mandare la richiesta della lista di untenti online
        -> restituisce 0 se è andato tutto bene */
int online_user_list_request(long sock, unsigned char* session_key, unsigned int *counter);

/* funzione usata dal client per mandare una richiesta di chat
        -> restituisce 0 se è andato tutto bene */
int send_chat_request(long sock, unsigned char* session_key, unsigned int *counter, char* user_to_send);

/* funzione per notificare al server di inserire il client nella lista degli utenti disponibile per chattare
        -> restituisce 0 se è andato tutto bene
        -> -1 altrimenti */
int wait_chat(long sock, unsigned char* session_key, unsigned int* counter);

/*********************** TODO ******************************/ 

/* funzione usata per leggere la chiave pubblica a partire dal nome del file
        -> restituisce la chiave pubblica in formato EVP_PKEY* */
EVP_PKEY* read_publicKey(char *file);

/* funzione usata per leggere la chiave privata a partire dal nome del file
        -> restituisce la chiave privata in formato EVP_PKEY* */
EVP_PKEY* read_privateKey(char *file);





#endif
