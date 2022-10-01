#include <./Server/server_functions.h>
#include <utility.h>
#include <pthread.h>
#include <iostream>
#include <list>

#define _XOPEN_SOURCE 700
#define BUFSIZE 4096           /* massima grandezza del payload */
#define MAX_CHARS_TO_READ 4095 /* massimo numero di caratteri da leggere da input */
#define HEADER_SESSION_LEN 4
#define OPT_LEN 30
#define TAG_LEN 16
using namespace std;


pthread_mutex_t user_list_mutex = PTHREAD_MUTEX_INITIALIZER;
list<user> user_list;

// restituisce la lista di utenti disponibili per la chat
string list_to_string(char *username){

    string list = "";

    pthread_mutex_lock(&user_list_mutex);
    for(std::list<user>::iterator iter = user_list.begin(); iter != user_list.end(); ++iter){

        if((strcmp((iter->username), username) != 0) && iter->free_to_chat){
            list = list.append(iter->username);
            list = list.append("\n");
        }
    }
    pthread_mutex_unlock(&user_list_mutex);

    return list;
}

// restituisce true se username è disponibile per la chat
bool check_list_name(char* username){
    pthread_mutex_lock(&user_list_mutex);

    for(std::list<user>::iterator iter = user_list.begin(); iter != user_list.end(); ++iter){
        if((strcmp((iter->username), username) == 0)){
            if(iter->free_to_chat){
                pthread_mutex_unlock(&user_list_mutex);
                return true;
            }
        }
    }

    pthread_mutex_unlock(&user_list_mutex);
    return false;
}

/* imposta il flag free_to_chat di username a true e restituisco 0 se è andato tutto bene,
   1 altrimenti*/
int wait_chat(char* username){
    pthread_mutex_lock(&user_list_mutex);

    for(std::list<user>::iterator iter = user_list.begin(); iter != user_list.end(); ++iter){
        if((strcmp((iter->username), username) == 0)){
            iter->free_to_chat = true;
            pthread_mutex_unlock(&user_list_mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&user_list_mutex);

    return 1;
}

/* imposta il flag free_to_chat di username a false e restituisco 0 se è andato tutto bene,
   1 altrimenti*/
int stop_wait_chat(char* username){
    pthread_mutex_lock(&user_list_mutex);

    for(std::list<user>::iterator iter = user_list.begin(); iter != user_list.end(); ++iter){
        if((strcmp((iter->username), username) == 0)){
            iter->free_to_chat = false;
            pthread_mutex_unlock(&user_list_mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&user_list_mutex);

    return 1;
}

// aggiunge la struttura user del nuovo utente alla Lista
// restituisce 0 se è andato tutto bene
int add_user_to_list(user *utente){
    pthread_mutex_lock(&user_list_mutex);
    user_list.push_back(*utente);
    pthread_mutex_unlock(&user_list_mutex);

    return 0;
}

// rimuove la struttura user dell'utente dalla Lista
// restituisce 0 se è andato tutto bene, 1 altrimenti
int remove_user_to_list(user *utente){
    pthread_mutex_lock(&user_list_mutex);
    std::list<user>::iterator iter = user_list.begin();

    while( iter != user_list.end() ){
        if(user_list.size() > 0 ){
            if((strcmp((iter->username), utente->username) == 0)){
                iter->busy = false;
                iter->msg_received_full = false;
                iter->handler_pt = 0;
                memcpy(utente->username, "", BUFSIZE);
                iter->opt.clear();
                memcpy(utente->IP_client, "", INET_ADDRSTRLEN);
                memcpy(utente->msg_received, "", BUFSIZE);
                iter->socket = -1;
                if(iter->session_key != NULL){
                    memset(iter->session_key, '\0', iter->key_len);
                    free(iter->session_key);
                }
                iter->key_len = 0;
                iter->count_client_server = 0;
                iter->count_server_client = 0;
                user_list.erase(iter);
                pthread_mutex_unlock(&user_list_mutex);
                return 0;
            }
            else
                ++iter;
        }
        else
            break;

    }

    pthread_mutex_unlock(&user_list_mutex);
    return 1;
}

// restituisce la chiave di sessione tra client e server
unsigned char* get_session_key(char* client){

    pthread_mutex_lock(&user_list_mutex);

    for(std::list<user>::iterator iter = user_list.begin(); iter != user_list.end(); ++iter){
        if((memcmp((iter->username), client, sizeof(client)) == 0)){
            pthread_mutex_unlock(&user_list_mutex);
            return iter->session_key;
        }

    }
    pthread_mutex_unlock(&user_list_mutex);

    return NULL;
}

// restituisce la socket del client se è andato tutto bene, -1 altrimenti
int get_socket(char* client){

    pthread_mutex_lock(&user_list_mutex);
    for(std::list<user>::iterator iter = user_list.begin(); iter != user_list.end(); ++iter){
        if((memcmp((iter->username), client, sizeof(client)) == 0)){
            pthread_mutex_unlock(&user_list_mutex);
            return iter->socket;
        }

    }
    pthread_mutex_unlock(&user_list_mutex);

    return -1;
}

// restituisce il counter dei messaggi dal server al client
// -1 altrimenti
unsigned int get_counter_sc(char* client){

    pthread_mutex_lock(&user_list_mutex);
    for(std::list<user>::iterator iter = user_list.begin(); iter != user_list.end(); ++iter){
        if(strcmp((iter->username), client) == 0) {
            pthread_mutex_unlock(&user_list_mutex);
            return iter->count_server_client;
        }
    }
    pthread_mutex_unlock(&user_list_mutex);

    return -1;

}

// restituisce il counter dei messaggi dal client al server
// -1 altrimenti
unsigned int get_counter_cs(char* client){

    pthread_mutex_lock(&user_list_mutex);
    for(std::list<user>::iterator iter = user_list.begin(); iter != user_list.end(); ++iter){
        if(strcmp((iter->username), client) == 0) {
            pthread_mutex_unlock(&user_list_mutex);
            return iter->count_client_server;
        }
    }
    pthread_mutex_unlock(&user_list_mutex);

    return -1;
}

/* incrementa il counter dei messaggi dal client al server
        -> restituisce true se è andato tutto bene
        -> false altrimenti */
bool add_counter_cs(char* client){

    pthread_mutex_lock(&user_list_mutex);
    for(std::list<user>::iterator iter = user_list.begin(); iter != user_list.end(); ++iter){
        if(strcmp((iter->username), client) == 0) {
            iter->count_client_server = iter->count_client_server + 1;
            pthread_mutex_unlock(&user_list_mutex);
            return true;
        }
    }
    pthread_mutex_unlock(&user_list_mutex);

    return false;
}

/* incrementa il counter dei messaggi dal server al client
        -> restituisce true se è andato tutto bene
        -> false altrimenti */
bool add_counter_sc(char* client){

    pthread_mutex_lock(&user_list_mutex);
    for(std::list<user>::iterator iter = user_list.begin(); iter != user_list.end(); ++iter){
        if(strcmp((iter->username), client) == 0) {
            iter->count_server_client = iter->count_server_client + 1;
            pthread_mutex_unlock(&user_list_mutex);
            return true;
        }
    }
    pthread_mutex_unlock(&user_list_mutex);

    return false;
}

int send_user_list(char *user, long sock){

    int error = 0;
    string list = list_to_string(user);

    if(strcmp(list.c_str(), "") == 0)
        list = "Lista Vuota\n";

    unsigned char* session_key = get_session_key(user);
    if(session_key == NULL){
        perror("Error in get_session_key");
        return -1;
    }

    int pt_len = strlen(list.c_str());
    unsigned char* pt = (unsigned char*) malloc(sizeof(unsigned char) * pt_len);
    memset(pt, '\0', pt_len);
    if( !pt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    copy(list.begin(), list.end(), pt);

    int iv_len = EVP_CIPHER_iv_length(EVP_aes_256_gcm());
    unsigned char* iv = (unsigned char*)malloc(iv_len);
    // seme OpenSSL PRNG
    RAND_poll();
    RAND_bytes((unsigned char*)&iv[0],iv_len);
    if(iv == NULL){
      return -1;
    }

    int ct_len = pt_len + EVP_CIPHER_block_size(EVP_aes_256_gcm());
    unsigned char* ct = (unsigned char*) malloc(sizeof(unsigned char) * ct_len);
    memset(ct, '\0', ct_len);
    if( !ct){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    int tag_len = TAG_LEN;
    unsigned char* tag = (unsigned char*) malloc(sizeof(unsigned char) * tag_len);
    memset(tag, '\0', tag_len);
    if( !tag){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    // AAD = (msgtype || cont_server_client)
    int aad_len = OPT_LEN + sizeof(int);
    unsigned char* aad = (unsigned char*) malloc(sizeof(unsigned char) * aad_len);
    memset(aad, '\0', aad_len);
    if( !aad){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    unsigned char* counter_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(counter_byte, '\0', sizeof(int));
    if( !counter_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    unsigned int counter = get_counter_sc(user);
    if(counter == -1)
        handleErrors("Error in get_counter_sc");
    unsigned_int_to_byte(counter, counter_byte);

    add_counter_sc(user);

    memcpy(aad, "list", sizeof("list"));
    memcpy(&aad[OPT_LEN], counter_byte, sizeof(int));

    // cifra il plaintext
    ct_len = gcm_encrypt(pt, pt_len, aad, aad_len, session_key, iv, iv_len, ct, tag);
    if(ct_len == -1)
      handleErrors("Error in gcm_encrypt\n");

    int msg_len = HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len + iv_len;
    int payload_len = msg_len - HEADER_SESSION_LEN;

    unsigned char* payload_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(payload_len_byte, '\0', sizeof(int));
    if( !payload_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(payload_len, payload_len_byte);

    unsigned char* ct_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(ct_len_byte, '\0', sizeof(int));
    if( !ct_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(ct_len, ct_len_byte);

    unsigned char* aad_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(aad_len_byte, '\0', sizeof(int));
    if( !aad_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(aad_len, aad_len_byte);

    unsigned char* msg =(unsigned char*) malloc(sizeof(unsigned char) * msg_len);
    memset(msg, '\0', msg_len);
    if( !msg){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    memcpy(msg, payload_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN], aad_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int)], aad, aad_len);
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len], ct_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int)], (unsigned char*) ct, ct_len);
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int) + ct_len], (unsigned char*) tag, tag_len);
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len], (unsigned char*) iv, iv_len);

    error = send_bytes(sock, msg, msg_len);
    if(error == -1){
        if(sock != -1)
            close(sock);
        handleErrors("Error on send_bytes");
    }

    free(pt);
    free(iv);
    free(ct);
    free(tag);
    free(counter_byte);
    free(payload_len_byte);
    free(ct_len_byte);
    free(msg);
    free(aad_len_byte);
    free(aad);

    return 0;
}

int quit_chat(char *user){
    int error = 0;

    unsigned char* session_key = get_session_key(user);
    if(session_key == NULL){
        perror("Error in get_session_key");
        return -1;
    }
    long sock = get_socket(user);

    int pt_len = 1;

    unsigned char* pt = (unsigned char*) malloc(sizeof(unsigned char) * pt_len);
    memset(pt, '\0', pt_len);
    if( !pt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
	memcpy(pt, "d", pt_len);

    int iv_len = EVP_CIPHER_iv_length(EVP_aes_256_gcm());
    unsigned char* iv = (unsigned char*)malloc(iv_len);
    // seme OpenSSL PRNG
    RAND_poll();
    RAND_bytes((unsigned char*)&iv[0],iv_len);
    if(iv == NULL){
      return -1;
    }

    int ct_len = pt_len + EVP_CIPHER_block_size(EVP_aes_256_gcm());
    unsigned char* ct = (unsigned char*) malloc(sizeof(unsigned char) * ct_len);
    memset(ct, '\0', ct_len);
    if( !ct){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    int tag_len = TAG_LEN;
    unsigned char* tag = (unsigned char*) malloc(sizeof(unsigned char) * tag_len);
    memset(tag, '\0', tag_len);
    if( !tag){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    // AAD = (msgtype || cont_server_client)
    int aad_len = OPT_LEN + sizeof(int);
    unsigned char* aad = (unsigned char*) malloc(sizeof(unsigned char) * aad_len);
    memset(aad, '\0', aad_len);
    if( !aad){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    unsigned char* counter_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(counter_byte, '\0', sizeof(int));
    if( !counter_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    unsigned int counter = get_counter_sc(user);
    if(counter == -1)
        handleErrors("Error in get_counter_sc");
    unsigned_int_to_byte(counter, counter_byte);

    add_counter_sc(user);

    memcpy(aad, "chat_quit", sizeof("chat_quit"));
    memcpy(&aad[OPT_LEN], counter_byte, sizeof(int));

    // cifra il plaintext
    ct_len = gcm_encrypt(pt, pt_len, aad, aad_len, session_key, iv, iv_len, ct, tag);
    if(ct_len == -1)
      handleErrors("Error in gcm_encrypt\n");

    int msg_len = HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len + iv_len;
    int payload_len = msg_len - HEADER_SESSION_LEN;

    unsigned char* payload_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(payload_len_byte, '\0', sizeof(int));
    if( !payload_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(payload_len, payload_len_byte);

    unsigned char* ct_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(ct_len_byte, '\0', sizeof(int));
    if( !ct_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(ct_len, ct_len_byte);

    unsigned char* aad_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(aad_len_byte, '\0', sizeof(int));
    if( !aad_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(aad_len, aad_len_byte);

    unsigned char* msg =(unsigned char*) malloc(sizeof(unsigned char) * msg_len);
    memset(msg, '\0', msg_len);
    if( !msg){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    memcpy(msg, payload_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN], aad_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int)], aad, aad_len);
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len], ct_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int)], (unsigned char*) ct, ct_len);
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int) + ct_len], (unsigned char*) tag, tag_len);
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len], (unsigned char*) iv, iv_len);

    error = send_bytes(sock, msg, msg_len);
    if(error == -1){
        if(sock != -1)
            close(sock);
        handleErrors("Error on send_bytes");
    }

    free(pt);
    free(iv);
    free(ct);
    free(tag);
    free(counter_byte);
    free(payload_len_byte);
    free(ct_len_byte);
    free(msg);
    free(aad_len_byte);
    free(aad);

    return 0;
}

int negative_chat_response(char *user){
    int error = 0;

    unsigned char* session_key = get_session_key(user);
    if(session_key == NULL){
        perror("Error in get_session_key");
        return -1;
    }
    long sock = get_socket(user);

    int pt_len = 1;

    unsigned char* pt = (unsigned char*) malloc(sizeof(unsigned char) * pt_len);
    memset(pt, '\0', pt_len);
    if( !pt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
	memcpy(pt, "d", pt_len);

    int iv_len = EVP_CIPHER_iv_length(EVP_aes_256_gcm());
    unsigned char* iv = (unsigned char*)malloc(iv_len);
    // seme OpenSSL PRNG
    RAND_poll();
    RAND_bytes((unsigned char*)&iv[0],iv_len);
    if(iv == NULL){
      return -1;
    }

    int ct_len = pt_len + EVP_CIPHER_block_size(EVP_aes_256_gcm());
    unsigned char* ct = (unsigned char*) malloc(sizeof(unsigned char) * ct_len);
    memset(ct, '\0', ct_len);
    if( !ct){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    int tag_len = TAG_LEN;
    unsigned char* tag = (unsigned char*) malloc(sizeof(unsigned char) * tag_len);
    memset(tag, '\0', tag_len);
    if( !tag){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    // AAD = (msgtype || cont_server_client)
    int aad_len = OPT_LEN + sizeof(int);
    unsigned char* aad = (unsigned char*) malloc(sizeof(unsigned char) * aad_len);
    memset(aad, '\0', aad_len);
    if( !aad){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    unsigned char* counter_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(counter_byte, '\0', sizeof(int));
    if( !counter_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    unsigned int counter = get_counter_sc(user);
    if(counter == -1)
        handleErrors("Error in get_counter_sc");
    unsigned_int_to_byte(counter, counter_byte);

    add_counter_sc(user);

    memcpy(aad, "nochat", sizeof("nochat"));
    memcpy(&aad[OPT_LEN], counter_byte, sizeof(int));

    // cifra il plaintext
    ct_len = gcm_encrypt(pt, pt_len, aad, aad_len, session_key, iv, iv_len, ct, tag);
    if(ct_len == -1)
      handleErrors("Error in gcm_encrypt\n");

    int msg_len = HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len + iv_len;
    int payload_len = msg_len - HEADER_SESSION_LEN;

    unsigned char* payload_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(payload_len_byte, '\0', sizeof(int));
    if( !payload_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(payload_len, payload_len_byte);

    unsigned char* ct_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(ct_len_byte, '\0', sizeof(int));
    if( !ct_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(ct_len, ct_len_byte);

    unsigned char* aad_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(aad_len_byte, '\0', sizeof(int));
    if( !aad_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(aad_len, aad_len_byte);

    unsigned char* msg =(unsigned char*) malloc(sizeof(unsigned char) * msg_len);
    memset(msg, '\0', msg_len);
    if( !msg){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    memcpy(msg, payload_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN], aad_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int)], aad, aad_len);
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len], ct_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int)], (unsigned char*) ct, ct_len);
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int) + ct_len], (unsigned char*) tag, tag_len);
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len], (unsigned char*) iv, iv_len);

    error = send_bytes(sock, msg, msg_len);
    if(error == -1){
        if(sock != -1)
            close(sock);
        handleErrors("Error on send_bytes");
    }

    free(pt);
    free(iv);
    free(ct);
    free(tag);
    free(counter_byte);
    free(payload_len_byte);
    free(ct_len_byte);
    free(msg);
    free(aad_len_byte);
    free(aad);

    return 0;
}

int positive_chat_response(char *user){
    int error = 0;

    unsigned char* session_key = get_session_key(user);
    if(session_key == NULL){
        perror("Error in get_session_key");
        return -1;
    }
    long sock = get_socket(user);
    int pt_len = 1;

    unsigned char* pt = (unsigned char*) malloc(sizeof(unsigned char) * pt_len);
    memset(pt, '\0', pt_len);
    if( !pt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
	memcpy(pt, "d", pt_len);

    int iv_len = EVP_CIPHER_iv_length(EVP_aes_256_gcm());
    unsigned char* iv = (unsigned char*)malloc(iv_len);
    // seme OpenSSL PRNG
    RAND_poll();
    RAND_bytes((unsigned char*)&iv[0],iv_len);
    if(iv == NULL){
      return -1;
    }

    int ct_len = pt_len + EVP_CIPHER_block_size(EVP_aes_256_gcm());
    unsigned char* ct = (unsigned char*) malloc(sizeof(unsigned char) * ct_len);
    memset(ct, '\0', ct_len);
    if( !ct){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    int tag_len = TAG_LEN;
    unsigned char* tag = (unsigned char*) malloc(sizeof(unsigned char) * tag_len);
    memset(tag, '\0', tag_len);
    if( !tag){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    // AAD = (msgtype || cont_server_client)
    int aad_len = OPT_LEN + sizeof(int);
    unsigned char* aad = (unsigned char*) malloc(sizeof(unsigned char) * aad_len);
    memset(aad, '\0', aad_len);
    if( !aad){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    unsigned char* counter_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(counter_byte, '\0', sizeof(int));
    if( !counter_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    unsigned int counter = get_counter_sc(user);
    if(counter == -1)
        handleErrors("Error in get_counter_sc");
    unsigned_int_to_byte(counter, counter_byte);

    add_counter_sc(user);

    memcpy(aad, "yeschat", sizeof("yeschat"));
    memcpy(&aad[OPT_LEN], counter_byte, sizeof(int));

    // cifra il plaintext
    ct_len = gcm_encrypt(pt, pt_len, aad, aad_len, session_key, iv, iv_len, ct, tag);
    if(ct_len == -1)
      handleErrors("Error in gcm_encrypt\n");

    int msg_len = HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len + iv_len;
    int payload_len = msg_len - HEADER_SESSION_LEN;

    unsigned char* payload_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(payload_len_byte, '\0', sizeof(int));
    if( !payload_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(payload_len, payload_len_byte);

    unsigned char* ct_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(ct_len_byte, '\0', sizeof(int));
    if( !ct_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(ct_len, ct_len_byte);

    unsigned char* aad_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(aad_len_byte, '\0', sizeof(int));
    if( !aad_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(aad_len, aad_len_byte);

    unsigned char* msg =(unsigned char*) malloc(sizeof(unsigned char) * msg_len);
    memset(msg, '\0', msg_len);
    if( !msg){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    memcpy(msg, payload_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN], aad_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int)], aad, aad_len);
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len], ct_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int)], (unsigned char*) ct, ct_len);
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int) + ct_len], (unsigned char*) tag, tag_len);
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len], (unsigned char*) iv, iv_len);

    error = send_bytes(sock, msg, msg_len);
    if(error == -1){
        if(sock != -1)
            close(sock);
        handleErrors("Error on send_bytes");
    }

    free(pt);
    free(iv);
    free(ct);
    free(tag);
    free(counter_byte);
    free(payload_len_byte);
    free(ct_len_byte);
    free(msg);
    free(aad_len_byte);
    free(aad);

    return 0;
}

/* invia il plaintext e il contenuto dell'aad cambiando solo il counter ad user*/
int send_to_the_other_client(char *user, unsigned char* pt, int pt_len, unsigned char* aad, int aad_len){
    int error = 0;

    int sock = get_socket(user);
    unsigned char* session_key = get_session_key(user);
    if(session_key == NULL){
        perror("Error in get_session_key");
        return -1;
    }

    int iv_len = EVP_CIPHER_iv_length(EVP_aes_256_gcm());
    unsigned char* iv = (unsigned char*)malloc(iv_len);
    // seme OpenSSL PRNG
    RAND_poll();
    RAND_bytes((unsigned char*)&iv[0],iv_len);
    if(iv == NULL){
      return -1;
    }

    int ct_len = pt_len + EVP_CIPHER_block_size(EVP_aes_256_gcm());
    unsigned char* ct = (unsigned char*) malloc(sizeof(unsigned char) * ct_len);
    memset(ct, '\0', ct_len);
    if( !ct){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    int tag_len = TAG_LEN;
    unsigned char* tag = (unsigned char*) malloc(sizeof(unsigned char) * tag_len);
    memset(tag, '\0', tag_len);
    if( !tag){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    unsigned char* counter_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(counter_byte, '\0', sizeof(int));
    if( !counter_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    unsigned int counter = get_counter_sc(user);
    if(counter == -1)
        handleErrors("Error in get_counter_sc");
    unsigned_int_to_byte(counter, counter_byte);

    add_counter_sc(user);

    // cambia il counter contenuto nell'aad, mettendo quello tra il server ed il client
    memcpy(&aad[OPT_LEN], counter_byte, sizeof(int));

    // cifra il plaintext
    ct_len = gcm_encrypt(pt, pt_len, aad, aad_len, session_key, iv, iv_len, ct, tag);
    if(ct_len == -1)
      handleErrors("Error in gcm_encrypt\n");

    int msg_len = HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len + iv_len;
    int payload_len = msg_len - HEADER_SESSION_LEN;

    unsigned char* payload_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(payload_len_byte, '\0', sizeof(int));
    if( !payload_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(payload_len, payload_len_byte);

    unsigned char* ct_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(ct_len_byte, '\0', sizeof(int));
    if( !ct_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(ct_len, ct_len_byte);

    unsigned char* aad_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(aad_len_byte, '\0', sizeof(int));
    if( !aad_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(aad_len, aad_len_byte);

    unsigned char* msg =(unsigned char*) malloc(sizeof(unsigned char) * msg_len);
    memset(msg, '\0', msg_len);
    if( !msg){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    memcpy(msg, payload_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN], aad_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int)], aad, aad_len);
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len], ct_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int)], (unsigned char*) ct, ct_len);
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int) + ct_len], (unsigned char*) tag, tag_len);
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len], (unsigned char*) iv, iv_len);

    fflush(stdout);
    error = send_bytes(sock, msg, msg_len);
    if(error == -1){
        if(sock != -1)
            close(sock);
        handleErrors("Error on send_bytes");
    }

    free(pt);
    free(iv);
    free(ct);
    free(tag);
    free(counter_byte);
    free(payload_len_byte);
    free(ct_len_byte);
    free(msg);
    free(aad_len_byte);

    return 0;
}

string receive_opt_request(long sock, unsigned char* session_key, unsigned int counter, char* user, char* user_to_send){
    int error = 0;

    // legge l'header del messaggio
    unsigned char* receive_buff = (unsigned char*) malloc(sizeof(unsigned char) * HEADER_SESSION_LEN);
    memset(receive_buff, '\0', HEADER_SESSION_LEN);
    if( !receive_buff){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    error = read_bytes(sock, receive_buff, HEADER_SESSION_LEN);
    if(error == -1 || error == 0){
		if(sock != -1)
			close(sock);
            string ret = "closed";
            return ret;
	}

    int payload_dim = 0;
    memcpy(&payload_dim, receive_buff, sizeof(int));

    // legge il campo aad
    unsigned char* aad_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(aad_len_byte, '\0', sizeof(int));
    if( !aad_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    error = read_bytes(sock, aad_len_byte, sizeof(int));
	if(error == -1){
		if(sock != -1)
			close(sock);
		handleErrors("Error in read_bytes");
	}

    int aad_len = 0;
    memcpy(&aad_len, aad_len_byte, sizeof(int));

    unsigned char* aad = (unsigned char*) malloc(sizeof(unsigned char) * aad_len);
    memset(aad, '\0', aad_len);
    if( !aad){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    error = read_bytes(sock, aad, aad_len);
	if(error == -1){
		if(sock != -1)
			close(sock);
		handleErrors("Error in read_bytes");
	}

    // legge il ciphertext
    unsigned char* ct_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(ct_len_byte, '\0', sizeof(int));
    if( !ct_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    error = read_bytes(sock, ct_len_byte, sizeof(int));
	if(error == -1){
		if(sock != -1)
			close(sock);
		handleErrors("Error in read_bytes");
	}

    int ct_len = EVP_CIPHER_block_size(EVP_aes_256_gcm());
    memcpy(&ct_len, ct_len_byte, sizeof(int));

    unsigned char* ct = (unsigned char*) malloc(sizeof(unsigned char) * ct_len);
    memset(ct, '\0', ct_len);
    if( !ct){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    error = read_bytes(sock, ct, ct_len);
	if(error == -1){
		if(sock != -1)
			close(sock);
		handleErrors("Error in read_bytes");
	}

    // Read tag
    unsigned char* tag = (unsigned char*) malloc(sizeof(unsigned char) * TAG_LEN);
    memset(tag, '\0', TAG_LEN);
    if( !tag){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    error = read_bytes(sock, tag, TAG_LEN);
	if(error == -1){
		if(sock != -1)
			close(sock);
		handleErrors("Error in read_bytes");
	}

    // legge l'iv
    int iv_len = EVP_CIPHER_iv_length(EVP_aes_256_gcm());
    unsigned char* iv =  (unsigned char*) malloc(sizeof(unsigned char) * iv_len);
    memset(iv, '\0', iv_len);
    if( !iv){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    error = read_bytes(sock, iv, iv_len);
	if(error == -1){
		if(sock != -1)
			close(sock);
		handleErrors("Error in read_bytes");
	}
	
    add_counter_cs(user);

    // decifra il ciphertext
    unsigned char* pt = (unsigned char*) malloc(sizeof(unsigned char) * (ct_len + 1));
    memset(pt, '\0', (ct_len + 1));
    if( !pt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    int result = gcm_decrypt(ct, ct_len, aad, aad_len, tag, session_key, iv, iv_len, pt);
    if(result <= 0)
      handleErrors("Error in gcm_decrypt");
    printf("Arrivato OPT: %.30s, da parte di %s\n", aad, user);
    if(memcmp("chat", aad, sizeof("chat")) == 0){
        string ret = "";
        ret += "chat";
        // ct_len deve essere <= BUFSIZE
        int space = OPT_LEN - 4;
        ret.insert(4, space, ' ');
        string prova((char*) pt);
        ret += prova;
        free(receive_buff);
        free(ct_len_byte);
        free(ct);
        free(pt);
    	free(tag);
    	free(iv);
        free(aad);
    	free(aad_len_byte);

        return ret;
    }
    if(memcmp("yeschat", aad, sizeof("yeschat")) == 0){
        string ret = "";
        ret += "yeschat";
        // ct_len deve essere <= BUFSIZE
        int space = OPT_LEN - 7;
        ret.insert(7, space, ' ');
        string prova((char*) pt);
        ret += prova;
        free(receive_buff);
        free(ct_len_byte);
        free(ct);
        free(pt);
    	free(tag);
      	free(iv);
        free(aad);
      	free(aad_len_byte);

        return ret;
    }
    if(memcmp("nochat", aad, sizeof("nochat")) == 0){
        string ret = "";
        ret += "nochat";
        // ct_len deve essere <= BUFSIZE
        int space = OPT_LEN - 6;
        ret.insert(6, space, ' ');
        string prova((char*) pt);
        ret += prova;
        free(receive_buff);
        free(ct_len_byte);
        free(ct);
        free(pt);
    	free(tag);
      	free(iv);
        free(aad);
      	free(aad_len_byte);

        return ret;
    }
    if(memcmp("in_chat", aad, sizeof("in_chat")) == 0){
        char user[BUFSIZE];
        memset(user, '\0', BUFSIZE);
        memcpy(user, user_to_send, BUFSIZE);

        if(send_to_the_other_client(user, pt, result, aad, aad_len) != 0)
            handleErrors("Error in send_to_the_other_client");
        string ret = "";
        string prova((char*) aad);
        ret += prova;
        free(receive_buff);
        free(ct_len_byte);
        free(ct);
    	free(tag);
    	free(iv);
    	free(aad_len_byte);

        return ret;
    }

    string ret = "";
    string prova((char*) aad);
    ret += prova;

    free(receive_buff);
	free(ct_len_byte);
    free(ct);
    free(pt);
	free(tag);
	free(iv);
    free(aad);
	free(aad_len_byte);

    return ret;
}

int send_chat_request_server(char* sender_user,char* user_to_send){

    int error = 0;
    int sock = get_socket(user_to_send);

    int pt_len = strlen((const char*)sender_user);
    unsigned char* pt = (unsigned char*) malloc(sizeof(unsigned char) * pt_len);
    memset(pt, '\0', pt_len);
    if( !pt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

	memcpy(pt, sender_user, pt_len);

    int iv_len = EVP_CIPHER_iv_length(EVP_aes_256_gcm());
    unsigned char* iv = (unsigned char*)malloc(iv_len);
    // seme OpenSSL PRNG
    RAND_poll();
    RAND_bytes((unsigned char*)&iv[0],iv_len);
    if(iv == NULL){
      return -1;
    }

    int ct_len = pt_len + EVP_CIPHER_block_size(EVP_aes_256_gcm());
    unsigned char* ct = (unsigned char*) malloc(sizeof(unsigned char) * ct_len);
    memset(ct, '\0', ct_len);
    if( !ct){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    int tag_len = TAG_LEN;
    unsigned char* tag = (unsigned char*) malloc(sizeof(unsigned char) * tag_len);
    memset(tag, '\0', tag_len);
    if( !tag){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    // AAD = (msgtype || cont_server_client)
    int aad_len = OPT_LEN + sizeof(int);
    unsigned char* aad = (unsigned char*) malloc(sizeof(unsigned char) * aad_len);
    memset(aad, '\0', aad_len);
    if( !aad){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    unsigned char* counter_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(counter_byte, '\0', sizeof(int));
    if( !counter_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    unsigned int counter = get_counter_sc(user_to_send);
    unsigned_int_to_byte(counter, counter_byte);
    add_counter_sc(user_to_send);

    unsigned char* opt = (unsigned char*) malloc(sizeof(unsigned char) * OPT_LEN);
    memset(opt, '\0', OPT_LEN);
    if( !opt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    memcpy(opt, "chat", OPT_LEN - 1);
    memcpy(aad, opt, OPT_LEN -1);
    memcpy(&aad[OPT_LEN], counter_byte, sizeof(int));

    unsigned char *session_key = get_session_key(user_to_send);
    // cifra il plaintext
    ct_len = gcm_encrypt(pt, pt_len, aad, aad_len, session_key, iv, iv_len, ct, tag);
    if(ct_len == -1)
      handleErrors("Error in gcm_encrypt\n");

    int msg_len = HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len + iv_len;
    int payload_len = msg_len - HEADER_SESSION_LEN;

    unsigned char* payload_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(payload_len_byte, '\0', sizeof(int));
    if( !payload_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(payload_len, payload_len_byte);

    unsigned char* ct_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(ct_len_byte, '\0', sizeof(int));
    if( !ct_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(ct_len, ct_len_byte);

    unsigned char* aad_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(aad_len_byte, '\0', sizeof(int));
    if( !aad_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(aad_len, aad_len_byte);

    unsigned char* msg =(unsigned char*) malloc(sizeof(unsigned char) * msg_len);
    memset(msg, '\0', msg_len);
    if( !msg){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    memcpy(msg, payload_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN], aad_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int)], aad, aad_len);
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len], ct_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int)], (unsigned char*) ct, ct_len);
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int) + ct_len], (unsigned char*) tag, tag_len);
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len], (unsigned char*) iv, iv_len);

    error = send_bytes(sock, msg, msg_len);
    if(error == -1){
        if(sock != -1)
            close(sock);
        handleErrors("Error on send_bytes");
    }

    free(pt);
    free(iv);
    free(ct);
    free(tag);
    free(counter_byte);
    free(payload_len_byte);
    free(ct_len_byte);
    free(msg);
    free(opt);
    free(aad_len_byte);
    free(aad);

    return 0;
}

int send_pub_key(char* sender_user,char* user_to_send){

    int error = 0;
    int sock = get_socket(user_to_send);

    // legge la chiave pubblica del client
    char* file = (char*)malloc(sizeof(char)*30);
    sprintf(file, "./../Client/pubKey-%s.pem", sender_user);
    EVP_PKEY *public_key = read_publicKey(file);
    fflush(stdout);
    if(public_key == NULL)
        handleErrors("Error in read_publicKey");

    int public_key_len = 0;
    unsigned char *public_key_byte = NULL;
    public_key_byte = publicKey_to_byte(public_key, &public_key_len);
    if(public_key_byte == NULL)
        handleErrors("Error in publicKey_to_byte");

    int pt_len = public_key_len;
    unsigned char* pt = (unsigned char*) malloc(sizeof(unsigned char) * pt_len);
    memset(pt, '\0', pt_len);
    if( !pt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

	memcpy(pt, public_key_byte, pt_len);

    int iv_len = EVP_CIPHER_iv_length(EVP_aes_256_gcm());
    unsigned char* iv = (unsigned char*)malloc(iv_len);
    // seme OpenSSL PRNG
    RAND_poll();
    RAND_bytes((unsigned char*)&iv[0],iv_len);
    if(iv == NULL){
      return -1;
    }

    int ct_len = pt_len + EVP_CIPHER_block_size(EVP_aes_256_gcm());
    unsigned char* ct = (unsigned char*) malloc(sizeof(unsigned char) * ct_len);
    memset(ct, '\0', ct_len);
    if( !ct){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    int tag_len = TAG_LEN;
    unsigned char* tag = (unsigned char*) malloc(sizeof(unsigned char) * tag_len);
    memset(tag, '\0', tag_len);
    if( !tag){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    // AAD = (msgtype || cont_server_client)
    int aad_len = OPT_LEN + sizeof(int);
    unsigned char* aad = (unsigned char*) malloc(sizeof(unsigned char) * aad_len);
    memset(aad, '\0', aad_len);
    if( !aad){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    unsigned char* counter_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(counter_byte, '\0', sizeof(int));
    if( !counter_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    unsigned int counter = get_counter_sc(user_to_send);
    unsigned_int_to_byte(counter, counter_byte);

    add_counter_sc(user_to_send);

    unsigned char* opt = (unsigned char*) malloc(sizeof(unsigned char) * OPT_LEN);
    memset(opt, '\0', OPT_LEN);
    if( !opt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    memcpy(opt, "pubKey", OPT_LEN - 1);
    memcpy(aad, opt, OPT_LEN -1);
    memcpy(&aad[OPT_LEN], counter_byte, sizeof(int));

    unsigned char *session_key = get_session_key(user_to_send);

    // cifra il plaintext
    ct_len = gcm_encrypt(pt, pt_len, aad, aad_len, session_key, iv, iv_len, ct, tag);
    if(ct_len == -1)
      handleErrors("Error in gcm_encrypt\n");

    int msg_len = HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len + iv_len;
    int payload_len = msg_len - HEADER_SESSION_LEN;

    unsigned char* payload_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(payload_len_byte, '\0', sizeof(int));
    if( !payload_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(payload_len, payload_len_byte);

    unsigned char* ct_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(ct_len_byte, '\0', sizeof(int));
    if( !ct_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(ct_len, ct_len_byte);

    unsigned char* aad_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(aad_len_byte, '\0', sizeof(int));
    if( !aad_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(aad_len, aad_len_byte);

    unsigned char* msg =(unsigned char*) malloc(sizeof(unsigned char) * msg_len);
    memset(msg, '\0', msg_len);
    if( !msg){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    memcpy(msg, payload_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN], aad_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int)], aad, aad_len);
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len], ct_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int)], (unsigned char*) ct, ct_len);
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int) + ct_len], (unsigned char*) tag, tag_len);
    memcpy((unsigned char*) &msg[HEADER_SESSION_LEN + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len], (unsigned char*) iv, iv_len);

    error = send_bytes(sock, msg, msg_len);
    if(error == -1){
        if(sock != -1)
            close(sock);
        handleErrors("Error on send_bytes");
    }

    free(pt);
    free(iv);
    free(ct);
    free(tag);
    free(counter_byte);
    free(payload_len_byte);
    free(ct_len_byte);
    free(msg);
    free(opt);
    free(aad_len_byte);
    free(aad);

    return 0;
}
