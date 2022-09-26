#ifndef SERVER_FUNCTIONS_H
#define SERVER_FUNCTIONS_H

#include <utility.h>

/* argomenti da passare ad ogni thread */
typedef struct thread_args
{
    size_t thread_index;                /* index del thread nell'array */
    bool busy;                          /* indica se la cella dell'array è assegnata a un thread in uso */
    bool free_to_chat;                  /* indica se l'utente è disponibile per chattare */
    int socket;                         /* socket da gestire */
    pthread_t handler_pt;               /* pthread_t del thread "handler_read" */
    int key_len;
    unsigned int count_server_client;   /* counter dei messaggi dal server al client */
    unsigned int count_client_server;   /* counter dei messaggi dal client al server */
    unsigned char *session_key;         /* chiave di sessione */
    char username[BUFSIZE];             /* username dell'utente gestito */
    char client_to_chat[BUFSIZE];       /* username dell'utente con cui vuole parlare l'utente gestito*/
    string opt;                         /* opt letto dal thread read */
    char IP_client[INET_ADDRSTRLEN];    /* buffer contenente l'indirizzo ip del client */
    char msg_received[BUFSIZE];         /* buffer contenente i messaggi ricevuti per il client */
    bool msg_received_full;             /* variabile di controllo per sapere se il buffer dei messaggi è pieno */
    pthread_mutex_t mutex_msg_received; /* mutex per accedere al buffer dei messaggi ricevuti in modo esclusivo */
    pthread_cond_t cond_msg_received;   /* condition variable per accedere al buffer dei messaggi ricevuti in modo esclusivo */
} user;

/* funzione per controllare se username è online e disponibile
        -> restituisce true e mette la variabile in_chat a true di username in caso affermativo
        -> false altrimenti */
bool check_list_name(char* username);

/* funzione per impostare il flag free_to_chat di username a true
        -> restituisce 0 se è andato tutto bene
        -> 1 altrimenti */
int wait_chat(char* username);

/* funzione per impostare il flag free_to_chat di username a false
        -> restituisce 0 se è andato tutto bene
        -> 1 altrimenti */
int stop_wait_chat(char* username);

/* funzione per aggiungere la struttura "user" del nuovo utente alla Lista
        -> restituisce 0 se è andato tutto bene */
int add_user_to_list(user *utente);

/* funzione per rimuovere la struttura "user" dell'utente dalla Lista
        -> restituisce 0 se è andato tutto bene
        -> 1 altrimenti */
int remove_user_to_list(user *utente);

/* funzione per ottenere il counter dei messaggi dal client al server
        -> restituisce il counter se va tutto bene
        -> -1 altrimenti */
unsigned int get_counter_cs(char* client);

/* funzione per mandare la lista di utenti online all'utente user_name
        -> restituisce 0 se è andato tutto bene
        -> -1 altrimenti */
int send_user_list(string user_name, long sock);

/* funzione per comunicare all'interlocutore che l'altro utente ha terminato la chat
            -> restituisce 0 se è andato tutto bene
            -> -1 altrimenti */
int quit_chat(char *user);

/* funzione per comunicare al mittente che il destinatario non intende iniziare la chat
            -> restituisce 0 se è andato tutto bene
            -> -1 altrimenti */
int negative_chat_response(char *user);

/* funzione per comunicare al mittente che il destinatario intende iniziare la chat
            -> restituisce 0 se è andato tutto bene
            -> -1 altrimenti */
int positive_chat_response(char *user);

/* funzione per leggere la richiesta da parte del client
        -> restituisce l'OPT corrispondente alla richiesta
           se tutto è andato a buon fine*/
char* receive_opt_request(long sock, unsigned char* session_key, unsigned int *counter, char* user);

/* funzione per inoltrare la richiesta di chat del mittente al destinatario selezionato
        -> restituisce 0 se è andato tutto bene
        -> -1 altrimenti */
int send_chat_request_server(char* sender_user,char* user_to_send);

/* funzione per inoltrare la chiave pubblica del mittente al destinatario selezionato
        -> restituisce 0 se è andato tutto bene
        -> -1 altrimenti */
int send_pub_key(char* sender_user,char* user_to_send);

#endif
