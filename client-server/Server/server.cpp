#include "server_functions.cpp"
#include "./crypto_functions.cpp"
#include <sys/wait.h>
#include "./../utility.cpp"
#include "unistd.h"

#define _XOPEN_SOURCE 700
#define BUFSIZE 4096           /* massima grandezza del payload */
#define OPT_LEN 30
#define MAX_CHARS_TO_READ 4095 /* massimo numero di caratteri da leggere da input */



/* variabili per la gestione dei thread */
pthread_t threads[SOMAXCONN];              /* potrò gestire fino ad un massimo di SOMAXCONN connessioni contemporanee */
pthread_t reading_threads[SOMAXCONN];      /* ognuno di essi è costantemente in ascolto di nuovi messaggi da inviare al client */
user thread_arg_array[SOMAXCONN];          /* array di struct contenenti gli argomenti da passare ad ogni thread */
pthread_attr_t attr;                       /* rendo esplicitamente joinable i thread */
pthread_mutexattr_t attr_mutex;            /* proprietà del mutex */
int err_thread;                            /* valore dell'errore ritornato nella creazione/join del thread */
char rec[OPT_LEN+BUFSIZE+1];               /* array che contiene il valore di ritorno dell'handler_connection*/

/* - - - - - - - - - - - - - - - - - -  */

/*
    Se le operazioni sono state effettuate correttamente ritorna 0.
    Altrimenti un numero != 0.
*/
int close_connection_thread(size_t thread_index)
{
    int return_err = 0;
    bool *busy = (bool *)&thread_arg_array[thread_index].busy;           /* flag per riusare le celle degli array solo se non più occupati a fare qualcosa */
    int *socket = (int *)&thread_arg_array[thread_index].socket;         /* socket da gestire */
    char *username = (char *)&thread_arg_array[thread_index].username;   /* username dell'utente gestito, copiato dal processo padre nel buffer del thread */
    char *IP_client = (char *)&thread_arg_array[thread_index].IP_client; /* buffer contenente l'indirizzo ip del client */
    pthread_mutex_t *mutex_msg_received = (pthread_mutex_t *)&thread_arg_array[thread_index].mutex_msg_received; /* mutex per accedere al buffer contenente i messaggi ricevuti */
    pthread_cond_t *cond_msg_received = (pthread_cond_t *)&thread_arg_array[thread_index].cond_msg_received;     /* coondition variable per accedere al buffer contenente i messaggi ricevuti */
    /* stampa le info sul client disconnesso */
    printf("%s:%s disconnected\n", IP_client, username);
    /* una volta terminata la sessione del client, chiude il socket */
    close(*socket);
    /* setta il thread come non più occupato */
    *busy = false;

    // elimina l'utente dalla Lista
    if(remove_user_to_list(&thread_arg_array[thread_index]) != 0 )
        handleErrors("Error remove_user_to_list");
    /* distrugge il mutex creato nel processo principale */
    return_err = pthread_mutex_destroy(mutex_msg_received);
    /* distrugge la condition variable creata nel processo principale */
    return_err = pthread_cond_destroy(cond_msg_received);
    pthread_exit((void*) 1);

    return return_err;
}

/*
    Trova il primo thread disponibile e ritorna l'indice relativo all'interno dell'array thread_arg_array.
    Ritorna -1 in caso di fallimento
*/
ssize_t find_available_thread(size_t max_number_threads)
{
    /*
        per trovare il primo thread disponibile, basta cercare nell'array quale ha valore busy = false.
        Dopo aver chiamato la pthread_exit() infatti viene settato a false.
    */
    for (size_t i = 0; i < max_number_threads; i++){
        if (!thread_arg_array[i].busy)
            return i;
    }

    return -1;
}

/*
    Questa funzione si occupa di controllare l'opt letto dall'handler_connection e
    di gestirlo in modo opportuno.
*/
void *handler_read(void *threadarg){

    /* ottengo gli argomenti passati come parametro */
    user *args = (user *)threadarg;

    size_t *thread_index = (size_t *)&(args->thread_index);
    int *socket = (int *)&args->socket;                         /* socket da gestire */
    char *username = (char *)&args->username;                   /* username dell'utente gestito, copiato dal processo padre nel buffer del thread */
    char *IP_client = (char *)&args->IP_client;                 /* buffer contenente l'indirizzo ip del client */
    unsigned char *session_key = (unsigned char*) malloc(sizeof(unsigned char) * (int)args->key_len);
    memset(session_key, '\0', (int)args->key_len);
    if( !session_key){
        if( *socket != -1 )
             close(*socket);
        handleErrors("Error on malloc");
    }
    memcpy(session_key, (unsigned char*)&args->session_key, (int)args->key_len);
    pthread_mutex_t *mutex_msg_received = (pthread_mutex_t *)&args->mutex_msg_received; /* mutex per accedere al buffer contenente i messaggi ricevuti */
    pthread_cond_t *cond_msg_received = (pthread_cond_t *)&args->cond_msg_received;     /* coondition variable per accedere al buffer contenente i messaggi ricevuti */
    bool closed_session = false;
    int error = 0;

    /* fin tanto che non viene chiusa la connessione o non c'è errore,
       controllo se ci sono eventuali nuovi opt da gestire */
    while (!closed_session)
    {
        if ((error=pthread_mutex_lock(mutex_msg_received)) != 0){
            printf("Error: %s\n", strerror(error));
            fprintf(stderr, "Error: handler_read() -> pthread_mutex_lock()\n");
            exit(EXIT_FAILURE);
        }
        // si sblocca tramite la broadcast dell'handler_connection
        pthread_cond_wait(cond_msg_received, mutex_msg_received);
        fflush(stdout);

        const std::string::size_type size = args->opt.size();

        memcpy(rec, args->opt.c_str(), size + 1);
        args->opt.clear();

        // controllo del tipo dei messaggi
        string delimiter = " ";
        string token = rec;
        token = token.substr(0, token.find(delimiter));
        if(memcmp("chat", token.c_str(), sizeof("chat")) == 0){
            char* dest_username = (char*) malloc(sizeof(char)* BUFSIZE);
            memset(dest_username, '\0', BUFSIZE);
            memcpy(dest_username, &rec[OPT_LEN], BUFSIZE);
            memcpy(args->client_to_chat, &rec[OPT_LEN], BUFSIZE);

            // caso negativo, utente già occupato
            if(!check_list_name(dest_username)){
                negative_chat_response(username);
                continue;
            }
            if(send_chat_request_server(username, dest_username) != 0)
                handleErrors("Error send_chat_request_server");


        }else if(memcmp("yeschat", token.c_str(), sizeof("yeschat")) == 0){
            /* questo opt mi arriverà quando il client che ha ricevuto la richiesta accetta
               di chattare, mando la chiave pubblica del client che ha mandato la richiesta
               a questo che ha risposto e possono iniziare la creazione della chiave di sessione
               e dopo la chat */
               string client_to_chat = (char*) &rec[OPT_LEN];
               memcpy(args->client_to_chat, &rec[OPT_LEN], BUFSIZE);
               fflush(stdout);
               if( positive_chat_response(const_cast<char*>(client_to_chat.c_str())))
                    handleErrors("Error in positive_chat_response");
               usleep(50000); //0.05 seconds
               send_pub_key(const_cast<char*>(client_to_chat.c_str()), username);
               send_pub_key(username, const_cast<char*>(client_to_chat.c_str()));

        }else if(memcmp("nochat", token.c_str(), sizeof("nochat")) == 0){
               /* opt che mi indica la risposta negativa da parte del client */
               string client_to_chat = (char*) &rec[OPT_LEN];
               negative_chat_response(const_cast<char*>(client_to_chat.c_str()));

        }else if(memcmp("in_chat", token.c_str(), sizeof("in_chat")) == 0){
               // non viene gestito qui, ma all'interno di receive_opt_request

        }else if(memcmp("chat_quit", token.c_str(), sizeof("chat_quit")) == 0){
            /* opt che indica che uno dei due client vuole terminare la chat,
               quindi anche il secondo deve terminare la chat */
               if(memcmp(args->client_to_chat, (const void*)" ", BUFSIZE) != 0)
                   quit_chat(args->client_to_chat);
               memset(args->client_to_chat, '\0', BUFSIZE);
               if( !(args->client_to_chat)){
                   if( *socket != -1 )
                       close(*socket);
                   handleErrors("Error on malloc");
               }

        }else if(memcmp("wait", token.c_str(), sizeof("wait")) == 0){
            /* il client si vuole mettere in attesa di chat */
            if(wait_chat(username))
                handleErrors("Error wait_chat");
            fflush(stdin);

        }else if(memcmp("stop", token.c_str(), sizeof("stop")) == 0){
            /* il client vuole tornare nel menu principale e non aspettare
               più richieste di chat da parte di altri utenti */
            if(stop_wait_chat(username))
                handleErrors("Error stop_wait_chat");
        }
        else if(memcmp("closed", token.c_str(), sizeof("closed")) == 0){
            /* il client ha chiuso la socket */
            closed_session = true;
            if( *socket != -1 )
                 close(*socket);

        }
        else if(memcmp((unsigned char*)"list_rq", token.c_str(), sizeof("list_rq")) == 0){

            /* il client vuole vedere la lista di utenti disponibili a chattare (utenti online) */
            if(send_user_list(username, *socket) != 0)
                handleErrors("Error in send_user_list\n");

        }
        else{
            closed_session = true;
            if( *socket != -1 )
                 close(*socket);
            printf("OPT non riconosciuto\n");
        }

        memset(rec, '\0', size +1);
        if( !rec){
            if( *socket != -1 )
                 close(*socket);
            handleErrors("Error on malloc");
        }

        /* faccio l'unlock e mando il segnale broadcast per avvertire l'handler_connection che
           ho gestito l'opt ricevuto e mi metto in attesa del prossimo */
        if (pthread_mutex_unlock(mutex_msg_received) != 0)
        {
            fprintf(stderr, "Error: handler_read() -> pthread_mutex_unlock()\n");
            exit(EXIT_FAILURE);
        }

        if (pthread_cond_broadcast(cond_msg_received) != 0)
        {
            fprintf(stderr, "Error: handler_read() -> pthread_cond_broadcast()\n");
            exit(EXIT_FAILURE);
        }
        usleep(50000); //0.05 seconds

    } //fine while sessione

    if (close_connection_thread(*thread_index) != 0)
    {
        printf("errore nella chiusura della connessione ->  handler_read() thread_index#%ld\n", *thread_index);
        exit(EXIT_FAILURE);
    }
    pthread_exit(NULL);
}

/*
    Questa funzione si occupa di gestire la connessione di uno specifico utente, in particolare
    legge l'opt mandato dal client e segnala all'handler_read che è pronto per essere gestito
*/
void *handler_connection(void *threadarg)
{
    /* ottengo gli argomenti passati come parametro */
    user *args = (user *)threadarg;

    size_t *thread_index = (size_t *)&args->thread_index;
    (void)thread_index;   /* evita warning */
    int *socket = (int *)&args->socket;                             /* socket da gestire */
    char *username = (char *)&args->username;                       /* username dell'utente gestito, copiato dal processo padre nel buffer del thread */
    char *client_to_chat = (char*)&args->client_to_chat;            /* username dell'utente con cui vuole parlare l'utente gestito */
    char *IP_client = (char *)&args->IP_client;                     /* buffer contenente l'indirizzo ip del client */
    pthread_t pth = (pthread_t)&args->handler_pt;
    unsigned char *session_key = (unsigned char*) malloc(sizeof(unsigned char) * (int)args->key_len);
    memset(session_key, '\0', (int)args->key_len);
    if( !session_key){
        if( *socket != -1 )
             close(*socket);
        handleErrors("Error on malloc");
    }
    memcpy(session_key, (unsigned char*)args->session_key, (int)args->key_len);
    fflush(stdout);
    pthread_mutex_t *mutex_msg_received = (pthread_mutex_t *)&args->mutex_msg_received; /* mutex per accedere al buffer contenente i messaggi ricevuti */
    pthread_cond_t *cond_msg_received = (pthread_cond_t *)&args->cond_msg_received;     /* coondition variable per accedere al buffer contenente i messaggi ricevuti */
    bool closed_session = false;                                                        /* flag per gestire il caso di connessione terminata con il client */

    printf("%s:%s connected\n", IP_client, username);
    usleep(500000); //0.5 seconds

    while (!closed_session)
    {
        ssize_t byte_read = 0;
        char rec[BUFSIZE + OPT_LEN];
        memset(&rec[0], '\0', (OPT_LEN + BUFSIZE));
        if( !rec){
            if( *socket != -1 )
                 close(*socket);
            handleErrors("Error on malloc");
        }

        int counter = get_counter_cs(username);
        args->opt = receive_opt_request(*socket, session_key, counter, username, client_to_chat);

        if(memcmp(rec, "closed", OPT_LEN) == 0){
            closed_session = 1;
            continue;
        }

        /* manda il segnale broadcast per avvisare l'handler_read che l'opt letto è pronto
           per essere gestito */
        if (pthread_cond_broadcast(cond_msg_received) != 0)
            fprintf(stderr, "Error: handler_connection() -> pthread_cond_broadcast()\n");
        if (pthread_mutex_lock(mutex_msg_received) != 0){
            fprintf(stderr, "Error: handler_read2() -> pthread_mutex_lock()\n");
            exit(EXIT_FAILURE);
        }

        // si sblocca tramite la broadcast dell'handler_read
        pthread_cond_wait(cond_msg_received, mutex_msg_received);
        if (pthread_mutex_unlock(mutex_msg_received) != 0)
            fprintf(stderr, "Error: handler_connection() -> pthread_mutex_unlock()\n");
        usleep(50000); //0.05 seconds

    } //fine while sessione

    // invia la richiesta per eliminare il thread handler_read
    if(pthread_cancel(pth) != 0)
        handleErrors("error in pthread_cancel");

    if (close_connection_thread(*thread_index) != 0)
    {
        printf("errore nella chiusura della connessione ->  handler_connection() thread_index#%ld\n", *thread_index);
    }

    pthread_exit(NULL);
}

void handler(int signo)
{
    int status;

    (void)signo; /* per evitare warning */

    /* eseguo wait non bloccanti finché ho dei figli terminati */
    while (waitpid(-1, &status, WNOHANG) > 0)
        continue;
}

int main(int argc, char const *argv[])
{
    /* variabili per la gestione dei socket */
    int flag_so_reuse = 1; //abilita il flag SO_REUSEADDR
    int init_socket, connected_socket;
    struct sockaddr_in addr_a; /* AF_INET + porta 16 bit + IP 32 bit */

    /* informazioni del client */
    struct sockaddr_in info_client; /* IP e porta del client */
    socklen_t len;
    /* - - - - - - - - - - - - */

    uint16_t PORT; /* parametro passato dall'utente */

    /* Controlla gli argomenti */
    if (argc != 2)
    {
        fprintf(stderr, "Errore, Uso: %s <portID>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    else
    {
        PORT = atoi(argv[1]);
    }

    /* resetta lo spazio di memoria che ospiterà le struct dei thread */
    memset(threads, 0, sizeof(threads));

    /* resetta lo spazio di memoria che ospiterà le struct dei thread in lettura */
    memset(reading_threads, 0, sizeof(reading_threads));

    /* resetta lo spazio di memoria che ospiterà gli argomenti dei thread */
    memset(thread_arg_array, 0, sizeof(thread_arg_array));

    /* esegue il reset al valore di default della struct */
    pthread_attr_init(&attr);

    /* rende i thread futuri creati con questi attributi joinable */
    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE) != 0)
    {
        perror("pthread_attr_setdetachstate()");
        exit(EXIT_FAILURE);
    }

    /* configura ogni thread con un id univoco che sarà riutilizzato per connessioni multiple
       ovvero ad ogni cella dell'array viene associato un id univoco fin dall'inizio.
       Inoltre configura tutti i thread come non occupati.
    */
    for (size_t t = 0; t < SOMAXCONN; t++)
    {

        thread_arg_array[t].thread_index = t;
        thread_arg_array[t].busy = false;
    }

    /* configura gli attributi dei mutex */
    if (pthread_mutexattr_init(&attr_mutex) != 0)
    {
        perror("pthread_mutexattr_init()");
        exit(EXIT_FAILURE);
    }
    if ((err_thread = pthread_mutexattr_settype(&attr_mutex, PTHREAD_MUTEX_ERRORCHECK)) != 0)
    {
        errno = err_thread;
        perror("pthread_mutexattr_settype()");
        exit(EXIT_FAILURE);
    }


    /* azzera la struttura che deve ospitare le info relative a numero di porta e indirizzo IP */
    memset(&addr_a, 0, sizeof(addr_a));

    /* configura la famiglia di indirizzo nella struct */
    addr_a.sin_family = AF_INET; /* indirizzo IPv4 */

    /* configura la porta nella struct con il formato di rete */
    addr_a.sin_port = htons(PORT);

    /* configura l'indirizzo IP in modo automatico */
    addr_a.sin_addr.s_addr = INADDR_ANY; /* il sistema in automatico configura l'IP */


    /* crea il socket */
    if ((init_socket = socket(PF_INET, SOCK_STREAM, 0)) < 0) /* protocolli internet IPv4 + socket TCP + protocollo di default del SO */
    {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    /* abilita il flag SO_REUSEADDR per la socket */
    if (setsockopt(init_socket, SOL_SOCKET, SO_REUSEADDR, &flag_so_reuse, sizeof(flag_so_reuse)))
    {
        perror("setsockopt()");
        exit(EXIT_FAILURE);
    }

    /* associa IP e porta al socket */
    if ((bind(init_socket, (struct sockaddr *)&addr_a, sizeof(addr_a))) < 0)
    {
        perror("bind()");
        exit(EXIT_FAILURE);
    }

    /* mette il socket in attesa di eventuali connessioni */
    if ((listen(init_socket, SOMAXCONN)) < 0)
    {
        perror("listen()");
        exit(EXIT_FAILURE);
    }

    while (true)
    {
        fflush(stdout);
        usleep(1000000); //1 seconds

        char username[BUFSIZE];          /* buffer contenente lo username ricevuto dal client */
        char IP_client[INET_ADDRSTRLEN]; /* buffer contenente l'indirizzo ip del client */
        struct in_addr ip_addr_network;  /* contiene l'IP del client nel formato di rete */

        len = (socklen_t)sizeof(info_client);
        connected_socket = accept(init_socket, (struct sockaddr *)&info_client, &len);
        if (connected_socket < 0)
        {
            if (errno == EINTR)
                continue;
            perror("accept()");
            exit(EXIT_FAILURE);
        }
        else /* esegue questo ramo solo se non ci sono stati errori con il connected_socket */
        {
            size_t available_thread = find_available_thread(SOMAXCONN);
            if (available_thread != -1) /* c'è un nuovo thread disponibile */
            {
                /*
                    legge lo username dalla socket, essendo di lunghezza finita, si poteva anche leggere
                    usando la classica read
                */
                ssize_t byte_read = 0;
                memset(username, 0, BUFSIZE);

                // legge il nonce del client
                int nonceC = 0;
                int nonceS = 0;
                string un = read_nonce(connected_socket, &nonceC);
                strcpy(username, un.c_str());

                // legge la public key del client
                char* file = (char*)malloc(sizeof(char)*30);
                sprintf(file, "./../Client/pubKey-%s.pem", username);
                EVP_PKEY *public_key = read_publicKey(file);
                fflush(stdout);
                if(public_key == NULL)
                    handleErrors("Error in read_publicKey");

                // genera la coppia di chiavi effimere e mando quella pubblica (i parametri DH)
                EVP_PKEY* ephemeral_public_key = NULL;
                EVP_PKEY* ephemeral_private_key = NULL;
                generate_ek(&ephemeral_private_key, &ephemeral_public_key);
                if(ephemeral_private_key == NULL)
                    handleErrors("Error in generate_ek private key");
                if( ephemeral_public_key == NULL)
                    handleErrors("Error in generate_ek public key");

                // legge la chiave privata del server
                memset(file, '\0', sizeof(char)*30);
                if( !file){
                    if( connected_socket != -1 )
                         close(connected_socket);
                    handleErrors("Error on malloc");
                }
                strcpy(file, "./privKey-server.pem");
                EVP_PKEY* priv_key = read_privateKey(file);
                if(priv_key == NULL)
                    handleErrors("Error in read_private_key");

                // manda ( Rc || Ys) con la firma e il certificato del server
                bool error = send_epk_server(connected_socket, ephemeral_public_key, nonceC, &nonceS, priv_key);
                if (!error)
                    handleErrors("Error in send_epk");

                /* legge la chiave effimera del client*/
                EVP_PKEY* ephemeral_pubKey_client = read_epk_client(connected_socket, nonceS, public_key);
                if(ephemeral_pubKey_client == NULL){
                    perror("Error read server ephemeral_pubKey");
                    close(connected_socket);
                    exit(EXIT_FAILURE);
                }


                unsigned int digest_len = 0;
                unsigned char *digest = derive_shared_secret(ephemeral_private_key, ephemeral_pubKey_client, &digest_len);

                const EVP_CIPHER* cipher = EVP_aes_128_cbc();
                int iv_len = EVP_CIPHER_iv_length(cipher);
                int key_len = EVP_CIPHER_key_length(cipher);
                int block_size = EVP_CIPHER_block_size(cipher);

                unsigned char *key = (unsigned char*)malloc(key_len);
                memcpy(key, digest, key_len);
                // alloca la memoria per la generazione dell'IV random
                unsigned char* iv = (unsigned char*)malloc(iv_len);
                // seme OpenSSL PRNG
                RAND_poll();
                RAND_bytes((unsigned char*)&iv[0],iv_len);
                // fa la free del buffer segreto condiviso
                #pragma optimize("", off)
                memset(digest, 0, digest_len);
                #pragma optimize("", on)
                free(digest);

                /* inizializza gli argomenti per il nuovo thread da creare */
                thread_arg_array[available_thread].busy = true; /* la cella corrispondente al thread creato è occupata */
                thread_arg_array[available_thread].free_to_chat = false;
                thread_arg_array[available_thread].thread_index = available_thread;

                memcpy(thread_arg_array[available_thread].username, username, BUFSIZE);
                thread_arg_array[available_thread].key_len = key_len;
                thread_arg_array[available_thread].session_key = (unsigned char*) malloc(sizeof(unsigned char)*key_len);
                memset(thread_arg_array[available_thread].session_key, '\0', key_len);
                if( !thread_arg_array[available_thread].session_key){
                    if( connected_socket != -1 )
                         close(connected_socket);
                    handleErrors("Error on malloc");
                }

                thread_arg_array[available_thread].opt;
                thread_arg_array[available_thread].opt.append(BUFSIZE+OPT_LEN, ' ');

                memcpy(thread_arg_array[available_thread].session_key, key, key_len);
                ip_addr_network = info_client.sin_addr; /* estraggo l'indirizzo ip */
                /* converte l'IP del client in un formato leggibile */
                if (inet_ntop(AF_INET, (void *)&ip_addr_network, IP_client, INET_ADDRSTRLEN) == NULL)
                {
                    perror("inet_ntop()");
                    exit(EXIT_FAILURE);
                }

                strncpy(thread_arg_array[available_thread].IP_client, IP_client, INET_ADDRSTRLEN);
                thread_arg_array[available_thread].socket = connected_socket;
                thread_arg_array[available_thread].count_client_server = 0;
                thread_arg_array[available_thread].count_server_client = 0;

                /* pulisce il buffer per i messaggi ricevuti da ogni utente e setta il flag di buffer pieno a false */
                memset(thread_arg_array[available_thread].msg_received, 0, BUFSIZE);
                thread_arg_array[available_thread].msg_received_full = false;

                /* inizializza il mutex e la condition variable */
                pthread_mutex_init(&thread_arg_array[available_thread].mutex_msg_received, &attr_mutex);
                pthread_cond_init(&thread_arg_array[available_thread].cond_msg_received, NULL);

                // aggiunge l'utente e i parametri appena creati alla struttura interna del server
                if( add_user_to_list(&thread_arg_array[available_thread]) != 0)
                    handleErrors("Error in add_user_to_list\n");

                // manda al client la lista di utenti online
                if(send_user_list(username, connected_socket) != 0)
                    handleErrors("Error in send_user_list\n");

                std::cout<<"\nLista utenti online mandata a "<<username<<endl;

                strcpy(username,"");
                strcpy(IP_client, "");

                len = 0;

                /* una volta configurati i parametri da passargli, crea il thread di sola lettura del buffer */
                if ((err_thread = pthread_create(&reading_threads[available_thread], &attr, handler_read, (void *)&thread_arg_array[available_thread])) != 0)
                {
                    fprintf(stderr, "ERROR: return code from pthread_create() is %d\n", err_thread);
                    exit(EXIT_FAILURE);
                }

                thread_arg_array[available_thread].handler_pt = reading_threads[available_thread];

                /* una volta configurati i parametri da passargli, crea il thread per gestire la connessione */
                if ((err_thread = pthread_create(&threads[available_thread], &attr, handler_connection, (void *)&thread_arg_array[available_thread])) != 0)
                {
                    fprintf(stderr, "ERROR: return code from pthread_create() is %d\n", err_thread);
                    exit(EXIT_FAILURE);
                }

                /* distrugge lo spazio usato per gli attributi dei thread */
                pthread_attr_destroy(&attr);

                /* distrugge lo spazio usato per gli attributi dei mutex */
                pthread_mutexattr_destroy(&attr_mutex);

                /* stacca i thread così da poter servire altre richieste */
                err_thread = pthread_detach(threads[available_thread]);
                if (err_thread)
                {
                    fprintf(stderr, "ERROR: return code from pthread_detach() is %d\n", err_thread);
                    close(connected_socket);
                }

                err_thread = pthread_detach(reading_threads[available_thread]);
                if (err_thread)
                {
                    fprintf(stderr, "ERROR: return code from pthread_detach() is %d\n", err_thread);
                    close(connected_socket);
                }
            }
        }
    }

    pthread_exit(NULL);
    close(init_socket);

    return 0;
}
