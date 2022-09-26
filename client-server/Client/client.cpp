
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <iostream>
#include <iomanip>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdbool.h>
#include <pthread.h>
#include <utility.cpp>
#include <crypto_functions.h>
#include "./../crypto_functions.cpp"

#define BUFACK_SIZE 4           /* 3 char + terminatore */
#define BUFSIZE 4096            /* massima grandezza del payload */
#define MAX_CHARS_TO_READ 4095  /* massimo numero di caratteri da leggere da input */

using namespace std;

const char *ack = "ACK"; 		/* concordato con il server */

volatile sig_atomic_t stop;  	/* variabile per fermare l'attesa di richieste di chat*/

unsigned char* list;        	/* lista di utenti in attesa di chattare*/

/* variabili per la gestione del thread di lettura */
pthread_t reading_thread; 		/* thread utilizzato per aspettare la richiesta di chat */
thread_args_t thread_arg; 		/* struct contenente gli argomenti da passare al thread di lettura */
pthread_attr_t attr;      		/* rendo esplicitamente joinable il thread */
int err_thread;           		/* valore dell'errore ritornato nella creazione/join del thread */

/* - - - - - - - - - - - - - - - - - -  */

/* variabili per la creazione del socket e la connessione con il server */
int sock;
struct sockaddr_in server_addr; /* AF_INET + porta 16 bit + IP 32 bit */

/* aspetta la richiesta di chat e viene terminata dall'arrivo di un segnale oppure
   se arriva la richiesta	*/
void *read_chat_request(void *arg){
	thread_args_t *thread_arg = (thread_args_t*) arg;
	int sock = thread_arg->socket;
    int *ret = (int*)&thread_arg->ret;
    unsigned char *key = (unsigned char*)&thread_arg->key;
    unsigned int *counter = (unsigned int*)&thread_arg->counter;
	int error = 0;

    // leggo l'header del messaggio
    unsigned char* receive_buff = (unsigned char*) malloc(sizeof(unsigned char) * HEADER_SESSION_LEN);
    memset(receive_buff, '\0', HEADER_SESSION_LEN);
    if( !receive_buff){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    error = read_bytes(sock, receive_buff, HEADER_SESSION_LEN);
    if(error == -1){
		    if(sock != 1)
			     close(sock);
		    handleErrors("Error read_bytes");
    }

    int payload_dim = 0;
    memcpy(&payload_dim, receive_buff, sizeof(int));

    // leggo l'aad
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

    // leggo il ciphertext
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

    int ct_len = 0;
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

    // leggo il tag
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

    // leggo l'IV
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

    // leggo l'opt del messaggio
    unsigned char *opt =  (unsigned char*) malloc(sizeof(unsigned char) * OPT_LEN);
    memset(opt, '\0', OPT_LEN);
    if( !opt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    //Converto il counter da byte a int
    memcpy(counter, &aad[OPT_LEN], sizeof(int));
    *counter = *counter + 1;

    // decifro il ciphertext
    unsigned char* pt = (unsigned char*) malloc(sizeof(unsigned char) * (ct_len + 1));
    memset(pt, '\0', (ct_len + 1));
    if( !pt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    int result = gcm_decrypt(ct, ct_len, aad, aad_len, tag, key, iv, iv_len, pt);
    if(result <= 0)
      handleErrors("Error in gcm_decrypt");

	// controllo il tipo del messaggio
    if(memcmp("chat", aad, sizeof("chat")) == 0){
        memcpy(thread_arg->client_to_chat, (unsigned char*) pt, ct_len + 1);
        *ret = 0;
    } else if(memcmp("stop", aad, sizeof("stop")) == 0){
		fflush(stdout);
	}
	else{
        *ret = -1;
        printf("OPT trovato: |%s|\n", aad);
	    handleErrors("Error: invalid OPT read_chat_request");
    }

  	free(receive_buff);
	free(ct_len_byte);
	free(ct);
	free(tag);
	free(iv);
  	free(aad);
	free(aad_len_byte);

  	pthread_exit(NULL);
}

/* gestione del segnale SIGTSTP */
void handler_sigtstp(int n){
    printf("Catturata SIGTSPT (ctrl+z)\n");
    stop = 1;
}

/* controlla se name è presenta nella lista che è stata mandata al client dal server */
int check_name(string list, string name){
    if( list.find(name, 0) != string::npos)
        return 0;
    return -1;
}

/* funzione che si occupa di leggere i messaggi che vengono mandati dall'altro client con cui sto chattando */
void *read_in_chat(void *arg){
    thread_args_t *thread_arg = (thread_args_t*) arg;

    while(!stop){
        int error = 0;

        // leggo l'header del messaggio
        unsigned char* receive_buff = (unsigned char*) malloc(sizeof(unsigned char) * HEADER_SESSION_LEN);
        memset(receive_buff, '\0', HEADER_SESSION_LEN);
        if( !receive_buff){
            if( sock != -1 )
                 close(sock);
            handleErrors("Error on malloc");
        }

        error = read_bytes(sock, receive_buff, HEADER_SESSION_LEN);
        if(error == -1){
    		if(sock != -1)
    			close(sock);
    		handleErrors("Error in read_bytes1");
    	}

        int payload_dim = 0;
        memcpy(&payload_dim, receive_buff, sizeof(int));

        // leggo l'aad
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

        // leggo il ciphertext
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

        unsigned char* ct = (unsigned char*) malloc(sizeof(unsigned char) * (ct_len + 1));
        memset(ct, '\0', (ct_len + 1));
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

        // leggo il tag
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

        // leggo l'IV
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

        // leggo l'opt del messaggio
        unsigned char *opt =  (unsigned char*) malloc(sizeof(unsigned char) * OPT_LEN);
        memset(opt, '\0', OPT_LEN);
        if( !opt){
            if( sock != -1 )
                 close(sock);
            handleErrors("Error on malloc");
        }

    	// controllo il tipo del messaggio
        if(memcmp("chat_quit", aad, sizeof("chat_quit")) == 0){
    		free(receive_buff);
            free(aad_len_byte);
            free(aad);
            free(iv);
            free(opt);
            free(tag);
            free(ct);
            free(ct_len_byte);
            stop = 1;
            printf("Digitare un carattere qualsiasi per tornare alla menu\n" );
            pthread_exit(NULL);
        }
        if(memcmp("in_chat", aad, sizeof("in_chat")) != 0){
    		free(receive_buff);
    		printf("Mi aspettavo l'OPT in_chat, invece trovo %s\n",aad);
            handleErrors("Error: opt type not match");
        }

        //Converto il counter da byte a int
        memcpy(&(thread_arg->counter), &aad[OPT_LEN], sizeof(int));
        thread_arg->counter = thread_arg->counter + 1;

        // decifro il ciphertext
        unsigned char* pt = (unsigned char*) malloc(sizeof(unsigned char) * (ct_len + 1));
        memset(pt, '\0', (ct_len + 1));
        if( !pt){
            if( sock != -1 )
                 close(sock);
            handleErrors("Error on malloc");
        }

        int result = gcm_decrypt(ct, ct_len, aad, aad_len, tag,(unsigned char*)thread_arg->key, iv, iv_len, pt);
        if(result <= 0){
            printf("result: %d\n", result);
            handleErrors("Error in gcm_decrypt\n");
      }

        int aad_C_len = 0;
        memcpy(&aad_C_len, &aad[OPT_LEN + sizeof(int)], sizeof(int)); // Converto byte in int

        // leggo l'aad del client
        unsigned char* aad_C = (unsigned char*) malloc(sizeof(unsigned char) * aad_C_len);
        memset(aad_C, '\0', aad_C_len);
        if( !aad_C){
            if( sock != -1 )
                 close(sock);
            handleErrors("Error on malloc");
        }
        memcpy(aad_C, &aad[OPT_LEN + sizeof(int) + sizeof(int)], aad_C_len);
        memcpy(&(thread_arg->counter_C), aad_C, sizeof(int));
        thread_arg->counter_C = thread_arg->counter_C + 1;

        int ct_C_len = -1;
        memcpy(&ct_C_len, &aad[OPT_LEN + sizeof(int) + sizeof(int) + aad_C_len], sizeof(int));

        // leggo il ciphertext dell'altro client
        unsigned char* ct_C = (unsigned char*) malloc(sizeof(unsigned char) * (ct_C_len + 1));
        memset(ct_C, '\0', (ct_C_len + 1));
        if( !ct_C){
            if( sock != -1 )
                 close(sock);
            handleErrors("Error on malloc");
        }
        memcpy(ct_C, &aad[OPT_LEN + sizeof(int) + sizeof(int) + aad_C_len + sizeof(int)], ct_C_len);

        // leggo tag del client
        unsigned char* tag_C = (unsigned char*) malloc(sizeof(unsigned char) * TAG_LEN);
        memset(tag_C, '\0', TAG_LEN);
        if( !tag_C){
            if( sock != -1 )
                close(sock);
            handleErrors("Error on malloc");
        }
        memcpy(tag_C, &aad[OPT_LEN + sizeof(int) + sizeof(int) + aad_C_len + sizeof(int) + ct_C_len], TAG_LEN);

        // leggo l'IV
        int iv_C_len = EVP_CIPHER_iv_length(EVP_aes_256_gcm());
        unsigned char* iv_C =  (unsigned char*) malloc(sizeof(unsigned char) * iv_C_len);
        memset(iv_C, '\0', iv_C_len);
        if( !iv_C){
            if( sock != -1 )
                 close(sock);
            handleErrors("Error on malloc");
        }

        memcpy(iv_C, &aad[OPT_LEN + sizeof(int) + sizeof(int) + aad_C_len + sizeof(int) + ct_C_len + TAG_LEN], iv_C_len);

       // decifro il ciphertext
       unsigned char* pt_C = (unsigned char*) malloc(sizeof(unsigned char) * (ct_C_len + 1));
       memset(pt_C, '\0', (ct_C_len + 1));
       if( !pt_C){
           if( sock != -1 )
                close(sock);
           handleErrors("Error on malloc");
       }
       result = gcm_decrypt(ct_C, ct_C_len, aad_C, aad_C_len, tag_C, (unsigned char*)thread_arg->key_with_client, iv_C, iv_C_len, pt_C);
       if(result <= 0)
            handleErrors("Error in gcm_decrypt\n");
       if(!stop)
	   		printf("                 %s\n",  pt_C);
            //printf("%s: %s\n", thread_arg->client_to_chat, pt_C);

       free(receive_buff);
       free(ct_len_byte);
       free(ct);
       free(tag);
       free(iv);
       free(aad);
       free(aad_len_byte);
    }
    pthread_exit(NULL);
}

/* funzione per mandare i messaggi all'altro client*/
void in_chat(unsigned char* client, thread_args_t *thread_arg){
    int err = -1;
    int num = -1;
    string in_C = "";
    fflush(stdin);
    cin.clear();

    /* counters per evitare attacchi di tipo replay*/
    thread_arg->counter_C = 0;
    printf("\n\nDigitare il messaggio che si vuole mandare a %s, oppure premere (CTRL + Z) per terminare la chat\n", client);
    while(!stop){
        getline(cin, in_C);
        if(in_C.size() >= BUFSIZE){
            cin.clear();
            printf("Il messaggio che è stato inserito è troppo lungo\nInserire un messaggio più corto\n");
            continue;
        }
        if(stop){
            return;
        }
        err = send_in_chat(thread_arg, in_C);
        if(err != 0)
            handleErrors("Error in send_in_chat");
        in_C.clear();
    }

}

int main(int argc, char *argv[])
{

    /* variabili per conservare gli argomenti passati */
    char IP_SERVER[INET_ADDRSTRLEN];
    char USERNAME[BUFSIZE];
    uint16_t PORT;

    /* variabili per la gestione dei segnali */
    struct sigaction sa;

    /* contatore tentativi connect() */
    ssize_t connect_try = 0;

    /* Controllo argomenti */
    if (argc != 4)
    {
        fprintf(stderr, "Errore, Uso: %s <hostID> <username> <portID>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    else
    {
        /* configuro i parametri del client in base all'input */
        strncpy(IP_SERVER,argv[1],INET_ADDRSTRLEN);
        /* lo username può essere di massimo 4095 + terminatore, dimensione concordata con il server */
        if (strlen(argv[2]) > BUFSIZE - 1)
        {
            fprintf(stderr, "Error <username>: max 4096 characters.\n");
            exit(EXIT_FAILURE);
        }
        else
        {
            strncpy(USERNAME,argv[2],4095);
        }

        PORT = atoi(argv[3]);
    }

    /* configurazione dei segnali */
    sa.sa_handler = handler_sigtstp;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if ( sigaction(SIGTSTP, &sa, NULL) == -1 ) {
        perror("Couldn't set SIGTSTP handler");
        exit(EXIT_FAILURE);
    }

    for (;;)
    {

        char input_user[BUFSIZE];  /* input dell'utente */
        char receiver[BUFSIZE];    /* destinatario del messaggio*/
        char msg[BUFSIZE];         /* messaggio da inviare */
        int err_connect = 0;
        bool end = false;

        /* resetto lo spazio di memoria che ospiterà la struct del thread di lettura */
        memset(&reading_thread, 0, sizeof(reading_thread));

        /* resetto lo spazio di memoria che ospiterà gli argomenti del thread di lettura */
        memset(&thread_arg, 0, sizeof(thread_arg));

        /* faccio il reset al valore di default della struct */
        pthread_attr_init(&attr);

        /* rendo il thread di lettura creato con questo attributo, joinable */
        if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE) != 0)
        {
            perror("pthread_attr_setdetachstate()");
            exit(EXIT_FAILURE);
        }

        /* creo il socket */
        if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
        {
            perror("socket()");
            exit(EXIT_FAILURE);
        }

        /* Costruzione dell'indirizzo */
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(PORT);
        if (inet_pton(AF_INET, IP_SERVER, &server_addr.sin_addr) < 0)
        {
            perror("inet_pton()");
            exit(EXIT_FAILURE);
        }

        if ((err_connect = connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr))) < 0)
        {
            printf("Server non disponibile\n");
            exit(EXIT_FAILURE);
        }

        /*************************************************************************/
        /* Fase di Pre-Autenticazione  */
        /*************************************************************************/

        /* counters per evitare attacchi di tipo replay*/
        unsigned int count_client_server = 0;
        unsigned int count_server_client = 0;

        int nonceC = send_random_nonce(sock, USERNAME);
        int nonceS = 0;

        char* file = (char*)malloc(sizeof(char)*30);

        /* legge la chiave effimera del server*/
        EVP_PKEY* ephemeral_pubKey_server = read_epk_server(sock, nonceC, &nonceS);
        if(ephemeral_pubKey_server == NULL){
            perror("Error read server ephemeral_pubKey");
            close(sock);
            exit(EXIT_FAILURE);
        }

        // Generazione delle chaivi effimere e mando quella pubblica al server
        EVP_PKEY* ephemeral_public_key = NULL;
        EVP_PKEY* ephemeral_private_key = NULL;
        generate_ek(&ephemeral_private_key, &ephemeral_public_key);
        if(ephemeral_private_key == NULL)
            handleErrors("Error in generate_ek private key");
        if( ephemeral_public_key == NULL)
            handleErrors("Error in generate_ek public key");

        // legge la chiave privata del client
        memset(file, '\0', sizeof(char)*30);
        if( !file){
            if( sock != -1 )
                 close(sock);
            handleErrors("Error on malloc");
        }
        fflush(stdout);
        sprintf(file, "./privKey-%s.pem", USERNAME);
        EVP_PKEY* priv_key;
        while((priv_key = read_privateKey(file)) == NULL)
            printf("Errore chiave privata, provare di nuovo\n");
        fflush(stdout);

        // manda ( Rs || Yc) con la firma
        bool error = send_epk_client(sock, ephemeral_public_key, nonceS, priv_key);
        if (!error)
            handleErrors("Error in send_epk");
        fflush(stdout);

        unsigned int digest_len = 0;
        unsigned char *digest = derive_shared_secret(ephemeral_private_key, ephemeral_pubKey_server, &digest_len);

        const EVP_CIPHER* cipher = EVP_aes_128_cbc();
        int iv_len = EVP_CIPHER_iv_length(cipher);
        int key_len = EVP_CIPHER_key_length(cipher);

        /* Configura la variabile di ritorno a 1 per dire che non ha ricevuto niente  */
        thread_arg.ret = 1;
        thread_arg.socket = sock;
        thread_arg.key_len = key_len;
        thread_arg.client_to_chat = (unsigned char*) malloc(sizeof(unsigned char)*BUFSIZE);
        memset(thread_arg.client_to_chat, '\0', BUFSIZE);
        if( !(thread_arg.client_to_chat)){
        	if( sock != -1 )
        		close(sock);
        	handleErrors("Error on malloc");
        }
        memset(thread_arg.key, '\0', key_len);
        if( !(thread_arg.key)){
        	if( sock != -1 )
        		close(sock);
        	handleErrors("Error on malloc");
        }
        int block_size = EVP_CIPHER_block_size(cipher);

        unsigned char *key = (unsigned char*)malloc(key_len);
        memset(key, '\0', key_len);
        if( !key){
            if( sock != -1 )
                 close(sock);
            handleErrors("Error on malloc");
        }
        memcpy(key, digest, key_len);
        memcpy(thread_arg.key, digest, key_len);

        unsigned char* iv = (unsigned char*)malloc(iv_len);

        // manda OpenSSL PRNG
        RAND_poll();
        RAND_bytes((unsigned char*)&iv[0],iv_len);

        // fa la free dello shared secret buffer
        #pragma optimize("", off)
            memset(digest, 0, digest_len);
        #pragma optimize("", on)
            free(digest);

        fflush(stdout);

        // legge la lista di utenti online
        list = online_user_list(sock, key, &count_server_client);
        if(list == NULL){
            close(sock);
            handleErrors("Error in online_user_list");
        }

        int num = -1;
        string in = "";
        fflush(stdin);
        cin.clear();
        bool finish = false;
        while(!finish){
            printf("\n\nDigitare il numero corrispondente alla scelta che si vuole fare \n1: Parlare con un altro utente \n2: Vedere la lista di utenti online \n3: Logout dal server \n4: Mettersi in attesa di chat\n");
            cin>>in;
            if( (strcmp(in.c_str(), "1") != 0) && (strcmp(in.c_str(), "2") != 0) && (strcmp(in.c_str(), "3") != 0) && (strcmp(in.c_str(), "4") != 0)){
                printf("Scelta non valida\n\n");
            }
            else{
                num = atoi( in.c_str() );
            }
            switch (num) {
                case 2: {// l'utente vuole vedere la lista di utenti online
                    case1:
                    online_user_list_request(sock, key, &count_client_server);

                    // legge la lista di utenti online
                    list = online_user_list(sock, key, &count_server_client);
                    if(list == NULL){
                        close(sock);
                        handleErrors("Error in online_user_list");
                    }
                }break;

                case 1: {// l'utente vuole parlare con un altro
                    stop = 0;
                    unsigned char *client_to_send = (unsigned char*) malloc(sizeof(char)* BUFSIZE);
                    memset(client_to_send, '\0', BUFSIZE);
                    if( !client_to_send){
                        if( sock != -1 )
                             close(sock);
                        handleErrors("Error on malloc");
                    }
                    memset(thread_arg.client_to_chat, '\0', BUFSIZE);
                    if( !(thread_arg.client_to_chat)){
                        if( sock != -1 )
                             close(sock);
                        handleErrors("Error on malloc");
                    }
                    printf("\nInserire nome utente al quale vogliamo mandare la richiesta di chat:\n");
                    cin>> setw(BUFSIZE) >>in;

                    memcpy(client_to_send, in.c_str(), in.size());
                    memcpy(thread_arg.client_to_chat, client_to_send, in.size());
                    string s1( reinterpret_cast< char const* >(list));
                    string s2( reinterpret_cast< char const* >(client_to_send));
                    if( check_name(s1, s2)  == 0){
                        send_chat_request(sock, key, &count_client_server, in);
                        char *res =(char*) malloc(sizeof(char)*OPT_LEN);
                        memset(res, '\0', OPT_LEN);
                        memcpy(res, chat_request_response(sock, key, &count_server_client), OPT_LEN);

                        if(res == NULL){
                            close(sock);
                            handleErrors("Error in online_user_list");
                        }else if(memcmp("yes", res, sizeof("yes")) == 0){
                            unsigned char* user2_public_key = NULL;
                            unsigned char* client = (unsigned char*) malloc(sizeof(unsigned char) * BUFSIZE);
                            memset(client, '\0', BUFSIZE);
                            memcpy(client, thread_arg.client_to_chat, BUFSIZE);
                            int user2_public_key_len = -1;
                            user2_public_key = read_pub_key(sock, key, &count_server_client, &user2_public_key_len);
                            if(user2_public_key == NULL)
                                handleErrors("Error in read_pub_key");
                            if( !create_session_key_from_client1(sock, key, &count_client_server, &count_server_client,
                               USERNAME, user2_public_key, user2_public_key_len, &thread_arg, priv_key))
                                handleErrors("Error in create_session_key_from_client1");
							fflush(stdout);
                            pthread_t reading_thread_chat;
                            if ((err_thread = pthread_create(&reading_thread_chat, NULL, &read_in_chat, (void *)&thread_arg)) != 0)
                                handleErrors("Error pthread_create");
                            err_thread = pthread_detach(reading_thread_chat);
                            if (err_thread){
                                fprintf(stderr, "ERROR: return code from pthread_detach() is %d\n", err_thread);
                                close(sock);
                            }
							fflush(stdout);
                            in_chat(client, &thread_arg);
                            in.clear();
                            cin.clear();

                            if(!send_quit_chat(sock, key, &count_client_server))
                                handleErrors("Error in send_quit_chat");
                            continue;

                        }else{
                            printf("Risposta negativa\n");
                            continue;
                        }
                    }

                    /* stampo che il nome non è presente e gli faccio fare l'opzione 2,
                       così gli viene stampata la lista aggiornata */
                    printf("Error: nome non presente nella lista, inserire un nome valido\n");
                    goto case1;
                }break;

                case 3: {// l'utente vuole disconnettersi dal server e terminare la chat
                    finish = true;
                }break;

                case 4:{
                    stop = 0;
                    memset(thread_arg.client_to_chat, '\0', BUFSIZE);
                    if( !thread_arg.client_to_chat){
                        if( sock != -1 )
                             close(sock);
                        handleErrors("Error on malloc");
                    }
                    if(wait_chat(sock, key, &count_client_server))
                        handleErrors("Error wait_chat");
                    printf("Sono in attesa di chattare......\n\n");

                label:
                    fflush(stdout);
                    if ((err_thread = pthread_create(&reading_thread, &attr, &read_chat_request, (void *)&thread_arg)) != 0)
                        handleErrors("Error pthread_create");

                    err_thread = pthread_detach(reading_thread);
                    if (err_thread){
                        fprintf(stderr, "ERROR: return code from pthread_detach() is %d\n", err_thread);
                        close(sock);
                    }

                    while(!stop && thread_arg.ret){
                        usleep(50000);
                    }

                    stop_wait_chat(sock, key, &count_client_server);
                    printf("\nRichiesta di chat arrivata da parte di %s\n", thread_arg.client_to_chat);
                    if(  thread_arg.ret == 1 ){
                        printf("il client non vuole più aspettare\n");
						usleep(50000);
						void* err = 0;
                        continue;
                    }else if( thread_arg.ret == 0){
                        num = -1;
                        in.clear();
                        fflush(stdin);
                        cin.clear();
                        bool finish1 = false;
                        while(!finish1){
                            printf("\n\nDigitare il numero corrispondente alla scelta che si vuole fare \n1: Accettare la richiesta dell'altro utente \n2: Rifiutare la richiesta dell'altro utente \n");
                            cin>>in;
                            if( (strcmp(in.c_str(), "1") != 0) && (strcmp(in.c_str(), "2") != 0) ){
                                printf("Scelta non valida\n\n");
                            }
                            else{
                                finish1 = true;
                                num = atoi( in.c_str() );
                            }

                            switch (num) {

                                case 1: { /* invio risposta positiva e inizio la fase di creazione della chiave tra i due client*/
                                    positive_chat_response_to_server(sock, key, &count_client_server, thread_arg.client_to_chat, BUFSIZE);
                                    unsigned char* user1_public_key = NULL;
                                    unsigned char* client = (unsigned char*) malloc(sizeof(unsigned char) * BUFSIZE);
                                    memset(client, '\0', BUFSIZE);
                                    memcpy(client, thread_arg.client_to_chat, BUFSIZE);
                                    int user1_public_key_len = -1;
                                    user1_public_key = read_pub_key(sock, key, &count_server_client, &user1_public_key_len);
                                    if(user1_public_key == NULL)
                                        handleErrors("Error in read_pub_key");
                                    if( !create_session_key_from_client2(sock, key, &count_client_server, &count_server_client,
                                       USERNAME, user1_public_key, user1_public_key_len, &thread_arg, priv_key))
                                        handleErrors("Error in create_session_key_from_client2");
									fflush(stdout);
                                    pthread_t reading_thread_chat;
                                    if ((err_thread = pthread_create(&reading_thread_chat, NULL, &read_in_chat, (void *)&thread_arg)) != 0)
                                        handleErrors("Error pthread_create");
                                    err_thread = pthread_detach(reading_thread_chat);
                                    if (err_thread){
                                        fprintf(stderr, "ERROR: return code from pthread_detach() is %d\n", err_thread);
                                        close(sock);
                                    }
                                    fflush(stdout);
                                    in_chat(client, &thread_arg);
                                    in.clear();
                                    cin.clear();

                                    if(!send_quit_chat(sock, key, &count_client_server))
                                        handleErrors("Error in send_quit_chat");
                                    thread_arg.ret = 1;

                                }break;
                                case 2:{ /* inviare risposta negativa e rimanere in attesa di chat */
                                    negative_chat_response_to_server(sock, key, &count_client_server, thread_arg.client_to_chat, BUFSIZE);
                                    finish1 = false;
                                    thread_arg.ret = 1;
                                    usleep(1000000);
                                    printf("Rimango in attesa di chat\n\n\n");
                                    goto label;
                                }break;
                            }
                        }
                    }

                }break;

            }
        }

        if(key == NULL || (key_len<0)){
            close(sock);
            break;
        }
        memset(key, '\0', key_len);
        free(key);
        free(iv);
        free(file);
        EVP_PKEY_free(ephemeral_public_key);
        EVP_PKEY_free(priv_key);

        break;
    }

    pthread_exit(NULL);

    return 0;
}
