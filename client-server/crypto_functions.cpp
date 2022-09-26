#include <crypto_functions.h>
#include <utility.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <map>
#include <string>

#define HEADER_LEN 34
#define OPT_LEN 30

using std::cout;
using std::endl;
using std::stringstream;
using std::vector;
using std::string;

/* funzione per la generazione della firma di un plaintext
 * 		-> restituisce la lunghezza della firma se è andato tutto bene
 		-> -2 altrimenti */
int digital_signature(unsigned char* pt, int pt_len, unsigned char* sign, EVP_PKEY* private_key, const EVP_MD* md){

    int error = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if(!ctx){
		printf("Error in EVP_MD_CTX_new()");
		return -2;
	}

    error = EVP_SignInit(ctx, md);
	if(!error){
		printf("Error in EVP_SignInit");
		return -2;
	}

    error = EVP_SignUpdate(ctx, pt, pt_len);
	if(!error){
		printf("Error in EVP_SignUpdate");
		return -2;
	}

    unsigned int sign_len = 0;
    error = EVP_SignFinal(ctx, sign, &sign_len, private_key);
	if(!error){
		printf("Error in EVP_SignFinal");
		return -2;
	}

    /* Context free */
    EVP_MD_CTX_free(ctx);

    return sign_len;
}

/* verifica la firma e restituisce il risultato della EVP_VerifyFinal non ci sono errori, quindi:
	 	-> 0 se la firma non è valida
		-> -1 se ci sono errori
		->  1 la verifica è andata a buon fine
		-> -2 altrimenti  */
int digital_signature_verify(unsigned char* sign, int sign_len, unsigned char* pt, int pt_len, EVP_PKEY* public_key, const EVP_MD* md){

    int error = 0, res;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if(!ctx){
		printf("Error in EVP_MD_CTX_new");
		return -2;
	}

    error = EVP_SignInit(ctx, md);
	if(!error){
		printf("Error in EVP_SignInit");
		return -2;
	}

    error = EVP_VerifyUpdate(ctx, pt, pt_len);
	if(!error){
		printf("Error in EVP_VerifyUpdate");
		return -2;
	}

    res = EVP_VerifyFinal(ctx, sign, sign_len, public_key);
    EVP_MD_CTX_free(ctx);
    return res;
}

/* funzione per convertire un certificato in formato bytes in X509
		-> restituisce il certificato in formato X509
        -> NULL altrimenti */
X509* convert_cert_to_X509(unsigned char* cert_buff, int size){

    BIO *bio = BIO_new_mem_buf(cert_buff, size);
    if(bio == NULL)
        handleErrors("Error in BIO_new_mem_buf");
    X509* server_cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
    BIO_free(bio);
    return server_cert;
}

/* converte i bytes dalla chiave pubblica in formato EVP_PKEY*
 		-> restituisce la chiave pubblica in formato  EVP_PKEY* */
EVP_PKEY* publicKey_to_EVP_PKEY(unsigned char* publicKey, int len){

    BIO* bio = BIO_new(BIO_s_mem());
    BIO_write(bio, publicKey, len);
    EVP_PKEY* pubK = NULL;
    pubK =  PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return pubK;
}

int send_random_nonce(long sock, string username){

    int error = 0;
    int nonce = rand();

    unsigned char* rand_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(rand_byte, '\0', sizeof(int));
    if( !rand_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    int_to_byte(nonce, rand_byte);

    // crea il buffer per mandare il messaggio
    int msg_len = HEADER_LEN + sizeof(int) + strlen(username.c_str());
    unsigned char* msg_buff = (unsigned char*) malloc(sizeof(unsigned char) * msg_len);
    memset(msg_buff, '\0', msg_len);
    if( !msg_buff){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    // converte int in unsigned char
    int payload_len = sizeof(int) + strlen(username.c_str());
    unsigned char* payload_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(payload_len_byte, '\0', sizeof(int));
    if( !payload_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(payload_len, payload_len_byte);

    // crea il messaggio da mandare
    memcpy(msg_buff, "login", OPT_LEN - 1);
    memcpy(&msg_buff[OPT_LEN], payload_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg_buff[HEADER_LEN], rand_byte, sizeof(int));
    copy(username.begin(), username.end(), &msg_buff[HEADER_LEN + sizeof(int)]);


    // manda il messaggio
    error = send_bytes(sock, msg_buff, msg_len);
    if(error == -1){
        if(sock != -1)
            close(sock);
        handleErrors("Error on send_bytes");
    }

    free(rand_byte);
    free(msg_buff);
    free(payload_len_byte);

    return nonce;
}

string read_nonce(long sock, int* nonce){

    int error = 0;

    // legge l'header del messaggio (msg_type + payload_len)
    unsigned char* receive_buff =(unsigned char*) malloc(sizeof(unsigned char) * HEADER_LEN);
    memset(receive_buff, '\0', HEADER_LEN);
    if( !receive_buff){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    error = read_bytes(sock, receive_buff, HEADER_LEN);
	if(error == -1){
        if(sock != -1)
            close(sock);
        handleErrors("Error on sendn");
    }

	// controlla il tipo del messaggio
    if(memcmp("login", receive_buff, sizeof("login")) != 0){
		free(receive_buff);
        handleErrors("Error: opt type not match:read nonce");
    }

    int payload_dim = 0;
    memcpy(&payload_dim, &receive_buff[OPT_LEN], sizeof(int));

    // legge il nonce
    unsigned char* nonce_buff =(unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(nonce_buff, '\0', sizeof(int));
    if( !nonce_buff){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    error = read_bytes(sock, nonce_buff, sizeof(int));
	if(error == -1){
        if(sock != -1)
            close(sock);
        handleErrors("Error on sendn");
    }

    // legge l'username del client
    int username_len = payload_dim - sizeof(int) + 1;
    unsigned char* user_buff = (unsigned char*) malloc(sizeof(unsigned char) * username_len);
    memset(user_buff, '\0', username_len);
    if( !user_buff){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    memset(user_buff, '\0', username_len);
    error = read_bytes(sock, user_buff, username_len - 1);
	if(error == -1){
        if(sock != -1)
            close(sock);
        handleErrors("Error on read_bytes");
    }

    // nonce da byte a int
    memcpy(nonce, nonce_buff, sizeof(int));

    // username da byte a string
    string usr_name = (char*) user_buff;

    free(receive_buff);
	free(user_buff);
	free(nonce_buff);

    return usr_name;

}

EVP_PKEY* read_epk_server(long sock, int nonceC, int *nonceS){

    int error = 0;

    // legge l'header del messaggio (msg_type + payload_len)
    unsigned char* receive_buff = (unsigned char*) malloc(sizeof(unsigned char) * HEADER_LEN);
    memset(receive_buff, '\0', HEADER_LEN);
    if( !receive_buff){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    error = read_bytes(sock, receive_buff, HEADER_LEN);
	if(error == -1){
		if(sock != 1)
			close(sock);
		handleErrors("Error read_bytes");
	}

	// legge l'opt del messaggio
	unsigned char* opt = (unsigned char*) malloc(sizeof(unsigned char) *OPT_LEN);
	memset(opt, '\0', OPT_LEN);
    if( !opt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    memcpy(&opt, &receive_buff, OPT_LEN);

    // legge la dimensione del payload
    int payload_dim = 0;
    // converte da byte a int
    memcpy(&payload_dim, &receive_buff[OPT_LEN], sizeof(int));

    // controlla il tipo del messaggio
    if(memcmp((unsigned char*)"login1", receive_buff, sizeof("login1")) != 0){
		free(receive_buff);
        handleErrors("Error: opt type not match: read_epk_server");
    }


    // legge la dimensione della firma
    unsigned char* sign_len_byte =  (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(sign_len_byte, '\0', sizeof(int));
    if( !sign_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    error = read_bytes(sock, sign_len_byte, sizeof(int));
	if(error == -1){
		if(sock != 1)
			close(sock);
		handleErrors("Error read_bytes");
	}
    int sign_len = 0;
    memcpy(&sign_len, sign_len_byte, sizeof(int)); // converte da byte a int

    // legge la firma
    unsigned char* sign = (unsigned char*) malloc(sizeof(unsigned char) * sign_len);
    memset(sign, '\0', sign_len);
    if( !sign){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    error = read_bytes(sock, sign, sign_len);
	if(error == -1){
		if(sock != 1)
			close(sock);
		handleErrors("Error read_bytes");
	}

    // legge la dimensione della chiave pubblica
    unsigned char* epk_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(epk_byte, '\0', sizeof(int));
    if( !epk_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    error = read_bytes(sock, epk_byte, sizeof(int));
    if(error == -1){
		if(sock != 1)
			close(sock);
		handleErrors("Error read_bytes");
	}
    int epk_len = -1;
    memcpy(&epk_len, epk_byte, sizeof(int));


    // legge la chiave pubblica effimera del server
    unsigned char* buff_epk = (unsigned char*) malloc(sizeof(unsigned char) * epk_len);
    memset(buff_epk, '\0', epk_len);
    if( !buff_epk){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    error = read_bytes(sock, buff_epk, epk_len);
	if(error == -1){
		if(sock != 1)
			close(sock);
		handleErrors("Error read_bytes");
	}

    // legge il nonce
    unsigned char* nonce_buff =(unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(nonce_buff, '\0', sizeof(int));
    if( !nonce_buff){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    error = read_bytes(sock, nonce_buff, sizeof(int));
	if(error == -1){
        if(sock != -1)
            close(sock);
        handleErrors("Error on sendn");
    }

    // nonce da byte a int
    memcpy(nonceS, nonce_buff, sizeof(int));

    // legge il certificato del server
    int cert_len = payload_dim - epk_len - sign_len - sizeof(int)*3;
    unsigned char* buff_cert = (unsigned char*) malloc(sizeof(unsigned char) * cert_len);
    memset(buff_cert, '\0', cert_len);
    if( !buff_cert){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    error = read_bytes(sock, buff_cert, cert_len);
	if(error == -1){
		if(sock != 1)
			close(sock);
		handleErrors("Error read_bytes");
	}

    // converto il certificato del server nel formato X509
    X509* cert = convert_cert_to_X509(buff_cert, cert_len);
    if(cert == NULL)
      handleErrors("Error convert_cert_to_X509");

    char *cert_CA_file = (char*) malloc(sizeof(char)*30);
    char *crl_CA_file  = (char*) malloc(sizeof(char)*30);
    strcpy(cert_CA_file, "./../Server/cert-ca.pem");
    strcpy(crl_CA_file, "./../Client/crl-ca.pem");
    int res = certificate_verification(cert_CA_file, crl_CA_file, cert);
    if(res == 1){
		/* DEBUG*/
		char* tmp = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
   		char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
   		printf("Certificate of %s released by %s VERIFIED SUCCESSFULLY\n\n", tmp, tmp2);
        fflush(stdout);
   		free(tmp);
   		free(tmp2);
   		/* DEBUG*/
    }
    else
        handleErrors("Error: certificate verification failed");

    // estrae la chaive pubblica dal certificato del server
    EVP_PKEY* server_pubKey = X509_get_pubkey(cert);
    if(server_pubKey == NULL)
      	handleErrors("Error in X509_get_pubkey");

    // crea il plaintext (nonceC || Ys) per verificare la firma
    int sign_plaintext_len = sizeof(int) + epk_len;
    unsigned char* sign_plaintext = (unsigned char*) malloc(sizeof(unsigned char) * sign_plaintext_len);
    memset(sign_plaintext, '\0', sign_plaintext_len);
    if( !sign_plaintext){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    unsigned char* nonce_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(nonce_byte, '\0', sizeof(int));
    if( !nonce_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(nonceC, nonce_byte);

    memcpy(sign_plaintext, nonce_byte, sizeof(int));
    memcpy(&sign_plaintext[sizeof(int)], buff_epk, epk_len);

    // verifica la firma e ottiene la chiave pubblica del server in formato EVP_PKEY
    res = digital_signature_verify(sign, sign_len, sign_plaintext, sign_plaintext_len, server_pubKey, EVP_sha256());
    EVP_PKEY* p = NULL;
    if(res == 1){
        p = publicKey_to_EVP_PKEY(buff_epk, epk_len);
        if(p == NULL)
          handleErrors("Error in publicKey_to_EVP_PKEY");
    } else
      handleErrors("Error: invalid signature verification");

    free(receive_buff);
    free(sign_len_byte);
    free(sign);
    free(epk_byte);
    free(buff_epk);
    free(buff_cert);
    free(sign_plaintext);
    free(nonce_byte);
    free(nonce_buff);
    EVP_PKEY_free(server_pubKey);

    return p;

}

bool send_epk_server(long sock, EVP_PKEY* ephemeral_public_key, int nonce, int *nonceS, EVP_PKEY *server_privKey){

    int error = 0;

    // converte il nonce in byte
    unsigned char* nonce_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(nonce_byte, '\0', sizeof(int));
    if( !nonce_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(nonce, nonce_byte);

    // serializza la chiave pubblica effimera
    int epk_len = 0;
    unsigned char* serialize_epk = publicKey_to_byte(ephemeral_public_key, &epk_len);
    if(serialize_epk == NULL)
        handleErrors("Error in publicKey_to_byte");


    // converte epk_len da int a byte
    unsigned char* epk_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(epk_len_byte, '\0', sizeof(int));
    if( !epk_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(epk_len, epk_len_byte);

    // crea il messaggio da firmare (Rc (nonce from client)||Ys)
    int msg_to_sign_len = sizeof(int) + epk_len;
    unsigned char* msg_to_sign = (unsigned char*) malloc(sizeof(unsigned char) * msg_to_sign_len);
    memset(msg_to_sign, '\0', msg_to_sign_len);
    if( !msg_to_sign){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    memcpy((unsigned char*)msg_to_sign, (unsigned char*) nonce_byte, sizeof(int));
    memcpy((unsigned char*)&msg_to_sign[sizeof(int)], (unsigned char*) serialize_epk, epk_len);

    // firma il messaggio
    int sign_len = EVP_PKEY_size(server_privKey);
    unsigned char* sign = (unsigned char*) malloc(sizeof(unsigned char) * sign_len);
    memset(sign, '\0', sign_len);
    if( !sign){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    sign_len = digital_signature(msg_to_sign, msg_to_sign_len, sign, server_privKey, EVP_sha256());
    if(sign_len == -2)
      handleErrors("Error in digital_signature");

    // converte la sign_len in byte
    unsigned char* sign_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(sign_len_byte, '\0', sizeof(int));
    if( !sign_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(sign_len, sign_len_byte);

    // legge il certificato del server
    int cert_len = -1;
    char *file = (char*) malloc(sizeof(char)*30);
    strcpy(file, "./cert-server.pem");
    unsigned char* cert = read_cert(file, &cert_len);
    if(cert == NULL)
      	handleErrors("Error in read_cert");

	// nonce da mandare al client
    *nonceS = rand();

    // converte da int a unsigned char
    unsigned char* rand_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(rand_byte, '\0', sizeof(int));
    if( !rand_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    int_to_byte(*nonceS, rand_byte);

    // converte il payload_len in byte
    int payload_len = sizeof(int) + sign_len + sizeof(int) + epk_len + sizeof(int) + cert_len;
    unsigned char* payload_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(payload_len_byte, '\0', sizeof(int));
    if( !payload_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(payload_len, payload_len_byte);


    // crea il buffer
    int msg_len = HEADER_LEN + payload_len;
    unsigned char* msg = (unsigned char*) malloc(sizeof(unsigned char) * msg_len);
    memset(msg, '\0', msg_len);
    if( !msg_len){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    unsigned char* opt = (unsigned char*) malloc(sizeof(unsigned char) * OPT_LEN);
    memset(opt, '\0', OPT_LEN);
    if( !opt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }


	memcpy((unsigned char*) &msg[0], (unsigned char*)"login1", OPT_LEN - 1);
    memcpy((unsigned char*) &msg[OPT_LEN], payload_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN], sign_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN + sizeof(int)], sign, sign_len);
    memcpy((unsigned char*) &msg[HEADER_LEN + sizeof(int) + sign_len], epk_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN + sizeof(int) + sign_len + sizeof(int)], serialize_epk, epk_len);
	memcpy((unsigned char*) &msg[HEADER_LEN + sizeof(int) + sign_len + sizeof(int) + epk_len], rand_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN + sizeof(int) + sign_len + sizeof(int) +  epk_len + sizeof(int) ], cert, cert_len);


    // manda il buffer
    error = send_bytes(sock, msg, msg_len);
	if(error == -1){
		if(sock != 1)
			close(sock);
		handleErrors("Error in send_bytes");
	}

    free(nonce_byte);
    free(rand_byte);
	free(serialize_epk);
	free(msg_to_sign);
	free(sign);
	free(sign_len_byte);
    free(payload_len_byte);
	free(msg);
	free(cert);
    free(file);
    free(opt);
	free(epk_len_byte);

    return true;

}

EVP_PKEY* read_epk_client(long sock, int nonceS, EVP_PKEY* client_pubKey){

    int error = 0;

    // legge l'header del messaggio (msg_type + payload_len)
    unsigned char* receive_buff = (unsigned char*) malloc(sizeof(unsigned char) * HEADER_LEN);
    memset(receive_buff, '\0', HEADER_LEN);
    if( !receive_buff){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    error = read_bytes(sock, receive_buff, HEADER_LEN);
	if(error == -1){
		if(sock != 1)
			close(sock);
		handleErrors("Error read_bytes");
	}

	// legge l'opt del messaggio
	unsigned char* opt = (unsigned char*) malloc(sizeof(unsigned char) *OPT_LEN);
	memset(opt, '\0', OPT_LEN);
    if( !opt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    memcpy(&opt, &receive_buff, OPT_LEN - 1);

    // legge la dimensione del payload
    int payload_dim = 0;
    memcpy(&payload_dim, &receive_buff[OPT_LEN], sizeof(int)); // converte da byte a int
    fflush(stdout);

    // controlla il tipo del messaggio
    if(memcmp((unsigned char*)"login2", receive_buff, sizeof("login2")) != 0){
		free(receive_buff);
        handleErrors("Error: opt type not match: login2");
    }
    //printf("PROVA after check login2\n");

    // legge la dimensione della firma
    unsigned char* sign_len_byte =  (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(sign_len_byte, '\0', sizeof(int));
    if( !sign_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    error = read_bytes(sock, sign_len_byte, sizeof(int));
	if(error == -1){
		if(sock != 1)
			close(sock);
		handleErrors("Error read_bytes");
	}
    int sign_len = 0;
    memcpy(&sign_len, sign_len_byte, sizeof(int)); // converte da byte a int

    // legge la firma
    unsigned char* sign = (unsigned char*) malloc(sizeof(unsigned char) * sign_len);
    memset(sign, '\0', sign_len);
    if( !sign){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    error = read_bytes(sock, sign, sign_len);
	if(error == -1){
		if(sock != 1)
			close(sock);
		handleErrors("Error read_bytes");
	}

    // legge la dimensione della chiave pubblica
    unsigned char* epk_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(epk_byte, '\0', sizeof(int));
    if( !epk_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    error = read_bytes(sock, epk_byte, sizeof(int));
    if(error == -1){
		if(sock != 1)
			close(sock);
		handleErrors("Error read_bytes");
	}
    int epk_len = -1;
    memcpy(&epk_len, epk_byte, sizeof(int));


    // legge la chiave pubblica effimera del server
    unsigned char* buff_epk = (unsigned char*) malloc(sizeof(unsigned char) * epk_len);
    memset(buff_epk, '\0', epk_len);
    if( !buff_epk){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    error = read_bytes(sock, buff_epk, epk_len);
	if(error == -1){
		if(sock != 1)
			close(sock);
		handleErrors("Error read_bytes");
	}

    // crea il plaintext (nonceC || Ys) per verificare la firma
    int sign_plaintext_len = sizeof(int) + epk_len;
    unsigned char* sign_plaintext = (unsigned char*) malloc(sizeof(unsigned char) * sign_plaintext_len);
    memset(sign_plaintext, '\0', sign_plaintext_len);
    if( !sign_plaintext){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    unsigned char* nonce_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(nonce_byte, '\0', sizeof(int));
    if( !nonce_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(nonceS, nonce_byte);

    memcpy(sign_plaintext, nonce_byte, sizeof(int));
    memcpy(&sign_plaintext[sizeof(int)], buff_epk, epk_len);
    fflush(stdout);

    // verifica la firma e ottiene la chiave pubblica del client in formato EVP_PKEY
    int res = digital_signature_verify(sign, sign_len, sign_plaintext, sign_plaintext_len, client_pubKey, EVP_sha256());
    EVP_PKEY* p = NULL;
    if(res == 1){
        p = publicKey_to_EVP_PKEY(buff_epk, epk_len);
        if(p == NULL)
          handleErrors("Error in publicKey_to_EVP_PKEY");
    } else
      handleErrors("Error: invalid signature verification");

    free(sign_len_byte);
    free(sign);
    free(nonce_byte);
    free(epk_byte);
    free(buff_epk);
    free(sign_plaintext);
    free(opt);
    EVP_PKEY_free(client_pubKey);

    return p;

}

bool send_epk_client(long sock, EVP_PKEY* ephemeral_public_key, int nonce, EVP_PKEY *client_privKey){

    int error = 0;

    // converte il nonce in byte
    unsigned char* nonce_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(nonce_byte, '\0', sizeof(int));
    if( !nonce_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(nonce, nonce_byte);

    // serializza la chiave pubblica effimera
    int epk_len = 0;
    unsigned char* serialize_epk = publicKey_to_byte(ephemeral_public_key, &epk_len);
    if(serialize_epk == NULL)
        handleErrors("Error in publicKey_to_byte");

    // converte epk_len da int a byte
    unsigned char* epk_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(epk_len_byte, '\0', sizeof(int));
    if( !epk_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(epk_len, epk_len_byte);


    // crea il messaggio da firmare (Rs (nonce from server)||Yc)
    int msg_to_sign_len = sizeof(int) + epk_len;
    unsigned char* msg_to_sign = (unsigned char*) malloc(sizeof(unsigned char) * msg_to_sign_len);
    memset(msg_to_sign, '\0', msg_to_sign_len);
    if( !msg_to_sign){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    memcpy((unsigned char*)msg_to_sign, (unsigned char*) nonce_byte, sizeof(int));
    memcpy((unsigned char*)&msg_to_sign[sizeof(int)], (unsigned char*) serialize_epk, epk_len);

    // firma il messaggio
    int sign_len = EVP_PKEY_size(client_privKey);
    unsigned char* sign = (unsigned char*) malloc(sizeof(unsigned char) * sign_len);
    memset(sign, '\0', sign_len);
    if( !sign){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    sign_len = digital_signature(msg_to_sign, msg_to_sign_len, sign, client_privKey, EVP_sha256());
    if(sign_len == -2)
      handleErrors("Error in digital_signature");

    // converte la sign_len in byte
    unsigned char* sign_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(sign_len_byte, '\0', sizeof(int));
    if( !sign_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(sign_len, sign_len_byte);

    // converte il payload_len in byte
    int payload_len = sizeof(int) + sign_len + sizeof(int) + epk_len;
    unsigned char* payload_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(payload_len_byte, '\0', sizeof(int));
    if( !payload_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(payload_len, payload_len_byte);


    // crea il buffer
    int msg_len = HEADER_LEN + payload_len;
    unsigned char* msg = (unsigned char*) malloc(sizeof(unsigned char) * msg_len);
    memset(msg, '\0', msg_len);
    if( !msg_len){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    unsigned char* opt = (unsigned char*) malloc(sizeof(unsigned char) * OPT_LEN);
    memset(opt, '\0', OPT_LEN);
    if( !opt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

	memcpy((unsigned char*) &msg[0], (unsigned char*)"login2", OPT_LEN - 1);
    memcpy((unsigned char*) &msg[OPT_LEN], payload_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN], sign_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN + sizeof(int)], sign, sign_len);
    memcpy((unsigned char*) &msg[HEADER_LEN + sizeof(int) + sign_len], epk_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN + sizeof(int) + sign_len + sizeof(int)], serialize_epk, epk_len);

    // manda il buffer
    error = send_bytes(sock, msg, msg_len);
	if(error == -1){
		if(sock != 1)
			close(sock);
		handleErrors("Error in send_bytes");
	}

    free(nonce_byte);
	free(serialize_epk);
	free(msg_to_sign);
	free(sign);
	free(sign_len_byte);
    free(payload_len_byte);
	free(msg);
	free(epk_len_byte);

    return true;
}

bool send_quit_chat(long sock, unsigned char* session_key, unsigned int* counter){
    int error = 0;

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
      return false;
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
	*counter = *counter + 1;

	unsigned_int_to_byte(*counter, counter_byte);

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

    return true;
}

/* funzione per mandare il nonce al client destinatario
        -> restituisce il nonce se è andato tutto bene
        -> -1 altrimenti */
int send_random_nonce2(long sock, unsigned char* session_key, unsigned int* counter){
    int error = 0;
    int nonce = rand();

    unsigned char* rand_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(rand_byte, '\0', sizeof(int));
    if( !rand_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    int_to_byte(nonce, rand_byte);

    int pt_len = sizeof(int);

    unsigned char* pt = (unsigned char*) malloc(sizeof(unsigned char) * pt_len);
    memset(pt, '\0', pt_len);
    if( !pt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
	memcpy(pt, rand_byte, pt_len);

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
	*counter = *counter + 1;

	unsigned_int_to_byte(*counter, counter_byte);

    memcpy(aad, "in_chat", sizeof("in_chat"));
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

    return nonce;
}

/* funzione per leggere la chiave effimera creata del client mittente
        -> restituisce la chiave in formato EVP_PKEY se è andato tutto bene */
EVP_PKEY* read_epk_server2(long sock, unsigned char* session_key, unsigned int* counter, int nonceC, int *nonceS, EVP_PKEY* client_pubKey){
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
    if(error == -1){
		if(sock != -1)
			close(sock);
		handleErrors("Error in read_bytes1");
	}

    int payload_dim = 0;
    memcpy(&payload_dim, receive_buff, sizeof(int));

    // legge l'aad
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

    // legge il tag
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

    // legge l'IV
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

    // legge l'opt del messaggio
    unsigned char *opt =  (unsigned char*) malloc(sizeof(unsigned char) * OPT_LEN);
    memset(opt, '\0', OPT_LEN);
    if( !opt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

	// controlla il tipo del messaggio
    if(memcmp("in_chat", aad, sizeof("in_chat")) != 0){
		free(receive_buff);
		printf("Mi aspettavo l'OPT in_chat, invece trovo %s\n",aad);
        handleErrors("Error: opt type not match");
    }

    // converte il counter da byte a int
    memcpy(counter, &aad[OPT_LEN], sizeof(int));
    *counter = *counter + 1;

    // legge la dimensione della firma
    unsigned char* sign_len_byte =  (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(sign_len_byte, '\0', sizeof(int));
    if( !sign_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    int sign_len = 0;
    memcpy(sign_len_byte, &aad[OPT_LEN + sizeof(int)], sizeof(int));
    memcpy(&sign_len, sign_len_byte, sizeof(int)); // converte da byte a int

    // legge la firma
    unsigned char* sign = (unsigned char*) malloc(sizeof(unsigned char) * sign_len);
    memset(sign, '\0', sign_len);
    if( !sign){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    memcpy(sign, &aad[OPT_LEN + sizeof(int) + sizeof(int)], sign_len);

    // legge la dimensione della chiave pubblica
    unsigned char* epk_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(epk_len_byte, '\0', sizeof(int));
    if( !epk_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    int epk_len = -1;
    memcpy(epk_len_byte, &aad[OPT_LEN + sizeof(int) + sizeof(int) + sign_len], sizeof(int));
    memcpy(&epk_len, epk_len_byte, sizeof(int));

    // legge la chiave pubblica effimera del server
    unsigned char* buff_epk = (unsigned char*) malloc(sizeof(unsigned char) * epk_len);
    memset(buff_epk, '\0', epk_len);
    if( !buff_epk){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    memcpy(buff_epk, &aad[OPT_LEN + sizeof(int) + sizeof(int) + sign_len + sizeof(int)], epk_len);

    unsigned char* nonce_buff =(unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(nonce_buff, '\0', sizeof(int));
    if( !nonce_buff){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    memcpy(nonce_buff, &aad[OPT_LEN + sizeof(int) + sizeof(int) + sign_len + sizeof(int) + epk_len], sizeof(int));
    memcpy(nonceS, nonce_buff, sizeof(int));

    // crea il plaintext (nonceC || Ys) per verificare la firma
    int sign_plaintext_len = sizeof(int) + epk_len;
    unsigned char* sign_plaintext = (unsigned char*) malloc(sizeof(unsigned char) * sign_plaintext_len);
    memset(sign_plaintext, '\0', sign_plaintext_len);
    if( !sign_plaintext){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    unsigned char* nonce_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(nonce_byte, '\0', sizeof(int));
    if( !nonce_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(nonceC, nonce_byte);

    memcpy(sign_plaintext, nonce_byte, sizeof(int));
    memcpy(&sign_plaintext[sizeof(int)], buff_epk, epk_len);

    // verifica la firma e ottiene la chiave pubblica del server in formato EVP_PKEY
    int res = digital_signature_verify(sign, sign_len, sign_plaintext, sign_plaintext_len, client_pubKey, EVP_sha256());
    EVP_PKEY* p = NULL;
    if(res == 1){
        p = publicKey_to_EVP_PKEY(buff_epk, epk_len);
        if(p == NULL)
          handleErrors("Error in publicKey_to_EVP_PKEY");
    } else{
        printf("return value: %d\n", res);
        handleErrors("Error: invalid signature verification");
    }
    // decifra il ciphertext
    unsigned char* pt = (unsigned char*) malloc(sizeof(unsigned char) * (ct_len + 1));
    memset(pt, '\0', (ct_len + 1));
    if( !pt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    memset(pt, '\0', ct_len + 1);
    int result = gcm_decrypt(ct, ct_len, aad, aad_len, tag, session_key, iv, iv_len, pt);
    if(result <= 0)
      handleErrors("Error in gcm_decrypt\n");

    free(receive_buff);
	free(ct_len_byte);
	free(ct);
	free(tag);
	free(iv);
    free(aad);
	free(aad_len_byte);

    return p;
}

/* funzione per mandare la chiave effimera al client destinatario
        -> restituisce true se è andato tutto bene
        -> false altrimenti */
bool send_epk_client2(long sock, unsigned char* session_key, unsigned int* counter, EVP_PKEY* ephemeral_public_key, int nonce, EVP_PKEY *client_privKey){
    int error = 0;

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
      return false;
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

    // converte il nonce in byte
    unsigned char* nonce_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(nonce_byte, '\0', sizeof(int));
    if( !nonce_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(nonce, nonce_byte);

    // serializza la chiave pubblica effimera
    int epk_len = 0;
    unsigned char* serialize_epk = publicKey_to_byte(ephemeral_public_key, &epk_len);
    if(serialize_epk == NULL)
        handleErrors("Error in publicKey_to_byte");

    // converte epk_len da int a byte
    unsigned char* epk_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(epk_len_byte, '\0', sizeof(int));
    if( !epk_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(epk_len, epk_len_byte);

    // crea il messaggio da firmare (R2 (nonce from Bob)||Ya)
    int msg_to_sign_len = sizeof(int) + epk_len;
    unsigned char* msg_to_sign = (unsigned char*) malloc(sizeof(unsigned char) * msg_to_sign_len);
    memset(msg_to_sign, '\0', msg_to_sign_len);
    if( !msg_to_sign){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    memcpy((unsigned char*)msg_to_sign, (unsigned char*) nonce_byte, sizeof(int));
    memcpy((unsigned char*)&msg_to_sign[sizeof(int)], (unsigned char*) serialize_epk, epk_len);

    // firma il messaggio
    int sign_len = EVP_PKEY_size(client_privKey);
    unsigned char* sign = (unsigned char*) malloc(sizeof(unsigned char) * sign_len);
    memset(sign, '\0', sign_len);
    if( !sign){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    sign_len = digital_signature(msg_to_sign, msg_to_sign_len, sign, client_privKey, EVP_sha256());
    if(sign_len == -2)
      handleErrors("Error in digital_signature");

    // converte la sign_len in byte
    unsigned char* sign_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(sign_len_byte, '\0', sizeof(int));
    if( !sign_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(sign_len, sign_len_byte);

    // AAD = (msgtype || cont_server_client)
    int aad_len = OPT_LEN + sizeof(int) + sizeof(int) + sign_len + sizeof(int) + epk_len;
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
	*counter = *counter + 1;

	unsigned_int_to_byte(*counter, counter_byte);

    memcpy(aad, "in_chat", sizeof("in_chat"));
    memcpy(&aad[OPT_LEN], counter_byte, sizeof(int));
    memcpy(&aad[OPT_LEN + sizeof(int)], sign_len_byte, sizeof(int));
    memcpy(&aad[OPT_LEN + sizeof(int) + sizeof(int)], sign, sign_len);
    memcpy(&aad[OPT_LEN + sizeof(int) + sizeof(int) + sign_len], epk_len_byte, sizeof(int));
    memcpy(&aad[OPT_LEN + sizeof(int) + sizeof(int) + sign_len + sizeof(int)], serialize_epk, epk_len);

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

    return true;
}

/* funzione per leggere il nonce del client mittente
        -> restituisce il nonce se è andato tutto bene
        -> -1 altrimenti */
int read_nonce2(long sock, unsigned char* session_key, unsigned int* counter){
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
    if(error == -1){
		if(sock != -1)
			close(sock);
		handleErrors("Error in read_bytes1");
	}

    int payload_dim = 0;
    memcpy(&payload_dim, receive_buff, sizeof(int));

    // legge l'aad
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

    // legge il tag
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

    // legge l'IV
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

    // legge l'opt del messaggio
    unsigned char *opt =  (unsigned char*) malloc(sizeof(unsigned char) * OPT_LEN);
    memset(opt, '\0', OPT_LEN);
    if( !opt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

	// controlla il tipo del messaggio
    if(memcmp("in_chat", aad, sizeof("in_chat")) != 0){
		free(receive_buff);
		printf("Mi aspettavo l'OPT in_chat, invece trovo %s\n",aad);
        handleErrors("Error: opt type not match");
    }

    // converte il counter da byte a int
    memcpy(counter, &aad[OPT_LEN], sizeof(int));
    *counter = *counter + 1;

    // decifra il ciphertext
    unsigned char* pt = (unsigned char*) malloc(sizeof(unsigned char) * (ct_len + 1));
    memset(pt, '\0', (ct_len + 1));
    if( !pt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    memset(pt, '\0', ct_len + 1);
    int result = gcm_decrypt(ct, ct_len, aad, aad_len, tag, session_key, iv, iv_len, pt);
    if(result <= 0)
      handleErrors("Error in gcm_decrypt\n");

    int nonce = -1;
    // nonce da byte a int
    memcpy(&nonce, pt, sizeof(int));

    free(receive_buff);
	free(ct_len_byte);
	free(ct);
	free(tag);
	free(iv);
    free(aad);
	free(aad_len_byte);

    return nonce;
}

/* funzione per mandare nonce e chiave effimera ( R1 || Yb) con la firma del client mittente al client destinatario
        -> restituisce true se è andato tutto bene
        -> false altrimenti */
bool send_epk_client1(long sock, unsigned char* session_key, unsigned int* counter, EVP_PKEY* ephemeral_public_key, int nonceC1, int *nonceC2, EVP_PKEY *client_privKey){
    int error = 0;
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
      return false;
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

    // converte il nonce in byte
    unsigned char* nonce_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(nonce_byte, '\0', sizeof(int));
    if( !nonce_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(nonceC1, nonce_byte);

    // serializza la chiave pubblica effimera
    int epk_len = 0;
    unsigned char* serialize_epk = publicKey_to_byte(ephemeral_public_key, &epk_len);
    if(serialize_epk == NULL)
        handleErrors("Error in publicKey_to_byte");

    // converte epk_len da int a byte
    unsigned char* epk_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(epk_len_byte, '\0', sizeof(int));
    if( !epk_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(epk_len, epk_len_byte);

    // crea il messaggio da firmare (R1 (nonce from Alice)||Yb)
    int msg_to_sign_len = sizeof(int) + epk_len;
    unsigned char* msg_to_sign = (unsigned char*) malloc(sizeof(unsigned char) * msg_to_sign_len);
    memset(msg_to_sign, '\0', msg_to_sign_len);
    if( !msg_to_sign){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    memcpy((unsigned char*)msg_to_sign, (unsigned char*) nonce_byte, sizeof(int));
    memcpy((unsigned char*)&msg_to_sign[sizeof(int)], (unsigned char*) serialize_epk, epk_len);

    // firma il messaggio
    int sign_len = EVP_PKEY_size(client_privKey);
    unsigned char* sign = (unsigned char*) malloc(sizeof(unsigned char) * sign_len);
    memset(sign, '\0', sign_len);
    if( !sign){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    sign_len = digital_signature(msg_to_sign, msg_to_sign_len, sign, client_privKey, EVP_sha256());
    if(sign_len == -2)
      handleErrors("Error in digital_signature");

    // converte la sign_len in byte
    unsigned char* sign_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(sign_len_byte, '\0', sizeof(int));
    if( !sign_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(sign_len, sign_len_byte);

    // nonce da mandare al client
    *nonceC2 = rand();

    // converte da int a unsigned char
    unsigned char* rand_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(rand_byte, '\0', sizeof(int));
    if( !rand_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    int_to_byte(*nonceC2, rand_byte);

    // AAD = (msgtype || cont_server_client
    int aad_len = OPT_LEN + sizeof(int) + sizeof(int) + sign_len + sizeof(int) + epk_len + sizeof(int);
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
	*counter = *counter + 1;

	unsigned_int_to_byte(*counter, counter_byte);

    memcpy(aad, "in_chat", sizeof("in_chat"));
    memcpy(&aad[OPT_LEN], counter_byte, sizeof(int));
    memcpy(&aad[OPT_LEN + sizeof(int)], sign_len_byte, sizeof(int));
    memcpy(&aad[OPT_LEN + sizeof(int) + sizeof(int)], sign, sign_len);
    memcpy(&aad[OPT_LEN + sizeof(int) + sizeof(int) + sign_len], epk_len_byte, sizeof(int));
    memcpy(&aad[OPT_LEN + sizeof(int) + sizeof(int) + sign_len + sizeof(int)], serialize_epk, epk_len);
    memcpy(&aad[OPT_LEN + sizeof(int) + sizeof(int) + sign_len + sizeof(int) + epk_len], rand_byte, sizeof(int));

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

    return true;
}

/* funzione per leggere la firma del client mittente e verificarla
        -> restituisce la chiave effimera se è andato tutto bene
        -> NULL altrimenti */
EVP_PKEY* read_epk_client2(long sock, unsigned char* session_key, unsigned int* counter, int nonce, EVP_PKEY* client_pubKey){
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
    if(error == -1){
		if(sock != -1)
			close(sock);
		handleErrors("Error in read_bytes1");
	}

    int payload_dim = 0;
    memcpy(&payload_dim, receive_buff, sizeof(int));

    // legge l'aad
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

    // legge il tag
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

    // legge l'IV
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

    // legge l'opt del messaggio
    unsigned char *opt =  (unsigned char*) malloc(sizeof(unsigned char) * OPT_LEN);
    memset(opt, '\0', OPT_LEN);
    if( !opt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

	// controlla il tipo del messaggio
    if(memcmp("in_chat", aad, sizeof("in_chat")) != 0){
		free(receive_buff);
		printf("Mi aspettavo l'OPT in_chat, invece trovo %s\n",aad);
        handleErrors("Error: opt type not match");
    }

    // converte il counter da byte a int
    memcpy(counter, &aad[OPT_LEN], sizeof(int));
    *counter = *counter + 1;

    // decifra il ciphertext
    unsigned char* pt = (unsigned char*) malloc(sizeof(unsigned char) * (ct_len + 1));
    memset(pt, '\0', (ct_len + 1));
    if( !pt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    memset(pt, '\0', ct_len + 1);
    int result = gcm_decrypt(ct, ct_len, aad, aad_len, tag, session_key, iv, iv_len, pt);
    if(result <= 0)
      handleErrors("Error in gcm_decrypt\n");

    int sign_len = 0;
    memcpy(&sign_len, &aad[OPT_LEN + sizeof(int)], sizeof(int)); // converte da byte a int

    // legge la firma
    unsigned char* sign = (unsigned char*) malloc(sizeof(unsigned char) * sign_len);
    memset(sign, '\0', sign_len);
    if( !sign){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    memcpy(sign, &aad[OPT_LEN + sizeof(int) + sizeof(int)], sign_len);
    int epk_len = -1;
    memcpy(&epk_len, &aad[OPT_LEN + sizeof(int) + sizeof(int) + sign_len], sizeof(int));

    // legge la chiave pubblica effimera del client mittente (Alice)
    unsigned char* buff_epk = (unsigned char*) malloc(sizeof(unsigned char) * epk_len);
    memset(buff_epk, '\0', epk_len);
    if( !buff_epk){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    memcpy(buff_epk, &aad[OPT_LEN + sizeof(int) + sizeof(int) + sign_len + sizeof(int)], epk_len);

    // crea il plaintext (nonceC1 || Ya) per verificare la firma
    int sign_plaintext_len = sizeof(int) + epk_len;
    unsigned char* sign_plaintext = (unsigned char*) malloc(sizeof(unsigned char) * sign_plaintext_len);
    memset(sign_plaintext, '\0', sign_plaintext_len);
    if( !sign_plaintext){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    unsigned char* nonce_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(nonce_byte, '\0', sizeof(int));
    if( !nonce_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    int_to_byte(nonce, nonce_byte);

    memcpy(sign_plaintext, nonce_byte, sizeof(int));
    memcpy(&sign_plaintext[sizeof(int)], buff_epk, epk_len);
    fflush(stdout);

    // verifica la firma e ottiene la chiave pubblica del client1 (Alice) nel formato EVP_PKEY
    int res = digital_signature_verify(sign, sign_len, sign_plaintext, sign_plaintext_len, client_pubKey, EVP_sha256());
    EVP_PKEY* p = NULL;
    if(res == 1){
        p = publicKey_to_EVP_PKEY(buff_epk, epk_len);
        if(p == NULL)
          handleErrors("Error in publicKey_to_EVP_PKEY");
    } else
      handleErrors("Error: invalid signature verification");

    free(receive_buff);
	free(ct_len_byte);
	free(ct);
	free(tag);
	free(iv);
    free(aad);
	free(aad_len_byte);

    return p;
}

/* funzione per mandare il messaggio all'altro client */
int send_in_chat(thread_args_t *thread_arg, string plaintext){
    int sock = thread_arg->socket;
    unsigned int *counter = &(thread_arg->counter);
    unsigned int *counter_C = &(thread_arg->counter_C);
    int error = 0;

    /* Parametri da inserire all'interno dell'AAD tra client e server  */

    int pt_C_len = plaintext.size() + 1;
    int ct_C_len = pt_C_len +  EVP_CIPHER_block_size(EVP_aes_256_gcm());
    unsigned char* ct_C = (unsigned char*) malloc(sizeof(unsigned char) * ct_C_len);
    memset(ct_C, '\0', ct_C_len);
    if( !ct_C){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    int tag_C_len = TAG_LEN;
    unsigned char* tag_C = (unsigned char*) malloc(sizeof(unsigned char) * tag_C_len);
    memset(tag_C, '\0', tag_C_len);
    if( !tag_C){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    int iv_C_len = EVP_CIPHER_iv_length(EVP_aes_256_gcm());
    unsigned char* iv_C = (unsigned char*)malloc(iv_C_len);
    // seme OpenSSL PRNG
    RAND_poll();
    RAND_bytes((unsigned char*)&iv_C[0],iv_C_len);
    if(iv_C == NULL){
      return -1;
    }

    unsigned char* counter_C_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(counter_C_byte, '\0', sizeof(int));
    if( !counter_C_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
	*counter_C += 1;

	unsigned_int_to_byte(*counter_C, counter_C_byte);

    int aad_C_len = sizeof(int);
    unsigned char* aad_C = (unsigned char*) malloc(sizeof(unsigned char) * aad_C_len);
    memset(aad_C, '\0', aad_C_len);
    if( !aad_C){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    memcpy(aad_C, counter_C_byte, sizeof(int));

    unsigned char *aad_C_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(aad_C_len_byte, '\0', sizeof(int));
    if( !aad_C_len_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    unsigned_int_to_byte(aad_C_len, aad_C_len_byte);

    // trasformo il plaintext (string) in pt_C (unsigned char*)
    unsigned char* pt_C = (unsigned char*) malloc(sizeof(unsigned char) * pt_C_len);
    memset(pt_C, '\0', pt_C_len);
    if( !pt_C){
        if( sock != -1 )
            close(sock);
        handleErrors("Error on malloc");
    }
    memcpy(pt_C, plaintext.c_str(), pt_C_len);

    ct_C_len = gcm_encrypt(pt_C, pt_C_len, aad_C, aad_C_len, (unsigned char*) thread_arg->key_with_client, iv_C, iv_C_len, ct_C, tag_C);
    if( ct_C_len == -1)
        handleErrors("Error in gcm_encrypt");

    unsigned char *ct_C_len_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(ct_C_len_byte, '\0', sizeof(int));
    if( !ct_C_len_byte){
        if( sock != -1 )
            close(sock);
        handleErrors("Error on malloc");
    }
    unsigned_int_to_byte(ct_C_len, ct_C_len_byte);

    // AAD = (msgtype || count_client_server || dim AAD_C || AAD_C || dim ct_C || ct_C || tag_C || IV_C )
    //                                                        -> count_client1_client2
    int aad_len = OPT_LEN + sizeof(int) + sizeof(int) + aad_C_len + sizeof(int) + ct_C_len + tag_C_len + iv_C_len;
    unsigned char* aad = (unsigned char*) malloc(sizeof(unsigned char) * aad_len);
    memset(aad, '\0', aad_len);
    if( !aad){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    /* Fine parametri tra i due client e inizio di quelli tra client server  */

    unsigned char* counter_byte = (unsigned char*) malloc(sizeof(unsigned char) * sizeof(int));
    memset(counter_byte, '\0', sizeof(int));
    if( !counter_byte){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
	*counter = *counter + 1;

	unsigned_int_to_byte(*counter, counter_byte);

    memcpy(aad, "in_chat", sizeof("in_chat"));
    memcpy(&aad[OPT_LEN], counter_byte, sizeof(int));
    memcpy(&aad[OPT_LEN + sizeof(int)], aad_C_len_byte, sizeof(int));
    memcpy(&aad[OPT_LEN + sizeof(int) + sizeof(int)], aad_C, aad_C_len);
    memcpy(&aad[OPT_LEN + sizeof(int) + sizeof(int) + aad_C_len], ct_C_len_byte, sizeof(int));
    memcpy(&aad[OPT_LEN + sizeof(int) + sizeof(int) + aad_C_len + sizeof(int)], ct_C, ct_C_len);
    memcpy(&aad[OPT_LEN + sizeof(int) + sizeof(int) + aad_C_len + sizeof(int) + ct_C_len], tag_C, tag_C_len);
    memcpy(&aad[OPT_LEN + sizeof(int) + sizeof(int) + aad_C_len + sizeof(int) + ct_C_len + tag_C_len], iv_C, iv_C_len);

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

    // cifra il plaintext
    ct_len = gcm_encrypt(pt, pt_len, aad, aad_len,(unsigned char*) thread_arg->key, iv, iv_len, ct, tag);
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

/* funzione per creare la chiave di sessione lato client1 (Alice)
   -> restituisce 1 se è andato tutto bene */
int create_session_key_from_client1(long sock, unsigned char* session_key, unsigned int* count_client_server, unsigned int* count_server_client ,char* username, unsigned char *pk, int pk_len, thread_args_t *thread_arg, EVP_PKEY* priv_key){

    // [messaggio 5a]
    int nonceC = send_random_nonce2(sock, session_key, count_client_server);
    int nonceS = 0;

    EVP_PKEY *public_key = publicKey_to_EVP_PKEY(pk,pk_len);
    if(public_key == NULL)
        handleErrors("Error in publicKey_to_PKEY");
    // legge la chiave effimera del server [messaggio 6b]
    EVP_PKEY* ephemeral_pubKey_client2 = read_epk_server2(sock, session_key, count_server_client, nonceC, &nonceS, public_key);
    if(ephemeral_pubKey_client2 == NULL){
        perror("Error read server ephemeral_pubKey");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // genera le chiavi effimere e manda quella pubblica (i parametri DH)
    EVP_PKEY* ephemeral_public_key = NULL;
    EVP_PKEY* ephemeral_private_key = NULL;
    generate_ek(&ephemeral_private_key, &ephemeral_public_key);
    if(ephemeral_private_key == NULL)
        handleErrors("Error in generate_ek private key");
    if( ephemeral_public_key == NULL)
        handleErrors("Error in generate_ek public key");

    // manda ( Rs || Yc) con la firma [messaggio 7a]
    bool error = send_epk_client2(sock, session_key, count_client_server, ephemeral_public_key, nonceS, priv_key);
    if (!error)
        handleErrors("Error in send_epk");
    fflush(stdout);

    unsigned int digest_len = 0;
    unsigned char *digest = derive_shared_secret(ephemeral_private_key, ephemeral_pubKey_client2, &digest_len);

    const EVP_CIPHER* cipher = EVP_aes_128_cbc();
    int iv_len = EVP_CIPHER_iv_length(cipher);
    int key_len = EVP_CIPHER_key_length(cipher);
    int block_size = EVP_CIPHER_block_size(cipher);

    memset(thread_arg->key_with_client, '\0', key_len);
    if( !(thread_arg->key_with_client)){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    memcpy(thread_arg->key_with_client, digest, key_len);

    // alloca memoria per generare l'IV random
    unsigned char* iv = (unsigned char*)malloc(iv_len);
    // seme OpenSSL PRNG
    RAND_poll();
    RAND_bytes((unsigned char*)&iv[0],iv_len);
    /* fa la free del buffer segreto condiviso */
    #pragma optimize("", off)
        memset(digest, 0, digest_len);
    #pragma optimize("", on)
        free(digest);

    fflush(stdout);
    usleep(50000);
    return 1;
}

/* funzione per creare la chiave di sessione lato client2 (Bob)
   -> restituisce 1 se è andato tutto bene*/
int create_session_key_from_client2(long sock, unsigned char* session_key, unsigned int* count_client_server, unsigned int* count_server_client ,char* username, unsigned char *pk, int pk_len, thread_args_t *thread_arg, EVP_PKEY* priv_key){

    // legge il nonce del client1
    int nonceC1 = 0;
    int nonceC2 = 0;
    nonceC1 = read_nonce2(sock, session_key, count_server_client);

    char* file = (char*)malloc(sizeof(char)*30);

    EVP_PKEY *public_key = publicKey_to_EVP_PKEY(pk,pk_len);
    if(public_key == NULL)
        handleErrors("Error in publicKey_to_PKEY");

    // genera le chiavi effimere e manda quella pubblica (i parametri DH)
    EVP_PKEY* ephemeral_public_key = NULL;
    EVP_PKEY* ephemeral_private_key = NULL;
    generate_ek(&ephemeral_private_key, &ephemeral_public_key);
    if(ephemeral_private_key == NULL)
        handleErrors("Error in generate_ek private key");
    if( ephemeral_public_key == NULL)
        handleErrors("Error in generate_ek public key");

    fflush(stdout);

    // manda ( R1 || Yb) con la firma del client2
    bool error = send_epk_client1(sock, session_key, count_client_server, ephemeral_public_key, nonceC1, &nonceC2, priv_key);
    if (!error)
        handleErrors("Error in send_epk");

    /* legge la chiave effimera del client1 */
    EVP_PKEY* ephemeral_pubKey_client = read_epk_client2(sock, session_key, count_server_client, nonceC2, public_key);
    if(ephemeral_pubKey_client == NULL){
        perror("Error read server ephemeral_pubKey");
        close(sock);
        exit(EXIT_FAILURE);
    }

    unsigned int digest_len = 0;
    unsigned char *digest = derive_shared_secret(ephemeral_private_key, ephemeral_pubKey_client, &digest_len);

    const EVP_CIPHER* cipher = EVP_aes_128_cbc();
    int iv_len = EVP_CIPHER_iv_length(cipher);
    int key_len = EVP_CIPHER_key_length(cipher);
    int block_size = EVP_CIPHER_block_size(cipher);
    memset(thread_arg->key_with_client, '\0', key_len);
    if( !(thread_arg->key_with_client)){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    memcpy(thread_arg->key_with_client, digest, key_len);

    /* fa la free del buffer segreto condiviso */
    #pragma optimize("", off)
        memset(digest, 0, digest_len);
    #pragma optimize("", on)
        free(digest);

    fflush(stdout);
    usleep(50000);
    return 1;
}
