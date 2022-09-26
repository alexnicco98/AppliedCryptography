#include <utility.h>
#include <stdio.h>

#define HEADER_LEN 34
#define HEADER_SESSION_LEN 4
#define OPT_LEN 30
#define TAG_LEN 16

using std::string;

int handleErrors(string msg){
	perror(msg.c_str());
	exit(EXIT_FAILURE);
}

void int_to_byte(int num, unsigned char* c){

    std::copy(static_cast<const char*>(static_cast<const void*>(&num)),
          static_cast<const char*>(static_cast<const void*>(&num)) + sizeof num,
          c);
}

void unsigned_int_to_byte(unsigned int num, unsigned char* c){

    std::copy(static_cast<const char*>(static_cast<const void*>(&num)),
          static_cast<const char*>(static_cast<const void*>(&num)) + sizeof num,
          c);
}

int certificate_verification(char *cert_CA_path, char *crl_CA_path, X509* cert){

	int error = 0;
    FILE* cert_CA_file = fopen(cert_CA_path, "r");
    if(!cert_CA_file)
		handleErrors("Error in fopen");

    X509* cert_CA = PEM_read_X509(cert_CA_file, NULL, NULL, NULL);
    fclose(cert_CA_file);
    if(!cert_CA)
		handleErrors("Error in PEM_read_X509");

    FILE* crl_CA_file = fopen(crl_CA_path, "r");
    if(!crl_CA_file)
		handleErrors("Error in fopen");

    X509_CRL* crl = PEM_read_X509_CRL(crl_CA_file, NULL, NULL, NULL);
    fclose(crl_CA_file);
    if(!crl)
		handleErrors("Error in PEM_read_X509_CRL");

    X509_STORE* st = X509_STORE_new();
    if(!st)
		handleErrors("Error in X509_STORE_new");

    error = X509_STORE_add_cert(st, cert_CA);
	if(!error)
		handleErrors("Error in X509_STORE_add_cert");

    error = X509_STORE_add_crl(st, crl);
	if(!error)
		handleErrors("Error in X509_STORE_add_crl");

    error = X509_STORE_set_flags(st, X509_V_FLAG_CRL_CHECK);
	if(!error)
		handleErrors("Error in X509_STORE_set_flags");


    // Verifica del certificato del peer
    X509_STORE_CTX* cert_ctx = X509_STORE_CTX_new();
	if(!cert_ctx)
		handleErrors("Error in X509_STORE_CTX_new");

    // Inizializzazione contesto per la verifica
    error = X509_STORE_CTX_init(cert_ctx, st, cert, NULL);
	if(!error)
		handleErrors("Error in X509_STORE_CTX_init");

    // Verifica certificato del peer
    error = X509_verify_cert(cert_ctx);
    if(error != 1) {
        printf("ERROR: certificato non valido\n");
        return -1;
    }
    return 1;
}

unsigned char* publicKey_to_byte(EVP_PKEY *pk, int* pk_len){

    BIO *bio = NULL;
    unsigned char *key = NULL;
    int key_len = 0;
    bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pk);
    key_len = BIO_pending(bio);
    *pk_len = key_len;

    key = (unsigned char *) malloc(sizeof(unsigned char) * key_len);
    BIO_read(bio, key, key_len);
    BIO_free_all(bio);
    return key;
}

// Generazione e restituzione parametri DH
void generate_ek(EVP_PKEY** eprivK, EVP_PKEY** epubK) {

    // Utilizzo i parametri incorporati
    EVP_PKEY *params;
    BIO *bio1 = NULL;
	BIO *bio2 = NULL;
    if(NULL == (params = EVP_PKEY_new()))
        handleErrors("Error in EVP_PKEY_new");
	if(1 != EVP_PKEY_assign(params, EVP_PKEY_DHX, DH_get_2048_256()))
	    handleErrors("Error in EVP_PKEY_set1_DH");

    // Creare un contesto per la generazione di chiavi
    EVP_PKEY_CTX *DHctx;
    if(!(DHctx = EVP_PKEY_CTX_new(params, NULL)))
        handleErrors("Error in EVP_PKEY_CTX_new");

    // Generazione di una nuova chiave
    if(1 != EVP_PKEY_keygen_init(DHctx))
        handleErrors("Error in EVP_PKEY_keygen_init");
    if(1 != EVP_PKEY_keygen(DHctx, &(*eprivK)))
        handleErrors("Error in EVP_PKEY_keygen");

	// Estrazione chiave privata
    bio1 = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio1, *eprivK, NULL, NULL, 0, NULL, NULL);
    PEM_read_bio_PrivateKey(bio1, &(*eprivK), NULL, NULL);
    BIO_free_all(bio1);

    // Estrazione chiave pubblica
    bio2 = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio2, *eprivK);
    PEM_read_bio_PUBKEY(bio2, &(*epubK), NULL, NULL);
    BIO_free_all(bio2);

	EVP_PKEY_free(params);
	EVP_PKEY_CTX_free(DHctx);
}

unsigned char* derive_shared_secret(EVP_PKEY *eprivK, EVP_PKEY *peer_pubK, unsigned int *digest_len){
	EVP_PKEY_CTX *derive_ctx;
	unsigned char *skey;
	size_t skey_len;

	derive_ctx = EVP_PKEY_CTX_new(eprivK,NULL);
	if (!derive_ctx)
		handleErrors("Error in EVP_PKEY_CTX_new\n");
	if (EVP_PKEY_derive_init(derive_ctx) <= 0)
		handleErrors("Error in EVP_PKEY_derive_init\n");
	// Impostare il peer con la sua pubkey
	if (EVP_PKEY_derive_set_peer(derive_ctx, peer_pubK) <= 0)
		handleErrors("Error in EVP_PKEY_derive_set_peer\n");

	// Determinare la lunghezza del buffer
	EVP_PKEY_derive(derive_ctx, NULL, &skey_len);

	// Allocare buffer per il secgreto condiviso
	skey = (unsigned char*)(malloc(int(skey_len)));
	if (!skey)
		handleErrors("Error nella malloc\n");

	// Eseguire nuovamente la derivazione e memorizzarla nel buffer skey
	if (EVP_PKEY_derive(derive_ctx, skey, &skey_len) <= 0)
		handleErrors("Error in EVP_PKEY_derive\n");

	unsigned char* digest;

	// Creazione e inizializzazione contesto
	EVP_MD_CTX *Hctx = EVP_MD_CTX_new();

	// Allocazione memoria per il digest
	digest = (unsigned char*) malloc(EVP_MD_size(EVP_sha256()));

	// Inizializzazione, aggiornamento e finalizzazione del digest
	EVP_DigestInit(Hctx, EVP_sha256());
	EVP_DigestUpdate(Hctx, (unsigned char*) skey, skey_len);
	EVP_DigestFinal(Hctx, digest, &(*digest_len));

	EVP_MD_CTX_free(Hctx);
	EVP_PKEY_CTX_free(derive_ctx);
	EVP_PKEY_free(peer_pubK);
	EVP_PKEY_free(eprivK);

	return digest;
}

int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int ciphertext_len = -1;

    // Creare e inizializzare il contesto
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors("Error in EVP_CIPHER_CTX_new");

    //  Inizializzare l'operazione di cifratura
    if(1 != EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv))
        handleErrors("Error in EVP_EncryptInit");

    //  Fornire tutti i dati AAD. Questo può essere chiamato zero o più volte come richiesto
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors("Error in EVP_EncryptUpdate1");

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors("Error in EVP_EncryptUpdate2");
    ciphertext_len = len;

	// Finalizzare la cifratura
    if(1 != EVP_EncryptFinal(ctx, ciphertext + len, &len))
        handleErrors("Error in EVP_EncryptFinal");
    ciphertext_len += len;

    // Ottenere il tag
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
        handleErrors("Error in EVP_CIPHER_CTX_ctrl");

    // Pulizia contesto
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    // Creare e inizializzare il contesto
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors("Error in EVP_CIPHER_CTX_new");
    if(!EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv))
        handleErrors("Error in EVP_DecryptInit");

	// Fornire tutti i dati AAD
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors("Error in EVP_DecryptUpdate");

	// Fornire il messaggio da decifrare e ottenere l'output del testo in chiaro
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors("Error in EVP_DecryptUpdate");
    plaintext_len = len;

    // Imposta il valore del tag atteso
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag))
        handleErrors("Error in EVP_CIPHER_CTX_ctrl");
    ret = EVP_DecryptFinal(ctx, plaintext + len, &len);

    // Pulizia contesto
    EVP_CIPHER_CTX_cleanup(ctx);

    if(ret <= 0) {
        printf("Error, ret_len: %d\n", ret);
        return -1;

    } else {
        // Successo
        plaintext_len += len;
        return plaintext_len;
    }
}

unsigned char* online_user_list(long sock, unsigned char* key, unsigned int *counter){

    int error = 0;

    // Lettura header del messaggio
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

    // Lettura AAD
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

    // Lettura ciphertext
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

    // Lettura tag
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

    // Lettura IV
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

    // Lettura messaggio opt
    unsigned char *opt =  (unsigned char*) malloc(sizeof(unsigned char) * OPT_LEN);
    memset(opt, '\0', OPT_LEN);
    if( !opt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

	// Controllo tipo del messaggio
    if(memcmp("list", aad, sizeof("list")) != 0){
		free(receive_buff);
		printf("Mi aspettavo l'OPT list, invece trovo %s\n",aad);
        handleErrors("Error: opt type not match");
    }

    // Convertire contatore da byte a int
    memcpy(counter, &aad[OPT_LEN], sizeof(int));
    *counter = *counter + 1;


    // Decifrare il ciphertext
    unsigned char* pt = (unsigned char*) malloc(sizeof(unsigned char) * (ct_len + 1));
    memset(pt, '\0', (ct_len + 1));
    if( !pt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    memset(pt, '\0', ct_len + 1);
    int result = gcm_decrypt(ct, ct_len, aad, aad_len, tag, key, iv, iv_len, pt);
    if(result <= 0)
      handleErrors("Error in gcm_decrypt\n");

    printf("\n[------ ONLINE USERS ------]\n\n %s\n", pt);
    printf("[--------------------------]\n");

    free(receive_buff);
	free(ct_len_byte);
	free(ct);
	free(tag);
	free(iv);
    free(aad);
	free(aad_len_byte);

    return pt;

}

char* chat_request_response(long sock, unsigned char *key, unsigned int *counter){
	int error = 0;
	char *res =(char*) malloc(sizeof(char)*OPT_LEN);

    // Lettura header del messaggio
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

    // Lettura AAD
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

    // Lettura ciphertext
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

    // Lettura tag
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

    // Lettura IV
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

    // Lettura messaggio opt
    unsigned char *opt =  (unsigned char*) malloc(sizeof(unsigned char) * OPT_LEN);
    memset(opt, '\0', OPT_LEN);
    if( !opt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

	// Controllo tipo del messaggio
    if(memcmp("yeschat", aad, sizeof("yeschat")) == 0){
		printf("Risposta di richiesta chat affermativa\n");
		memcpy(res, "yes\0", sizeof("yes\0"));
    } else{
		printf("Risposta di richiesta chat negativa: %s\n", aad);
		memcpy(res, "no\0", sizeof("no\0"));
	}

    // Converti contatore da byte a int
    memcpy(counter, &aad[OPT_LEN], sizeof(int));
    *counter = *counter + 1;

    // Decifrare il ciphertext
    unsigned char* pt = (unsigned char*) malloc(sizeof(unsigned char) * (ct_len + 1));
    memset(pt, '\0', (ct_len + 1));
    if( !pt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    memset(pt, '\0', ct_len + 1);
    int result = gcm_decrypt(ct, ct_len, aad, aad_len, tag, key, iv, iv_len, pt);
    if(result <= 0)
      handleErrors("Error in gcm_decrypt\n");

    free(receive_buff);
   	free(ct_len_byte);
	free(ct);
	free(tag);
	free(iv);
    free(aad);
	free(aad_len_byte);

    return res;
}

/* funzione che legge la chiave pubblica mandata dal server del client con
   cui vogliamo chattare, passiamo public_key_len in modo che il client sappia
   la dimensione della chave pubblica ed insfine restituisce quest'ultima */
unsigned char* read_pub_key(long sock, unsigned char *key, unsigned int *counter, int *public_key_len){
	int error = 0;

    // Lettura header del messaggio
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

    // Lettura AAD
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

    // Lettura ciphertext
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

    // Lettura tag
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

    // Lettura IV
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

    // Lettura messaggio opt
    unsigned char *opt =  (unsigned char*) malloc(sizeof(unsigned char) * OPT_LEN);
    memset(opt, '\0', OPT_LEN);
    if( !opt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

	// Controllo tipo del messaggio
    if(memcmp("pubKey", aad, sizeof("pubKey")) != 0){
		printf("%.6s\n",aad);
		handleErrors("Error opt not match with pubKey");
	}

    // Convertire contatore da byte a int
    memcpy(counter, &aad[OPT_LEN], sizeof(int));
    *counter = *counter + 1;

    // Decifrare il ciphertext
    unsigned char* pt = (unsigned char*) malloc(sizeof(unsigned char) * (ct_len + 1));
    memset(pt, '\0', (ct_len + 1));
    if( !pt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
    memset(pt, '\0', ct_len + 1);
    int result = gcm_decrypt(ct, ct_len, aad, aad_len, tag, key, iv, iv_len, pt);
    if(result <= 0)
      handleErrors("Error in gcm_decrypt\n");

  	*public_key_len = ct_len + 1;

    free(receive_buff);
	free(ct_len_byte);
	free(ct);
	free(tag);
	free(iv);
    free(aad);
	free(aad_len_byte);

    return pt;
}

/* funzione per leggere il certificato nella locazione specificata
 		-> restituisce il certificato se è andato tutto bene
		-> NULL altrimenti */
unsigned char* read_cert(char *cert_path, int* cert_size){

    FILE* f_cert = fopen(cert_path, "r");
    if(!f_cert)
		handleErrors("Error in fopen");

    X509* cert = PEM_read_X509(f_cert, NULL, NULL, NULL);
    if(!cert)
		handleErrors("Error in PEM_read_X509");
    fclose(f_cert);

    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);

    unsigned char* buff_cert = NULL;
    *cert_size = BIO_get_mem_data(bio, &buff_cert);
    if((*cert_size) < 0)
		handleErrors("Error in BIO_get_mem_data");
    return buff_cert;
}

int send_bytes(long sock, void *buf, size_t size) {
    size_t left = size;
    int r;
    int letto_tmp = 0;
    char *bufptr = (char*)buf;

    while(left > 0) {
        if ((r = send(sock, bufptr, left, 0)) == -1 ) {
            if (errno == EINTR) continue;
            return -1;
        }

        if (r == 0) return 0;

        left    -= r;
        bufptr  += r;
        letto_tmp = letto_tmp + r;
    }

    return letto_tmp;
}

int read_bytes(long sock, void *buf, size_t size){
    size_t left = size;
    int r = 0;
    int letto_tmp = 0;
    char *bufptr = (char*)buf;

    while(left > 0) {
        if ((r = read(sock ,bufptr,left)) == -1) {
            if (errno == EINTR){
                continue;
            }
            else{
                if(errno == EAGAIN || errno == EWOULDBLOCK){ // per gestire il timeout sul socket
                    return -2;
                }
                  return -1; // errore generico
            }
        }
        if (r == 0){ return 0; }   // gestione chiusura del socket

        left    -= r;
        bufptr  += r;
        letto_tmp = letto_tmp + r;
    }

    return letto_tmp;
}

EVP_PKEY* read_publicKey(char *file){

   FILE* fd = fopen(file, "r");
   if(fd == NULL)
   		handleErrors("Error in fopen");
   EVP_PKEY* public_key = PEM_read_PUBKEY(fd, NULL, NULL, NULL);
   if(public_key == NULL)
   		handleErrors("Error in PEM_read_PUBKEY");
   fclose(fd);
   return public_key;
}

EVP_PKEY* read_privateKey(char *file){

    FILE* fd = fopen(file, "r");
    if(fd == NULL)
        handleErrors("Error in fopen");
    EVP_PKEY* private_key = PEM_read_PrivateKey(fd, NULL, NULL, NULL);
    fclose(fd);
    return private_key;
}

int online_user_list_request(long sock, unsigned char* session_key, unsigned int *counter){
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

    // Seme OpenSSL PRNG
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

    unsigned_int_to_byte(*counter, counter_byte);

    *counter = *counter + 1;

    unsigned char* opt = (unsigned char*) malloc(sizeof(unsigned char) * OPT_LEN);
    memset(opt, '\0', OPT_LEN);
    if( !opt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    memcpy(opt, "list_rq", OPT_LEN - 1);
    memcpy(aad, opt, OPT_LEN - 1);
    memcpy(&aad[OPT_LEN], counter_byte, sizeof(int));

    // Cifrare il plaintext
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

int send_chat_request(long sock, unsigned char* session_key, unsigned int *counter, string user_to_send){

    int error = 0;

    int pt_len = strlen(user_to_send.c_str());
    unsigned char* pt = (unsigned char*) malloc(sizeof(unsigned char) * pt_len);
    memset(pt, '\0', pt_len);
    if( !pt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

  	memcpy(pt, user_to_send.c_str(), pt_len);

    int iv_len = EVP_CIPHER_iv_length(EVP_aes_256_gcm());
    unsigned char* iv = (unsigned char*)malloc(iv_len);

    // Seme OpenSSL PRNG
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

    // Cifrare il plaintext
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

/* chiedo al server di mettere l'utente disponibile per chattare */
int wait_chat(long sock, unsigned char* session_key, unsigned int* counter){
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

    // Seme OpenSSL PRNG
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

    unsigned char* opt = (unsigned char*) malloc(sizeof(unsigned char) * OPT_LEN);
    memset(opt, '\0', OPT_LEN);
    if( !opt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    memcpy(opt, "wait", OPT_LEN - 1);
    memcpy(aad, opt, OPT_LEN -1);
    memcpy(&aad[OPT_LEN], counter_byte, sizeof(int));

    // Cifrare il plaintext
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

/* chiedo al server di mettere l'utente non disponibile per chattare*/
int stop_wait_chat(long sock,unsigned char* session_key, unsigned int* counter){
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

    // Seme OpenSSL PRNG
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

    unsigned char* opt = (unsigned char*) malloc(sizeof(unsigned char) * OPT_LEN);
    memset(opt, '\0', OPT_LEN);
    if( !opt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }

    memcpy(opt, "stop", OPT_LEN - 1);
    memcpy(aad, opt, OPT_LEN -1);
    memcpy(&aad[OPT_LEN], counter_byte, sizeof(int));

    // Cifrare il plaintext
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

/* dico al server che il client rifiuta la richiesta di chat da parte di respond_to_user
   e restituisco 0 se tutto va bene, -1 altrimenti */
int negative_chat_response_to_server(long sock, unsigned char* session_key, unsigned int* counter,unsigned char* respond_to_user, int respond_to_user_len){
    int error = 0;
	int pt_len = respond_to_user_len;

    unsigned char* pt = (unsigned char*) malloc(sizeof(unsigned char) * pt_len);
    memset(pt, '\0', pt_len);
    if( !pt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
	  memcpy(pt, respond_to_user, pt_len);

    int iv_len = EVP_CIPHER_iv_length(EVP_aes_256_gcm());
    unsigned char* iv = (unsigned char*)malloc(iv_len);

    // Seme OpenSSL PRNG
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

    memcpy(aad, "nochat", sizeof("nochat"));
    memcpy(&aad[OPT_LEN], counter_byte, sizeof(int));

    // Cifrare il plaintext
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

/* dico al server che il client eccetta la richiesta di chat da parte di respond_to_user
   e restituisco 0 se tutto va bene, -1 altrimenti */
int positive_chat_response_to_server(long sock, unsigned char* session_key, unsigned int* counter,unsigned char* respond_to_user, int respond_to_user_len){
    int error = 0;

    int pt_len = respond_to_user_len;

    unsigned char* pt = (unsigned char*) malloc(sizeof(unsigned char) * pt_len);
    memset(pt, '\0', pt_len);
    if( !pt){
        if( sock != -1 )
             close(sock);
        handleErrors("Error on malloc");
    }
	memcpy(pt, respond_to_user, pt_len);

    int iv_len = EVP_CIPHER_iv_length(EVP_aes_256_gcm());
    unsigned char* iv = (unsigned char*)malloc(iv_len);

    // Seme OpenSSL PRNG
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

    memcpy(aad, "yeschat", sizeof("yeschat"));
    memcpy(&aad[OPT_LEN], counter_byte, sizeof(int));

    // Cifrare il plaintext
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
