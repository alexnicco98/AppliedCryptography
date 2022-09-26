#!/bin/bash
chmod +x $0
server_dir="Server"
client_dir="Client"

# Create directory for server files.
if [[ ! -d $server_dir ]]; then
    mkdir $server_dir
else
	echo "Non è stato possibile creare la direcory '$server_dir': $!."
fi

# Create directory for client files.
if [[ ! -d $client_dir ]]; then
    mkdir $client_dir
else
	echo "Non è stato possibile creare la direcory '$client_dir': $!."
fi

# Initialize serial if it isn t already created.
if [[ ! -f "$server_dir/ca.serial" ]]; then
   touch $server_dir/ca.serial
   echo "01\n" > $server_dir/ca.serial
else
    echo "Non è stato possibile creare il file serial: $!"
fi

# Create index file if not existant.
if [[ ! -f "$server_dir/ca.index" ]]; then
   touch $server_dir/ca.index
else
    echo "Non è stato possibile creare il file index: $!"
fi

if [[ ! -f "$client_dir/crlnumber" ]]; then
    echo 1000 > ./Server/crlnumber
else
    echo "Non è stato possibile creare il file crlnumber: $!"
fi

# create CA private key and certificate
openssl genrsa -des3 -out ./$server_dir/privKey-ca.pem 1024
openssl req -new -x509 -days 3650 -key ./$server_dir/privKey-ca.pem -out ./$server_dir/cert-ca.pem \
    -config openssl.cnf
openssl ca -config openssl.cnf -keyfile ./$server_dir/privKey-ca.pem -cert ./$server_dir/cert-ca.pem \
    -gencrl -out ./$client_dir/crl-ca.pem
cp ./$server_dir/cert-ca.pem ./$client_dir/

# create server private key and public keys
openssl req -newkey rsa:1024 -keyout ./$server_dir/privKey-server.pem -nodes -config openssl.cnf -out server.req
openssl ca -config openssl.cnf -out server.crt -infiles server.req
openssl x509 -pubkey -noout -in 01.pem  > ./$server_dir/pubKey-server.pem
mv ./01.pem ./$server_dir/cert-server.pem

# create user private key and public key
openssl req -newkey rsa:1024 -keyout ./$client_dir/privKey-alice.pem -config openssl.cnf -out alice.req
openssl ca -config openssl.cnf -out alice.crt -infiles alice.req
openssl x509 -pubkey -noout -in 02.pem  > ./$client_dir/pubKey-alice.pem

openssl req -newkey rsa:1024 -keyout ./$client_dir/privKey-bob.pem -config openssl.cnf -out bob.req
openssl ca -config openssl.cnf -out bob.crt -infiles bob.req
openssl x509 -pubkey -noout -in 03.pem  > ./$client_dir/pubKey-bob.pem

openssl req -newkey rsa:1024 -keyout ./$client_dir/privKey-andrea.pem -config openssl.cnf -out andrea.req
openssl ca -config openssl.cnf -out andrea.crt -infiles andrea.req
openssl x509 -pubkey -noout -in 04.pem  > ./$client_dir/pubKey-andrea.pem

echo "fase di registrazione di inizializzazione delle coppie di chiavi e certificati finita"

# Remove temporary files that are used for creation
rm -f ./*.pem ./*.crt ./*.req
rm -f ./Server/ca.index ./Server/ca.serial ./Server/*.old ./Server/*.attr ./Server/crlnumber
echo "file temporanei rimossi con sucesso"
