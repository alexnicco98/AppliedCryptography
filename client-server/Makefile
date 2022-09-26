#Makefile

test:
	echo "Execute test"
	./script.sh

clean:
	@echo "Removing garbage"
	-rm -f ./*.pem ./*.crt ./*.req
	-rm -f ./Client/*.pem ./Client/*.o
	-rm -f ./Server/ca.index ./Server/ca.serial ./Server/*.old ./Server/*.attr ./Server/crlnumber
	-rm -f ./Server/*.pem ./Server/*.o
