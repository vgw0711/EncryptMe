#!/bin/bash

function encryption(){
mkdir tobesent #temporary folder to store the data to be sent.
touch symmkey.key #temporary file to store the symmetric encryption key
#Generating Symmetric Key using Pseudorandom PRNG, which is why you will be asked for a password.
openssl aes-256-cbc -nosalt -P -in symmkey.key&>/dev/null
#Encrypting the symmetric key using public key encryption.
openssl rsautl -encrypt -inkey "$MASTERPUBLICKEY" -pubin -in symmkey.key -out tobesent/symmkey.enc&>/dev/null
#Encrypting the file supposed to be encrypted.
openssl enc -aes-256-cbc -in "$PLAINFILE" -out tobesent/"$ENCFILENAME".enc -k symmkey.key&>/dev/null
#Generating Checksum for the file that will be verified after decryption.
sha512sum "$PLAINFILE" | awk '{print $1}' > tobesent/checksum
#Generating digital signature for the encrypted file.
openssl dgst -sha256 -sign sender_private.pem -out /tmp/sign.sha256 tobesent/"$ENCFILENAME".enc
#Encoding the digital signature to base64 format
openssl base64 -in /tmp/sign.sha256 -out tobesent/dgtsign
#Compressing the files to be sent using tar.
tar -cvzf "$ENCFILENAME" tobesent&>/dev/null
#removing all the temporary files and folders generated while generation.
rm -r tobesent
rm symmkey.key
if [ -f "$ENCFILENAME" ]
then
echo "File Encrypted!"
else
echo "Failure"
fi
}

function decryption(){
#Extracting the files from the compressed file.
tar xvzf "$ENCFILE" &>/dev/null
#Decoding the base64 encoded digital signature.
openssl base64 -d -in tobesent/dgtsign -out tobesent/sign.sha256
#Verifying the signature.
SIGNCHECK="$(openssl dgst -sha256 -verify "$SNDRPUBKEY" -signature tobesent/sign.sha256 tobesent/"$ENCFILE".enc)"
#Deciding further steps based on digital signature verification output.
if [ "$SIGNCHECK" == "Verified OK" ]
then
#Decrypting the symmetric key.
openssl rsautl -decrypt -inkey "$MASTERPRIVKEY" -in tobesent/symmkey.enc -out tobesent/symmkey.key&>/dev/null
#decrypting the file.
openssl enc -d -aes-256-cbc -in tobesent/"$ENCFILE".enc -out "$DECFILE" -k symmkey.key&>/dev/null
#Calculating and verifying sha512 checksum of decrypted file with the checksum provided.
NEWCHECKSUM="$(sha512sum "$DECFILE" | awk '{print $1}')"
OGCHECKSUM="$(cat tobesent/checksum)"
if [ "$NEWCHECKSUM" == "$OGCHECKSUM" ]
then
echo "Hash Verified OK"
echo "Decryption of the file $ENCFILE done to the file $DECFILE"
else
echo "Hash Verification Failure"
fi
else
echo "$SIGNCHECK" 
fi
rm -r tobesent
}

#Handling user input using case statements.
case $1 in
[-][e])
#Assigning command line arguments to variables.
MASTERPUBLICKEY="$2"
SENDERPRIVKEY="$3"
PLAINFILE="$4"
ENCFILENAME="$5"
#passing all the required arguments to encryption function
encryption $MASTERPUBLICKEY $SENDERPRIVKEY $PLAINFILE $ENCFILENAME 
;;
[-][d])
MASTERPRIVKEY="$2"
SNDRPUBKEY="$3"
ENCFILE="$4"
DECFILE="$5"
#passing all the required arguments to decryption function
decryption $MASTERPRIVKEY $SNDRPUBKEY $ENCFILE $DECFILE
;;
*)
echo "You have only two options -e or -d. Please choose the correct one."
;;
esac

