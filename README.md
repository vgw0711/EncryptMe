Crypto.sh Usage​ : Ensure crypto.sh has execution privileges. (To provide privileges enter : chmod +x <location of crypto.sh>)

File info:
receiver_private.pem (Receiver private key)
receiver_public.pem (Receiver public key)
sender_private.pem (Sender private key)
sender_public.pem (Sender public key)

Execution Command:

1.Encryption 

./crypto.sh -e <receiver_public_key_file> <sender_private_key_file> <plaintext_file> <encrypted_file>

When asked for the aes-256-cbc password, use password of your choice. (Be careful, it will ask to repeat the password, don’t press enter without repeating the same password.)
When asked for​ RSA passphrase, ​enter “​1234@Vishal​”

2.Decryption

./crypto.sh -d <receiver_private_key_file> <sender_public_key_file> <encrypted_file> <decrypted_file>

When asked for​ RSA passphrase, ​enter “​asdfg​”

Note:
You can generate your own RSA key pair and use the files generated instead of the files provided.
These files are just for test purposes.

