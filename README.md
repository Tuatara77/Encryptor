# Encryptor

A python CLI encryptor that can encrypt and decrypt text, files and files within directories.

## Usage
```
python encryptor.py --help                Show this menu
                    --encrypt [key]       Encryption
                        --text [text]             Encrypts the text
                        --file [filename]         Encrypts the file
                        --directory [directory]   Encrypts all files in the directory

                    --decrypt [key]       Decryption
                        --text [text]             Decrypts the text
                        --file [filename]         Decrypts the file
                        --directory [directory]   Decrypts all files in the directory
Examples:
	python encryptor.py --encrypt cork --text quark
	python encryptor.py -d password -f banana.txt
```
