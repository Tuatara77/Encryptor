import os
import base64
from sys import argv
from time import perf_counter
from multiprocessing.pool import Pool
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ModuleNotFoundError:
    os.system(f"pip install cryptography")


helptext = """Usage:
	python encryptor.py --help\t\t Show this menu
\t\t\t    --encrypt [key]\t Encryption
\t\t\t\t  --text [text]\t\t\t Encrypts the text
\t\t\t\t  --file [filename]\t\t Encrypts the file
\t\t\t\t  --directory [directory]\t Encrypts all files in the directory

\t\t\t    --decrypt [key]\t Decryption
\t\t\t\t  --text [text]\t\t\t Decrypts the text
\t\t\t\t  --file [filename]\t\t Decrypts the file
\t\t\t\t  --directory [directory]\t Decrypts all files in the directory
Examples:
	python encryptor.py --encrypt cork --text quark
	python encryptor.py -d password -f banana.txt"""


class Encryption:
	def __init__(self, key):
		self.generate_key(key)

	def generate_key(self, key:str):
		kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
						 salt=b'salt', iterations=100000, backend=default_backend())
		self.key = base64.urlsafe_b64encode(kdf.derive(key.encode()))
		self.fernet = Fernet(self.key)
	
	def encrypt(self, text):
		return self.fernet.encrypt(text)
	
	@classmethod
	def decrypt(cls, text, key):
		cls.generate_key(cls, key)
		return cls.fernet.decrypt(text)


def encrypt_file(file, encryptor:Encryption):
	try:
		with open(file, "rb") as initial: 
			contents = initial.read()
		with open(file, "wb") as encrypted:
			encrypted.write(encryptor.encrypt(contents))
	except PermissionError: print("Permission Error")


def decrypt_file(file, key):
	try:
		with open(file, "rb") as initial: 
			contents = initial.read()
		with open(file, "wb") as decrypted:
			try:
				decrypted.write(Encryption.decrypt(contents, key))
			except InvalidToken:
				decrypted.write(contents)
				print("Incorrect key.")
	except PermissionError: print("Permission Error")


if __name__ == "__main__":
	if len(argv) == 1: print(helptext)
	elif argv[1] == "--help" or argv[1] == "-h": print(helptext)
	elif len(argv) == 5:
		if argv[1] == "-e" or argv[1] == "--encrypt":
			encryptor = Encryption(argv[2])

			if argv[3] == "-t" or argv[3] == "--text":
				print(encryptor.encrypt(" ".join(argv[4:]).encode()).decode())

			elif argv[3] == "-f" or argv[3] == "--file":
				encrypt_file(argv[4], encryptor)
			
			elif argv[3] == "-d" or argv[3] == "--directory":
				files = [(item[0]+os.sep+file, encryptor) for item in os.walk(argv[4]) for file in item[-1]]

				t1 = perf_counter()
				with Pool() as pool:
					pool.starmap(encrypt_file, files)
				
				print(f"Time: {perf_counter()-t1}")

					# This is testing/non-multiprocessing way it was done
				# for file in files:
				# 	encrypt_file(file)

				# for file in [item[0]+os.sep+file for item in os.walk(argv[4]) for file in item[-1]]:
				# 	try:
				# 		with open(file, "rb") as initial: 
				# 			contents = initial.read()
				# 		with open(file, "wb") as encrypted:
				# 			encrypted.write(encryptor.encrypt(contents))
				# 	except PermissionError: pass

			else: print("Invalid arguments. Use python encryptor.py --help for details.")
	
		elif argv[1] == "-d" or argv[1] == "--decrypt":
			if argv[3] == "-t" or argv[3] == "--text":
				print(Encryption.decrypt(argv[4].encode(), argv[2]).decode())

			elif argv[3] == "-f" or argv[3] == "--file":
				decrypt_file(argv[4], argv[2])
			
			elif argv[3] == "-d" or argv[3] == "--directory":
				files = [(item[0]+os.sep+file, argv[2]) for item in os.walk(argv[4]) for file in item[-1]]
				
				t1 = perf_counter()
				with Pool() as pool:
					pool.starmap(decrypt_file, files)
				print(f"Time: {perf_counter()-t1}")
				
					# This is testing/non-multiprocessing way it was done
				# for file in files:
				# 	try:
				# 		with open(file, "rb") as initial: 
				# 			contents = initial.read()
				# 		with open(file, "wb") as decrypted:
				# 			try:
				# 				decrypted.write(Encryption.decrypt(contents, argv[2]))
				# 			except InvalidToken:
				# 				decrypted.write(contents)
				# 				print("Incorrect key.")
				# 	except PermissionError: pass

			else: print("Invalid arguments. Use python encryptor.py --help for details.")
		else: print("Invalid arguments. Use python encryptor.py --help for details.")
	else: 
		if argv[1] == "-e" or argv[1] == "--encrypt":
			encryptor = Encryption(argv[2])
			if argv[3] == "-t" or argv[3] == "--text":
				print(encryptor.encrypt(" ".join(argv[4:]).encode()).decode())
			else: print("Invalid arguments. Use python encryptor.py --help for details.")
		else: print("Invalid arguments. Use python encryptor.py --help for details.")
