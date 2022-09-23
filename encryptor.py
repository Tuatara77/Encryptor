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


def main(params:tuple[str]):
	if len(params) == 1: print(helptext)
	elif params[1] == "--help" or params[1] == "-h": print(helptext)
	elif len(params) == 5:
		if params[1] == "-e" or params[1] == "--encrypt":
			encryptor = Encryption(params[2])

			if params[3] == "-t" or params[3] == "--text":
				print(encryptor.encrypt(" ".join(params[4:]).encode()).decode())

			elif params[3] == "-f" or params[3] == "--file":
				t1 = perf_counter()
				encrypt_file(params[4], encryptor)
				print(f"Time: {perf_counter()-t1}")
			
			elif params[3] == "-d" or params[3] == "--directory":
				files = [(item[0]+os.sep+file, encryptor) for item in os.walk(params[4]) for file in item[-1]]

				t1 = perf_counter()
				with Pool() as pool:
					pool.starmap(encrypt_file, files)
				
				# for file in files:
				# 	try:
				# 		with open(file[0], "rb") as initial: 
				# 			contents = initial.read()
				# 		with open(file[0], "wb") as encrypted:
				# 			encrypted.write(encryptor.encrypt(contents))
				# 	except PermissionError: pass
				print(f"Time: {perf_counter()-t1}")

			else: print("Invalid arguments. Use python encryptor.py --help for details.")
	
		elif params[1] == "-d" or params[1] == "--decrypt":
			if params[3] == "-t" or params[3] == "--text":
				print(Encryption.decrypt(params[4].encode(), params[2]).decode())

			elif params[3] == "-f" or params[3] == "--file":
				t1 = perf_counter()
				decrypt_file(params[4], params[2])
				print(f"Time: {perf_counter()-t1}")
			
			elif params[3] == "-d" or params[3] == "--directory":
				files = [(item[0]+os.sep+file, params[2]) for item in os.walk(params[4]) for file in item[-1]]
				
				t1 = perf_counter()
				with Pool() as pool:
					pool.starmap(decrypt_file, files)
				
				# for file in files:
				# 	try:
				# 		with open(file[0], "rb") as initial: 
				# 			contents = initial.read()
				# 		with open(file[0], "wb") as decrypted:
				# 			try:
				# 				decrypted.write(Encryption.decrypt(contents, file[1]))
				# 			except InvalidToken:
				# 				decrypted.write(contents)
				# 				print("Incorrect key.")
				# 	except PermissionError: pass
				print(f"Time: {perf_counter()-t1}")

			else: print("Invalid arguments. Use python encryptor.py --help for details.")
		else: print("Invalid arguments. Use python encryptor.py --help for details.")
	else: 
		if params[1] == "-e" or params[1] == "--encrypt":
			encryptor = Encryption(params[2])
			if params[3] == "-t" or params[3] == "--text":
				print(encryptor.encrypt(" ".join(params[4:]).encode()).decode())
			else: print("Invalid arguments. Use python encryptor.py --help for details."); print("q")
		else: print("Invalid arguments. Use python encryptor.py --help for details.")

if __name__ == "__main__":
	main(argv)
