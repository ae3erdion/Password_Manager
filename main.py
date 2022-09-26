import base64
import os
import string
import random
from unittest import TestCase
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

characters = list(string.ascii_letters + string.digits + "!@#$%^&*()")
site = ""
user = ""
password = ""
password_file = {}
encrypted = ""

# Generate key for encryption
def generate_key():
    password = input ("Enter password: ")
    password = bytes(password, 'utf-8')
    salt = b'\xceN\x01s\xabE\x15\x02\xd9pz(1\t\xbc4'
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=390000,
    )
    global key
    key = base64.urlsafe_b64encode(kdf.derive(password))
# Check for the encryption key hash file exists and validate if the key is the same    
    if os.path.exists('password.hash'):
        with open('password.hash', 'rb') as f:
            key_validation = f.read()
        if key_validation == key:
            print("What would you like to do: ")
            menu()
        else:
            print("Wrong password ") 
            exit
# If key hash file doesnt exist it create the file and write the encryption key hash to it       
    else: 
        with open('password.hash', 'wb') as f:
            f.write(key)
        with open('password.encode', 'wb') as f:
              
            print("What would you like to do: ")
            menu()
        

 
# Randon password generator
def generate_password():
    length = int(16)
    random.shuffle(characters)
    random_password = []
    for i in range(length):
        random_password.append(random.choice(characters))
    random.shuffle(random_password)
    random_password = ("".join(random_password))
    print(random_password)
    
# Write a new password to the pasword file
def add_password(site, user, password_site):
    password_file[site] = password_site
    with open('password.encode', 'a+') as f:
            encrypted = Fernet(key).encrypt(password_site.encode())
            f.write(site + " " + user + ":" + encrypted.decode() + "\n")

# Read password file and get the password 
def get_password(site):
    with open('password.encode', 'r') as f:
            for line in f:
               site, encrypted = line. split (":")
               password_file[site] = Fernet(key).decrypt(encrypted.encode()).decode()
    return password_file[site]

# Check for all files.  
def main():
    if os.path.exists('password.hash') & os.path.exists('password.encode'):
        print ("Welcome Back!")
        generate_key()
        
    else:
        print ("""
        Welcome!
        Create password""")
        generate_key()

# Menu of options
def menu():
    print("""
    (1) Generate random password
    (2) Add new password
    (3) Get login information
    (q) Quit""")

    done = False
    while not done:
        choice = input("Enter choice: ")
        if choice == "1":
            generate_password()
        elif choice == "2":
            site = input("Enter the site: ")
            user = input("Enter User: ")
            password = input("Enter the password: ")
            add_password(site, user, password)
        elif choice == "3":           
            site = input("Enter site: ")
            print(f"Your login information for {site} is ({get_password(site)})")  
        elif choice == "q":
            done = True
            print("Bye!")
        else:
            print("Invalid Choice")









if __name__== "__main__":
    main()        
 




   

    


