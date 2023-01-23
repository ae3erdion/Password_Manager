import base64
import os
import string
import random
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass

characters = list(string.ascii_letters + string.digits + "!@#$%^&*()")
site = ""
user = ""
password = ""
password_file = {}
encrypted = ""

# Generate key for encryption
def generate_key():
    password = getpass.getpass()
    password = bytes(password, 'utf-8')
    salt = b'\xceN\x01s\xabE\x15\x02\xd9pz(1\t\xbc4'
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,
    )
    global key
    key = base64.urlsafe_b64encode(kdf.derive(password))
    testkey = "7d#g8j$k2l3m5n6p7q8r9s0t@v#w$x%y^z&A*B("
    keyhash = Fernet(key).encrypt(testkey.encode())
# Check for the encryption key hash file exists and validate if the key is the same    
    if os.path.exists('password.hash'):
        with open('password.hash', 'rb') as f:
            key_validation = f.read()
        try:
            key_validation = Fernet(key).decrypt(key_validation)
            if key_validation.decode() == testkey:
                print("What would you like to do: ")    
                menu()
            else:
                print("Wrong password ") 
                exit
        except Exception:
                print("Wrong password")
                exit
 #If key hash file doesnt exist it create the file and write the encryption key hash to it       
    else: 
        with open('password.hash', 'wb') as f:
            f.write(keyhash)
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
    return random_password
    
# Write a new password to the password file
def add_password(site, user, password_site):
    site = base64.b64encode(site.encode()).hex()
    user = base64.b64encode(user.encode()).hex()
    password_file[site] = password_site
    with open('password.encode', 'a+') as f:
        encrypted = Fernet(key).encrypt(password_site.encode())
        f.write(site + "," + user + ":" + encrypted.decode() + "\n")
    

# Read password file and get the password 
def get_password(site):
    with open('password.encode', 'r') as f:
            for line in f:
               site, encrypted = line. split (":")
               site, user = site.split(",")
               site = base64.b64decode(bytes.fromhex(site)).decode()
               user = base64.b64decode(bytes.fromhex(user)).decode()
               password_file[site] = user, Fernet(key).decrypt(encrypted.encode()).decode()
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
    MENU
    (1) Generate random password
    (2) Add new password
    (3) Get login information
    (q) Quit""")

    done = False
    while not done:
        choice = input("Enter choice: ")
 # When selected generate random password       
        if choice == "1":
            print("Your password is: ")
            password = generate_password()
            password = str(password) 
# Add random password to file            
            answer = input("Do you want to add the password? Yes/No ")
            if answer.upper() == "YES":
                site = input("Enter the site: ")
                site = base64.b64encode(site.encode()).hex()
# Check if the site already exist                    
                with open('password.encode', 'r') as f:
                    site_validation = f.read()
                    if site in site_validation:
                        print("Site already exist!")
                    else:
                        user = input("Enter User: ")
                        add_password(site.upper(), user, password)
                        print("Done!")
            elif answer.upper() == "NO":
                pass
            

# When selected add password to file        
        elif choice == "2":
            site = input("Enter the site: ")
# Check if the site already exist             
            with open('password.encode', 'r') as f:
                site_validation = f.read()
                site = base64.b64encode(site.encode()).hex()
                if site in site_validation:
                    print("Site already exist!")
                    pass
                else:
                    user = input("Enter User: ")
                    password = input("Enter the password: ")
                    add_password(site.upper(), user, password)
                    print("Done!")
            
# When selected retrieve password from file        
        elif choice == "3":           
            site = input("Enter site: ")
            user, password = get_password(site.upper())
            print(f"Your login information for {user} @ {site.upper()} is ({password})")
            
# When selected exit program        
        elif choice == "q":
            done = True
            print("Bye!")
        
        else:
            print("Invalid Choice")

if __name__== "__main__":
    main()        
