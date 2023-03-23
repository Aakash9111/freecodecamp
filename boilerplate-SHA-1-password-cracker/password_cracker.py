import hashlib

def crack_sha1_hash(hash,use_salts=False):
    if use_salts:
        return crack_sha1_hash_salt(hash)
    file = open("top-10000-passwords.txt",'r')
    for password in file.readlines():
        hashedpass = hashlib.sha1(password.strip().encode()).hexdigest()
        # print(hashedpass)
        if hash == hashedpass:
            file.close()
            return (password.strip())
    file.close()
    return "PASSWORD NOT IN DATABASE"

def check_salted_pass(password,hash):
    salts =  open("known-salts.txt",'r')
    for salt in salts.readlines():
            salt = salt.strip()
            hashedpass1 = hashlib.sha1((password+salt).encode()).hexdigest()
            hashedpass2 = hashlib.sha1((salt+password).encode()).hexdigest()
            if hash == hashedpass1:
                salts.close()
                return True
            if hash == hashedpass2:
                salts.close()
                return True
    salts.close()
    return False






def crack_sha1_hash_salt(hash):
    file = open("top-10000-passwords.txt",'r')
    for password in file.readlines():
        password = password.strip()
        if check_salted_pass(password,hash):
            file.close()
            return password

    file.close()
    return "PASSWORD NOT IN DATABASE"

print(crack_sha1_hash("53d8b3dc9d39f0184144674e310185e41a87ffd5",True))

