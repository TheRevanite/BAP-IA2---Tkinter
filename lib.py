import os
import hashlib
import sqlite3

if os.path.isdir(".Database"):
    os.chdir(".Database/")
else:
    os.mkdir(".Database")
    os.chdir(".Database/")
sql = sqlite3.connect("Database.db")

def fetch_from_database(ha_sh):
    cursor = sql.execute("select * from data_table")
    sql.commit()
    for row in cursor:
        if ha_sh==row[1]:
            return True
        if ha_sh==row[2]:
            return True
        if ha_sh==row[3]:
            return True
        if ha_sh==row[4]:
            return True
        if ha_sh==row[5]:
            return True
        if ha_sh==row[6]:
            return True
        if ha_sh==row[7]:
            return True
        if ha_sh==row[8]:
            return True
        if ha_sh==row[9]:
            return True
        if ha_sh==row[10]:
            return True
        if ha_sh==row[11]:
            return True
        if ha_sh==row[12]:
            return True
    else:
        return False

def fetch_from_database_storage(ha_sh):
    cursor = sql.execute("select * from data_table")
    sql.commit()
    for row in cursor:
        if ha_sh==row[1]:
            return ("md5", ha_sh)
        if ha_sh==row[2]:
            return ("sha1", ha_sh)
        if ha_sh==row[3]:
            return ("sha224", ha_sh)
        if ha_sh==row[4]:
            return ("blake2s", ha_sh)
        if ha_sh==row[5]:
            return ("blake2b", ha_sh)
        if ha_sh==row[6]:
            return ("sha3_384", ha_sh)
        if ha_sh==row[7]:
            return ("sha384", ha_sh)
        if ha_sh==row[8]:
            return ("sha3_512", ha_sh)
        if ha_sh==row[9]:
            return ("sha3_224", ha_sh)
        if ha_sh==row[10]:
            return ("sha512", ha_sh)
        if ha_sh==row[11]:
            return ("sha256", ha_sh)
        if ha_sh==row[12]:
            return ("sha3_256", ha_sh)
    else:
        return None

def get_username(hash_value):
    cursor = sql.execute("SELECT username FROM data_table WHERE md5=? OR sha1=? OR sha224=? OR blake2s=? OR blake2b=? OR sha3_384=? OR sha384=? OR sha3_512=? OR sha3_224=? OR sha512=? OR sha256=? OR sha3_256=?", (hash_value, hash_value, hash_value, hash_value, hash_value, hash_value, hash_value, hash_value, hash_value, hash_value, hash_value, hash_value,))
    row = cursor.fetchone()
    if row:
        return row[0]
    else:
        return None
    
    
def get_all_hashes(username):
    cursor = sql.execute("SELECT * FROM data_table where username=?", (username,))
    rows = cursor.fetchall()
    hashes = []
    for row in rows:
        for i in range(1, len(row)):
            if row[i] is not None:
                hashes.append(fetch_from_database_storage(row[i]))
    return hashes

def check_me(ck_word):
    cursor = sql.execute("select username from data_table")
    sql.commit()

    for row in cursor:
        if ck_word==row[0]:
            return False
    else:
        return True
    
def add_data(username, password):
    chk = check_me(username)
    if chk is False:
        return False
    if chk is True:
        md5 = hashlib.md5(password.encode()).hexdigest()
        sha1 = hashlib.sha1(password.encode()).hexdigest()
        sha224 = hashlib.sha224(password.encode()).hexdigest()
        blake2s = hashlib.blake2s(password.encode()).hexdigest()
        blake2b = hashlib.blake2b(password.encode()).hexdigest()
        sha3_384 = hashlib.sha3_384(password.encode()).hexdigest()
        sha384 = hashlib.sha384(password.encode()).hexdigest()
        sha3_512 = hashlib.sha3_512(password.encode()).hexdigest()
        sha3_224 = hashlib.sha3_224(password.encode()).hexdigest()
        sha512 = hashlib.sha512(password.encode()).hexdigest()
        sha256 = hashlib.sha256(password.encode()).hexdigest()
        sha3_256 = hashlib.sha3_224(password.encode()).hexdigest()

        sql.execute("INSERT INTO data_table (username, md5, sha1, sha224, blake2s, blake2b, sha3_384, sha384, sha3_512, sha3_224, sha512, sha256, sha3_256) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (username, md5, sha1, sha224, blake2s, blake2b, sha3_384, sha384, sha3_512, sha3_224, sha512, sha256, sha3_256))
        sql.commit()
        return True
