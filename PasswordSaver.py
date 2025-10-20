import hashlib, binascii, time, bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

def stream_wordlist(path):
    with open(path, "rb") as f:
        for line in f:
            pw = line.rstrip(b"\r\n")
            if pw:
                yield pw

def try_md5(wordlist):
    md5_hash = "0cf1390f2f34257cf588f3f4f3a8964a"
    md5_salt = "5d1e9695870aed7b"
    salt_bytes = binascii.unhexlify(md5_salt)
    for pw in stream_wordlist(wordlist):
        combined = pw + salt_bytes
        digest = hashlib.md5(combined).hexdigest()
        if digest == md5_hash:
            print(f"[✓] MD5 {md5_hash} -> {pw.decode()}")
            return
    print(f"[x] MD5 {md5_hash} (not found)")


def try_sha256(wordlist):
    hash = "b6fe82227ff583887cbf45c83429fd400643d9b647e91856a205300d616e40d8"
    salt = "785c0f01c3dbd71a"
    salt_bytes = binascii.unhexlify(salt)

    for pw in stream_wordlist(wordlist):
        for combo in [salt_bytes + pw, pw + salt_bytes]:
            if hashlib.sha256(combo).hexdigest().lower() == hash:
                print(f"[✓] SHA-256 {hash} -> {pw.decode()}")
                return
    print(f"[x] SHA-256 {hash} (not found)")

def try_bcrypt(wordlist):
    hash = "$2b$11$MkKpKb/fYkydwbdF4m4sYOQYyudVFY2pDq90aFMHOCptE/8/HFsTW"
    for pw in stream_wordlist(wordlist):
        if bcrypt.checkpw(pw, hash.encode()):
            print(f"[✓] bcrypt {hash} -> {pw.decode()}")
            return
    print(f"[x] bcrypt {hash} (not found)")

def try_argon2(wordlist):
    argon2_hash = "$argon2id$v=19$m=47104,t=4,p=1$3L/IzT8gua/fT+fx+15Csg$rN0WzRkmkZ7NKm868cdhMDl1hBzo8x9mJi7FLVTOnKw"
    ph = PasswordHasher()

    for pw in stream_wordlist(wordlist):
        try:
            if ph.verify(argon2_hash, pw.decode("utf-8", "ignore")):
                print(f"[✓] argon2 -> {pw.decode()}")
                return
        except VerifyMismatchError:
            continue
    print(f"[x] argon2 (not found)")

def main():
    print("[*] Starting cracking...")
    t0 = time.time()

    try_md5("rockyou_1000.txt")
    try_sha256("rockyou_1000.txt")
    try_bcrypt("rockyou_1000.txt")
    try_argon2("rockyou_1000.txt")

    print(f"[*] Done in {time.time()-t0:.2f}s")

if __name__ == "__main__":
    main()

