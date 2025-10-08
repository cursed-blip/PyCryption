import random, sys, os, time
from pathlib import Path

#---------------------------------------------------------------------------------------------------------
# u can change the tokens as much as u want and the seed deriving too
# made by sentinel
# isnt good for securing really crazy stuff like bank data but for simple lightwheight encrpytion its good
# around 98% lighter then AES 128/256
#---------------------------------------------------------------------------------------------------------

TOKENS = [
    "gh","s","j4","k1","uy","e","xc78","fdgy3","a45d","fhd5g","z3sf",
    "gf","236d","h","k4d","y","iurt","fb","v3c6","ghbdt","hg","df63ty",
    "47","6j","ghj","jfsg","567","5678","9","35","sd","fv","se",
    "54","67","589i","rt5y","5","alp51ha","be9a","gauytrmma","de543lta","oms5ega",
    "ssgtgrd","moo6578n","sta35r","lq7eaf","roo0t","st2one","r4nd0m","p553lex",
    "su8grgd","m66f8n","suvc35r","l87ehf","roo0t","s9gxne","ksnd0m","posclex",
    "hadgd3","mkgose","67367767","lgsoiry96","r0skfyuht","ut2hs","r4iks","v07a3lex"
]

def rol(val, r, bits=64):
    r %= bits
    return ((val << r) & ((1 << bits) - 1)) | (val >> (bits - r))

def derive_seed(token: str, nonce: int, extra: int = 0, rounds: int = 1000) -> int:
    MODMASK = (1 << 63) - 1
    acc = 1469598103934665603 ^ (nonce & MODMASK)
    for i, ch in enumerate(token):
        acc = (acc ^ (ord(ch) + i * 131 + 17)) & MODMASK
        acc = (acc * 1099511628211) & MODMASK
        acc = rol(acc ^ (i + nonce), (i % 17) + 1, bits=63)
    for r in range(rounds):
        acc = (acc ^ (r * 6364136223846793005 + extra)) & MODMASK
        acc = rol(acc, (r % 23) + 1, bits=63)
        acc = (acc * 1442695040888963407) & MODMASK
    return acc & MODMASK

def keystream_bytes(seed: int, length: int):
    x = seed & ((1 << 64) - 1)
    keystream = bytearray(length)
    for i in range(length):
        x = (6364136223846793005 * x + 1442695040888963407) & ((1 << 64) - 1)
        keystream[i] = (x >> 24) & 0xFF
    return keystream

def compute_tag(token_index: int, nonce: int, cipher_list):
    s = 0
    for i, v in enumerate(cipher_list):
        s = (s + ((v ^ (i * 131)) & 0xFFFFFFFF)) & 0xFFFFFFFF
    s = (s + (nonce & 0xFFFFFFFF) + ((token_index * 1315423911) & 0xFFFFFFFF)) & 0xFFFFFFFF
    s ^= ((s << 13) & 0xFFFFFFFF)
    s = (s + ((s >> 7) & 0xFFFFFFFF)) & 0xFFFFFFFF
    return s

def encrypt_bytes(data: bytes, token_index: int, nonce: int = None, seed_override: int = None):
    if nonce is None:
        nonce = random.getrandbits(64)
    token = TOKENS[token_index]
    seed = seed_override if seed_override is not None else derive_seed(token, nonce)
    ks = keystream_bytes(seed, len(data))
    cipher = bytearray((data[i] + ks[i]) & 0xFF for i in range(len(data)))
    tag = compute_tag(token_index, nonce, cipher)
    return token_index, nonce, cipher, tag

def decrypt_bytes(token_index: int, nonce: int, cipher_list, seed_override: int = None):
    token = TOKENS[token_index]
    seed = seed_override if seed_override is not None else derive_seed(token, nonce)
    ks = keystream_bytes(seed, len(cipher_list))
    return bytearray((cipher_list[i] - ks[i]) & 0xFF for i in range(len(cipher_list)))

def save_encrypted_file(out_path: Path, token_index: int, nonce: int, cipher_list, tag: int):
    out_path.write_text(f"{token_index}\n{nonce}\n{','.join(map(str,cipher_list))}\n{tag}")

def load_encrypted_file(path: Path):
    text = path.read_text().splitlines()
    token_index = int(text[0].strip())
    nonce = int(text[1].strip())
    cipher_list = bytearray(int(x) for x in text[2].split(",") if x != "")
    tag = int(text[3].strip()) if len(text) > 3 else None
    return token_index, nonce, cipher_list, tag

def encrypt_file(path_str: str, seed_override: int = None):
    p = Path(path_str)
    data = p.read_bytes()
    token_index = random.randrange(len(TOKENS))
    token_index, nonce, cipher, tag = encrypt_bytes(data, token_index, nonce=None, seed_override=seed_override)
    save_encrypted_file(p.with_suffix(p.suffix + ".enc"), token_index, nonce, cipher, tag)

def decrypt_file(path_str: str, seed_override: int = None):
    p = Path(path_str)
    token_index, nonce, cipher_list, tag = load_encrypted_file(p)
    if tag is None or compute_tag(token_index, nonce, cipher_list) != tag:
        raise ValueError("Integrity check failed: tag mismatch")
    plain = decrypt_bytes(token_index, nonce, cipher_list, seed_override=seed_override)
    out = p.with_suffix(p.suffix + ".dec")
    out.write_bytes(plain)

def interactive_text(seed_override: int = None):
    text = input("Enter text to encrypt: ")
    b = text.encode("utf-8")
    token_index = random.randrange(len(TOKENS))
    token_index, nonce, cipher, tag = encrypt_bytes(b, token_index, nonce=None, seed_override=seed_override)
    print("Encrypted (numbers):", list(cipher))
    print("Token index:", token_index)
    print("Nonce:", nonce)
    print("Tag:", tag)
    recovered = decrypt_bytes(token_index, nonce, cipher, seed_override=seed_override)
    try:
        print("Decrypted:", recovered.decode("utf-8"))
    except:
        print("Decrypted (bytes):", recovered)

def benchmark():
    size = 10 * 1024 * 1024  # 10 MB
    data = os.urandom(size)
    token_index = random.randrange(len(TOKENS))

    t1 = time.time()
    token_index, nonce, cipher, tag = encrypt_bytes(data, token_index)
    t2 = time.time()
    decrypt_bytes(token_index, nonce, cipher)
    t3 = time.time()

    enc_speed = size / (t2 - t1) / (1024 * 1024)
    dec_speed = size / (t3 - t2) / (1024 * 1024)
    print("Benchmarking Pycryption...")
    print(f"Encryption speed: {enc_speed:.1f} MB/s")
    print(f"Decryption speed: {dec_speed:.1f} MB/s")


if __name__ == "__main__":
    args = sys.argv[1:]
    mode_encrypt = "--encrypt" in args
    mode_decrypt = "--decrypt" in args
    mode_bench = "--benchmark" in args
    file_arg = None
    seed_override = None
    if "--file" in args:
        idx = args.index("--file")
        file_arg = args[idx+1]
    if "-seed" in args:
        idx = args.index("-seed")
        seed_override = int(args[idx+1])
    if mode_bench:
        benchmark()
    elif mode_encrypt and file_arg:
        encrypt_file(file_arg, seed_override=seed_override)
        print(f"Encrypted {file_arg} -> {Path(file_arg).with_suffix(Path(file_arg).suffix + '.enc')}")
    elif mode_decrypt and file_arg:
        decrypt_file(file_arg, seed_override=seed_override)
    else:
        interactive_text(seed_override=seed_override)
