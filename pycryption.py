import random, sys, os
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
    "ssgtgrd","moo6578n","sta35r","lq7eaf","roo0t","st2one","r4nd0m","p553lex"
    "su8grgd","m66f8n","suvc35r","l87ehf","roo0t","s9gxne","ksnd0m","posclex"
    "hadgd3","mkgose","67367767","lgsoiry96","r0skfyuht","ut2hs","r4iks","v07a3lex"
]

def derive_seed(token: str, nonce: int, extra: int = 0, rounds: int = 1000) -> int:
    MOD = (1 << 61) - 1
    acc = 1469598103934665603
    for i, ch in enumerate(token):
        acc = (acc * 1099511628211 + (ord(ch) + i*131 + 17)) % MOD
    acc = (acc ^ (nonce + 0x9e3779b97f4a7c15)) % MOD
    for r in range(rounds):
        acc = ((acc * 6364136223846793005) + (r * 1442695040888963407)) % MOD
        acc ^= (acc >> ((r % 13) + 1))
    return acc & ((1 << 63) - 1)

def keystream_bytes(seed: int, length: int):
    rng = random.Random(seed)
    return [rng.randrange(0, 256) for _ in range(length)]

def encrypt_bytes(data: bytes, token_index: int, nonce: int = None, seed_override: int = None):
    if nonce is None:
        nonce = random.getrandbits(64)
    token = TOKENS[token_index]
    seed = seed_override if seed_override is not None else derive_seed(token, nonce)
    ks = keystream_bytes(seed, len(data))
    cipher = [(data[i] + ks[i]) % 256 for i in range(len(data))]
    return token_index, nonce, cipher

def decrypt_bytes(token_index: int, nonce: int, cipher_list, seed_override: int = None):
    token = TOKENS[token_index]
    seed = seed_override if seed_override is not None else derive_seed(token, nonce)
    ks = keystream_bytes(seed, len(cipher_list))
    return bytes((cipher_list[i] - ks[i]) % 256 for i in range(len(cipher_list)))

def save_encrypted_file(out_path: Path, token_index: int, nonce: int, cipher_list):
    out_path.write_text(f"{token_index}\n{nonce}\n{','.join(map(str,cipher_list))}")

def load_encrypted_file(path: Path):
    text = path.read_text().splitlines()
    token_index = int(text[0].strip())
    nonce = int(text[1].strip())
    cipher_list = [int(x) for x in text[2].split(",") if x != ""]
    return token_index, nonce, cipher_list

def encrypt_file(path_str: str, seed_override: int = None):
    p = Path(path_str)
    data = p.read_bytes()
    token_index = random.randrange(len(TOKENS))
    token_index, nonce, cipher = encrypt_bytes(data, token_index, nonce=None, seed_override=seed_override)
    save_encrypted_file(p.with_suffix(p.suffix + ".enc"), token_index, nonce, cipher)

def decrypt_file(path_str: str, seed_override: int = None):
    p = Path(path_str)
    token_index, nonce, cipher_list = load_encrypted_file(p)
    plain = decrypt_bytes(token_index, nonce, cipher_list, seed_override=seed_override)
    out = p.with_suffix(p.suffix + ".dec")
    out.write_bytes(plain)

def interactive_text(seed_override: int = None):
    text = input("Enter text to encrypt: ")
    b = text.encode("utf-8")
    token_index = random.randrange(len(TOKENS))
    token_index, nonce, cipher = encrypt_bytes(b, token_index, nonce=None, seed_override=seed_override)
    print("Encrypted (numbers):", cipher)
    print("Token index:", token_index)
    print("Nonce:", nonce)
    recovered = decrypt_bytes(token_index, nonce, cipher, seed_override=seed_override)
    try:
        print("Decrypted:", recovered.decode("utf-8"))
    except:
        print("Decrypted (bytes):", recovered)

if __name__ == "__main__":
    args = sys.argv[1:]
    mode_encrypt = "--encrypt" in args
    mode_decrypt = "--decrypt" in args
    file_arg = None
    seed_override = None
    if "--file" in args:
        idx = args.index("--file")
        file_arg = args[idx+1]
    if "-seed" in args:
        idx = args.index("-seed")
        seed_override = int(args[idx+1])

    if mode_encrypt and file_arg:
        p = Path(file_arg)
        data = p.read_bytes()
        token_index = random.randrange(len(TOKENS))
        token_index, nonce, cipher = encrypt_bytes(data, token_index, nonce=None, seed_override=seed_override)
        save_encrypted_file(p.with_suffix(p.suffix + ".enc"), token_index, nonce, cipher)
        print(f"Encrypted {file_arg} -> {p.with_suffix(p.suffix + '.enc')}")
    elif mode_decrypt and file_arg:
        decrypt_file(file_arg, seed_override=seed_override)
    else:
        interactive_text(seed_override=seed_override)

