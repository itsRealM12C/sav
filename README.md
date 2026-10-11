# unitycipher-decryptor

Decrypts game save/config files protected by the open-source **UnityCipher**
helper class (`UnityCipher.RijndaelEncryption`) used by some Unity games —
entirely locally, no network requests, no third-party crypto dependency.

Confirmed working on **Baldi's Basics Classic Remastered**'s
`PlayerFile_!UnassignedFile.sav` / `PlayerConfig_!UnassignedFile.cfg`,
reverse-engineered directly from that game's `Assembly-CSharp.dll` via IL
disassembly (`monodis`). The scheme likely recurs in other Unity games built
with the same public library.

Two equivalent implementations are included:

- **`unitycipher-decryptor.html`** — a self-contained browser tool.
- **`unitycipher_decrypt.py`** — the same logic as a stdlib-only CLI
  (includes a from-scratch pure-Python Rijndael implementation — see below
  for why that's necessary).

## The format

```
base64-decoded file bytes:
  [ salt : N bytes ][ IV : N bytes ][ ciphertext : multiple of N bytes ]

where N = BufferKeySize, default 32

key = Rfc2898DeriveBytes(password, salt).GetBytes(N)
    = PBKDF2-HMAC-SHA1, 1000 iterations, N-byte output

cipher = Rijndael, BlockSize = N*8 bits, KeySize = N*8 bits, CBC, PKCS7 padding
```

### Why not just use a standard AES library?

Because it isn't standard AES. .NET's legacy `RijndaelManaged` supports
block sizes of 128/192/256 bits, unlike "AES" proper (which fixed the block
size at 128 bits when NIST standardized it). UnityCipher's default is a
**256-bit block** — every mainstream crypto library (PyCryptodome, OpenSSL,
the browser's Web Crypto `AES-CBC`) only implements the fixed 128-bit-block
variant and cannot decrypt this at all, even with the exact right key. Both
tools here include a from-scratch variable-block-size Rijndael
implementation (ported from the classic Bram Cohen public-domain reference)
specifically to handle this.

PBKDF2 itself isn't block-size-dependent, so that part *does* use standard
library/Web Crypto calls.

### The password

UnityCipher takes the password as a plain argument chosen by the calling
game. In the one confirmed case (Baldi's Basics CR), it's **the save file's
own name**, stripped of its `PlayerFile_`/`PlayerConfig_` prefix and
extension (e.g. `PlayerFile_!UnassignedFile.sav` → password
`!UnassignedFile`). Both tools guess this automatically but let you override
it — other games using this library may hardcode a different password
(findable the same way, via `monodis` + grepping IL near
`RijndaelEncryption::Encrypt`/`Decrypt` call sites).

## Usage

```
python3 unitycipher_decrypt.py PlayerFile_!UnassignedFile.sav
python3 unitycipher_decrypt.py save.sav --password "custom" -o out.json
python3 unitycipher_decrypt.py save.sav --buffer-key-size 16 --iterations 1000
```

Or just open `unitycipher-decryptor.html` in a browser.

## Credits

UnityCipher is a pre-existing open-source library — this repo doesn't claim
authorship of the scheme, only an independent clean-room re-implementation
of its decrypt path derived from disassembling a real shipped game that uses
it.

## License

MIT — see [LICENSE](LICENSE).
