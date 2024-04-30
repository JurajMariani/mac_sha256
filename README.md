# Cryptography 2024

## Bc. Juraj Mariani, xmaria03, <xmaria03@stud.fit.vutbr.cz>

## MAC implementation using SHA256 & Length extension attack

### SHA256

SHA256 is the backbone of the implementation. It has been implemented in accordance with NIST FIPS SHS publication of secure hashing algorithms.

The implementation has been tested and results compared with the output of builtin UNIX tool `sha256sum`.

### MAC

There is a naive implementation of a MAC function dictated by the following formula `MAC = SHA256(passwd + message)`.

### Length extension attack

The attack profile has been studied from provided references and implemented to the best of our abilities.

The attack has four key requirements:

* Length of password string is guessed
* Original message is captured
* The resulting MAC has been captured
* Implementation provides friendly interface / can be manipulated

And should be performed as such:

* The captured MAC is sat as the initial hash value
* The message block is recreated (including padding and length)
* A new block is supplied with the extension

Even though the first block has previously been a standalone block, now the extension has been concatenated behind it making it a normal block. Therefore padding and length is automatically inserted following the extended string. This should make the hash same as if the attacker knew the password.

This is possible due to the principle of SHA256.

```txt
mess0 -> | ... |    mess1 -> | ... |    mess2 ->
ihash -> | ... | -> hash1 -> | ... | -> hash2 -> and so on
```

The attack utilizes this by appending one more chain link:

```txt
-> messN-1 -> | ... |      extension -> | ... |
-> hashN-1 -> | ... | -> result hash -> | ... | -> new hash (attacker)
```

The hash is therefore calculated from `H(passwd + orig_message + extension)`

### Compilation

Compilation is facilitated via `make` tool and a provided `makefile`. To ensure correctness various compilation flags have been utilized along with address and leak sanitizers provided by `GCC`. The complete list can be found in the `makefile`. Current state of implementation has been tested on school server `Merlin` with successful compilation.

The compilation process generates an executable file `kry`.

### Execution

This tool can be executed on `UNIX` terminal.

```bash
$ ./kry
SHA256, MAC and Lenght Extension Attack demonstration tool.
Program has four modes:
        - SHA256 calculation
        - MAC calculation
        - MAC validation
        - Length extrnsion attack demonstration

For SHA256, add '-c' parameter
For MAC, add '-s' along with '-k passwd' to specify password
For MAC verification, add '-v' along with '-k passwd' and '-m MAC' to validate
For LEA demonstration, add '-e' along with '-m MAC', '-n passwdlen' and '-a extension'

**Please note that the program takes input message from STDIN.
```

Running the tool with no arguments prints a help message.
