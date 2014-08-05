tap11tools
========

tap11tools is a utility software to operate security token device.
this utility allow follow operations.

* initialize token
* change pin
* init pin(user pin unlock and set newpin)
* generate and store key(only rsa)
* make csr with the key inside token
* store certificate to token
* store rsa keypair to token
* list keys in token
* list certs in token

tap11tools uses libp11.so you need pkcs#11 library for your token.

## build

    % autoreconf -i -f
    % ./configure
    % make
    % make install

## commands

#### tap11_init_token

tap11_init_token initialize token.

    % tap11_init_token <pkcs11_library> <sopin> <pin>

    Example:
      % tap11_init_token /usr/lib/libsomevenderspkcs11.so 1234 5678

#### tap11_change_pin

tap11_change_pin change so or user pin.

    % tap11_change_pin <pkcs11_library> <so or user> <pin> <new_pin>

    Example:
      % tap11_change_pin /usr/lib/libsomevenderspkcs11.so so 1234 5678   (for so pin)
      % tap11_change_pin /usr/lib/libsomevenderspkcs11.so user 1234 5678 (for user pin)

#### tap11_init_pin

tap11_init_pin init user pin(unlock user pin and set newpin).

    % tap11_init_pin <pkcs11_library> <sopin> <new_pin>

    Example:
      % tap11_init_pin /usr/lib/libsomevenderspkcs11.so 1234 5678

#### tap11_generate_key

tap11_generate_key generate rsa key pair and stores it to token.
if specify onboard option,tap11_generate_key try generate key on board(token feature).
to use onboard option,you needs modified libp11 [https://github.com/yusukemihara/libp11/tree/for_epass2003]. 
and specify --enable-onboard-keygen on configure.

    % tap11_generate_key <pkcs11_library> <pin> <keybits> <keyid> [onboard]

    Example:
      % tap11_generate_key /usr/lib/libsomevenderspkcs11.so 1234 2048 "solomon's key"
      % tap11_generate_key /usr/lib/libsomevenderspkcs11.so 1234 2048 "solomon's key" onboard

#### tap11_make_csr

tap11_make_csr make csr with specified key in the token.
tap11_make_csr use OpenSSL Engine to make csr.

    % tap11_make_csr <pkcs11_library> <pin> <keyid> <subject>

    Example:
      % tap11_make_csr /usr/lib/libsomevenderspkcs11.so 1234 "C=JP,O=org,CN=name" > csr.pem

#### tap11_store_cert

tap11_store_cert store certificate to token with specify id.

    % tap11_store_cert <pkcs11_library> <pin> <certid> <cerfitifate file(PEM)>

    Example:
      % tap11_store_cert /usr/lib/libsomevenderspkcs11.so 1234 "solomon's cert" solomon.pem

#### tap11_store_key

tap11_store_key store keypair to token with specify id.

    % tap11_store_key <pkcs11_library> <pin> <keyid> <key file(PEM)>

    Example:
      % tap11_store_key /usr/lib/libsomevenderspkcs11.so 1234 "solomon's key" rsa_solomon.pem

#### tap11_list_keys

tap11_list_keys list key(id,label) in the token.

    % tap11_list_keys <pkcs11_library> <pin>

    Example:
      % tap11_list_keys /usr/lib/libsomevenderspkcs11.so 1234

#### tap11_list_certs

tap11_list_certs list certificate(id,label,pem) in the token.

    % tap11_list_certs <pkcs11_library> <pin>

    Example:
      % tap11_list_certs /usr/lib/libsomevenderspkcs11.so 1234
