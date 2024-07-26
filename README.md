# kerberos
Kerberos in Go

## Windows

Server-side configuration. Specifies the key type of the master
key. This is used to encrypt the database, and the default is
aes256-cts-hmac-sha1-96 .

| enctype                    | weak?      | krb5   | Windows |
| :------------              | :---       | :--    | :--     |
| des-cbc-crc                | weak       | <1.18  | >=2000  |
| des-cbc-md4                | weak       | <1.18  | ?       |
| des-cbc-md5                | weak       | <1.18  | >=2000  |
| des3-cbc-sha1              | deprecated | >=1.1  | none    |
| arcfour-hmac               | deprecated | >=1.3  | >=2000  |
| arcfour-hmac-exp           | weak       | >=1.3  | >=2000  |
| aes128-cts-hmac-sha1-96    |            | >=1.3  | >=Vista |
| aes256-cts-hmac-sha1-96    |            | >=1.3  | >=Vista |
| aes128-cts-hmac-sha256-128 |            | >=1.15 | none    |
| aes256-cts-hmac-sha384-192 |            | >=1.15 | none    |
| camellia128-cts-cmac       |            | >=1.9  | none    |
| camellia256-cts-cmac       |            | >=1.9  | none    |
