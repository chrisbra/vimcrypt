
# A small project to play around with libsodium

## The idea

Learn something about [libsodium][1], which is now also part of Vim (see [patch 8.2.3022][2]). 

So here is a small utility, that let's you encrypt and decrypt messages, that can also be read by Vim.

### Install

```sh
~$ apt install libsodium # libsodium is required to build
~$ git clone https://github.com/chrisbra/vimcrypt
~$ cd vimcrypt; make
```

### Usage

```sh
~$ vimcrypt encrypt file  # encrypt
~$ vimcrypt decrypt file.enc # decrypt
```

By default, when encrypting, it will leave your precious input files alone and write the encrypted file to the same name with the suffix `.enc` added.

That means, you need to decrypt files with the name `<input>.enc`.

#### Arguments:

```
-v		    -  be verbose
-b <nr>   -  Use <nr> as block size for encryption
```

This matters mostly for files larger than the block size, because if the wrong block size is given, the file won't be decrypted properly.
By default, Vim uses a block size of 8192 Bytes, so this script also uses 8K block size if no one is given.

License & Copyright
-------

The GPL 2 License applies.
© 2021 by Christian Brabandt

__NO WARRANTY, EXPRESS OR IMPLIED.  USE AT-YOUR-OWN-RISK__

[1]: https://doc.libsodium.org/
[2]: https://github.com/vim/vim/releases/tag/v8.2.3022
