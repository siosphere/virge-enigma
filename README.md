
# Virge::Enigma
Used to encrypt/decrypt data, and produce hashes.

# Encrypt
Encryption used mcrypt to encrypt/decrypt data. Default set to RIJNDAEL_128 but can be changed as needed.
```
$myString = "secrets";
$key = "password";
$encrypted = Enigma::encrypt($myString, $key);
Enigma::decrypt($encrypted, $key); //secrets
```

# Hash
Hashing uses the hash_hmac function and supports all alogrithms returned by hash_algos();
```
$passwordHash = Enigma::hash('mypassword', 'salt');
```
Can also be used without input, in which case it will generate a hash of the current microtime
```
$randomhash = Enigma::hash();
```

# Encrypt File
Encryption of a file takes in an input file and an output file. The input file 
is read in blocks of 1MB, encrypted, and written out to the output file.

Likewise, decryption will take an input file (the encrypted file) and an output
file, will read the encrypted file line by line.

```
$inputFile = "./test.txt";

$outputFile = "./encrypted.txt";

$decryptedFile = "./decrypted.txt";

Enigma::encryptFile($inputFile, $outputFile, "secret");

Enigma::decryptFile($outputFile, $decryptedFile, "secret");

if(Enigma::md5File($inputFile) !== Enigma::md5File($decryptedFile)) {
    die("File hashes do not match");
}
```