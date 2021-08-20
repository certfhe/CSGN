# CSGN - Bounded Homomorphic Encryption from Monoid Algebras


CSGN is a [homomorphic encryption (HE)](https://en.wikipedia.org/wiki/Homomorphic_encryption) library that implements the scheme presented [here](https://certfhewiki.certsign.ro/wiki/CertSGN).

The library is implemented in C++.

Documentation can be found [here](https://certfhe.gitbook.io/csgn/).

## Building CSGN library

### Linux 

```bash
mkdir build
cd build
cmake ../
make
```

### Windows 

To build on Windows using cmake and VS:

```bash
mkdir build
cd build
cmake ../
```

Then, open the VS solution from build server and build all from VS.


# Example

```cpp
// initializing library (using local time as seed for further pseudo random generator calls)
certFHE::Library::initializeLibrary();

// setup the certFHE context 
certFHE::Context context(1247,16);

// the secret key
certFHE::SecretKey seckey(context);

// use two bits: 0,1
Plaintext p1(1);
Plaintext p0(0);

// encrypt the bits using secret key 
Ciphertext c1 = seckey.encrypt(p1);
Ciphertext c0 = seckey.encrypt(p0);

// multiply two ciphertexts 
c1 = c1 * c2;
c1 *= c2;

// add a ciphertexts
c1 = c1 + c2;
c1 += c2;

// decrypt the result
Plaintext result = seckey.decrypt(c1);

//print the results 
std::cout << result;
```

# License

This software is distributed under a proprietary license. If you have any question, please contact us at certfhe@certsign.ro.