# certFHE - Bounded Fully Homomorphic Encryption from Monoid Algebras


certFHE is a [fully homomorphic encryption (FHE)](https://en.wikipedia.org/wiki/Homomorphic_encryption) library that implements the scheme presented [here](http://certfhewiki.certsign.ro/wiki/CertSGN).

The library is implemented in C++.


## Building certFHE library

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
initializeLibrary();

// setup the certFHE context 
certFHEContext ctx;
ctx.N = 1247;
ctx.D = 16;

// the secret key
uint64_t* s = NULL;

// generate the secret key 
setup(ctx, s);

// use two bits: 0,1
char b0 = 0x00;
char b1 = 0x01;

// ciphertexts to be used
certFHECtxt ctxt0,ctxt1;

// encrypt the bits using secret key scheme
encrypt(ctxt0,b0,ctx,s);
encrypt(ctxt1,b1,ctx,s);

// multiply two ciphertexts 
certFHECtxt* m =  multiply(ctx,ctxt0,ctxt1);

// add a ciphertexts
certFHECtxt* r = add (*m,ctxt1);

// decrypt the result
uint64_t dec = decrypt(*r, ctx, s);

//print the results 
printf("enc ( %d ) * enc ( %d ) + enc ( %d ) ) = enc ( %d ) \n\n",b0,b1,b1,dec);
```

# License

This software is distributed under a proprietary license. If you have any question, please contact us at certfhe@certsign.ro.