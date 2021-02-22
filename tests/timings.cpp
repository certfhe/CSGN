#include "../src/certFHE.h"

using namespace certFHE;
using namespace std;

int main()
{
    // Initialize the PRNG by seeding it with local time
    certFHE::Library::initializeLibrary();
   
    // Input the certFHE parameters : N,D
    certFHE::Context context(1247,16);
    std::cout<<context;
    std::cout<<"Security(lambda)= "<<120<<endl<<endl;

    // Generate a secret key based on context
    Timer t1("Key generation ");
    t1.start();
    certFHE::SecretKey seckey(context);
    t1.stopAndPrint();

    // Define some plaintext
    Plaintext p1(1);

    // Encrypt 
    Timer t2("Encryption ");
    t2.start();
    Ciphertext c1 = seckey.encrypt(p1);
    t2.stopAndPrint();

    Ciphertext permuted_ciphertext;
    Ciphertext added, multiplicated;

    Timer t3("Addition of fresh ciphertexts");
    t3.start();
    added = c1+c1;
    t3.stopAndPrint();

    Timer t4("Multiplication of fresh ciphertexts");
    t4.start();
    multiplicated = c1*c1;
    t4.stopAndPrint();

    // Generate a permutation
    Timer t5 ("Permutation generation ");
    t3.start();
    Permutation permutation(context);
    t3.stopAndPrint();
   
    // Applying the permutation over the secret key
    Timer t6("Permuting the secret key ");
    t4.start();
    SecretKey permutedSecretKey = seckey.applyPermutation(permutation);
    t4.stopAndPrint();

    //Applying the permutation over the ciphertext
    Timer t7("Permuting the ciphertext ");
    t5.start();
    Ciphertext permutedCiphertext = c1.applyPermutation(permutation);
    t5.stopAndPrint();

    // Decrypt using the permuted key and ciphertext
    Timer t8("Decryption ");
    t6.start();
    Plaintext decrypted = permutedSecretKey.decrypt(permutedCiphertext);
    t6.stopAndPrint();

    std::cout<<endl;
    std::cout<<"Secret key size: "<<seckey.size()<<" bytes"<<endl;
    std::cout<<"Fresh ciphertext size: "<<c1.size()<<" bytes"<<endl;
    std::cout<<"After multiplication ciphertext size: "<<multiplicated.size()<<" bytes"<<endl;
    std::cout<<"After addition ciphertext size: "<<added.size()<<" bytes"<<endl;

    return 0;
}