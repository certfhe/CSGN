#include "../src/certFHE.h"

using namespace certFHE;
using namespace std;

int main()
{
    // Initialize the PRNG by seeding it with local time
    std::cout<<"Initializing certFHE library................OK"<<endl;
    certFHE::Library::initializeLibrary();
   
    // Input the certFHE parameters : N,D
    std::cout<<"Setup the certFHE context...................OK"<<endl;
    certFHE::Context context(1247,16);

    // Generate a secret key based on context
    std::cout<<"Generate the secret key.....................OK"<<endl;
    certFHE::SecretKey seckey(context);

    // Define some plaintext
    Plaintext p1(1);

    // Encrypt 
    std::cout<<"Encrypting..................................OK"<<endl;
    Ciphertext c1 = seckey.encrypt(p1);

    Ciphertext permuted_ciphertext;
   
    // Generate a permutation
    std::cout<<"Generating a random permutation.............OK"<<endl;
    Permutation permutation(context);
   
    // Applying the permutation over the secret key
    std::cout<<"Permuting the secret key ...................OK"<<endl;
    SecretKey permutedSecretKey = seckey.applyPermutation(permutation);

    //Applying the permutation over the ciphertext
    std::cout<<"Permuting the ciphertext key ...............OK"<<endl;
    Ciphertext permutedCiphertext = c1.applyPermutation(permutation);

    // Decrypt using the permuted key and ciphertext
    std::cout<<"Decrypting..................................OK"<<endl;
    Plaintext decrypted = permutedSecretKey.decrypt(permutedCiphertext);

    // Printing the result
    std::cout<<" Dec ( Enc ( 1 ) ) = "<<decrypted<<endl;

    // Compute the inverse of a permutation
    Permutation inversePermutation = permutation.getInverse();

    // Combine two permutations
    Permutation identityPermutation;
    identityPermutation = permutation+inversePermutation;

    return 0;
}