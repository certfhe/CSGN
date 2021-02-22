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

    // Define two plaintext objects: 0/1 bits
    Plaintext p1(1);
    Plaintext p0(0);

    // Encrypt two bits
    std::cout<<"Encrypting two bits.........................OK"<<endl;
    Ciphertext c1 = seckey.encrypt(p1);
    Ciphertext c0 = seckey.encrypt(p0);

    Ciphertext added;
    Ciphertext multiplied;
   
    // Add and multiply two bits
    std::cout<<"Performing addition and multiplications.....OK"<<endl;
    added = c1+c0;
    multiplied = c1*c0;
   
    // Decrypt the result
    std::cout<<"Decrypting results..........................OK"<<endl;
    Plaintext dec_addition = seckey.decrypt(added);
    Plaintext dec_multiplied = seckey.decrypt(multiplied);

    // Print the result
    std::cout<<"Printing results............................OK"<<endl<<endl;
    std::cout<<"Dec ( Enc (1) + Enc (0) ) = "<<dec_addition<<std::endl;
    std::cout<<"Dec ( Enc (1) * Enc (0) ) = "<<dec_multiplied<<std::endl;

    return 0;
}