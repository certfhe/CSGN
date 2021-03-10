#ifndef SECRET_KEY_H
#define SECRET_KEY_H

#include "utils.h"
#include "Context.h"
#include "Plaintext.h"
#include "Ciphertext.h"
#include "Helpers.h"
#include "Permutation.h"

using namespace std;

namespace certFHE
{
    /**
     * Class used for storing the secret key and to perform operations such as encrypt/decrypt
    **/
    class SecretKey{

    private:

        uint64_t *s;                    // secret positions from the vector [0,n-1]. 
        long length;                    // length of the s vector, containing the secret posionts

        Context *certFHEContext;

        /**
         * Encrypts a bit 
         * @param[in] bit: input from F2 space
         * @param[in] n: N value from Context
         * @param[in] d: D value from Context
         * @param[in] s: the secret key 
         * @return value : encryption of input bit
        **/
        uint64_t* encrypt(unsigned char bit, uint64_t n, uint64_t d, uint64_t*s);

        /**
         * Decryption function when the size of ciphertext is equal to context.N
         * @param[in] v: vector of size n bits
         * @param[in] len: size of vector v in bytes
         * @param[in] n: n value from context
         * @param[in] d: d value from context
         * @param[in] s: secret key s
         * @param[in] bitlen: length in bits of each v[i]
         * @return value: decrypted bit (F2 space)
        **/
        uint64_t defaultN_decrypt(uint64_t* v,uint64_t len, uint64_t n, uint64_t d, uint64_t* s,uint64_t* bitlen);

        /**
         * Decrypts an encrypted value 
         * @param[in] v: vector of bits, size in multiple of n
         * @param[in] len: size of vector v in bytes
         * @param[in] defLen: default length of N
         * @param[in] n: n value from context
         * @param[in] d: d value from context
         * @param[in] s: secret key s
         * @param[in] bitlen: length in bits of each v[i]
         * @return value: decrypted bit (F2 space)
        **/
        uint64_t decrypt(uint64_t* v,uint64_t len,uint64_t defLen, uint64_t n, uint64_t d, uint64_t* s,uint64_t* bitlen);

    public:

        /**
         * Deleted default constructor
        **/
        SecretKey() = delete;

        /**
         * Custom constructor. Generates a secret key based on the context.
         * @param[in] context: a const. reference to an context
        **/
        SecretKey(const Context &context);

        /**
         * Copy constructor
         * @param[in] secKey: SecretKey object 
        **/
        SecretKey(const SecretKey& secKey);

        /**
         * Encrypts a plaintext
         * @param[in] plaintext: input to be encrypted ({0,1})
         * @return value: resultint ciphertext
        **/
        Ciphertext encrypt( Plaintext &plaintext);

        /**
         * Decrypts an ciphertxts
         * @param[in] ciphertext: ciphertext to be decrypted 
         * @return value: decrypted plaintext
        **/
        Plaintext decrypt( Ciphertext& ciphertext);

        /**
         * Apply the permutation on current secret key
         * @param[in] permutation: Permutation object
        **/
        void applyPermutation_inplace(const Permutation& permutation);

        /**
         * Apply a permutation on the current secret key and return a new object
         * @param[in] permutation: permutation object to be applied
         * @return value: a permuted secret key object
        **/
        SecretKey applyPermutation(const Permutation& permutation);

        /**
         * Friend class for operator<<
        **/
        friend ostream& operator<<(ostream &out, const SecretKey &c);

        /**
         * Assignment operator
         * @param[in] secKey: a constant copy of an secret key object
        **/
        SecretKey& operator= (const SecretKey& secKey);

        /**
         * Destructor
        **/
        virtual ~SecretKey();

        /**
         * Getters
        **/
        uint64_t getLength() const;

        /**
         * DO NOT DELETE THIS POINTER
        **/
        uint64_t* getKey() const;
		
		/**
		 * Setters
		**/
		void setKey(uint64_t*s, uint64_t len);
		
        /**
         * Get the size in bytes of the secret key
         * @return value: size in bytes
        **/
        long size();

    };


}





#endif