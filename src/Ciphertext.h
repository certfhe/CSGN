#ifndef CIPHERTEXT_H
#define CIPHERTEXT_H

#include "utils.h"
#include "Context.h"
#include "Permutation.h"

using namespace std;

namespace certFHE{

    /**
     * Class used for storing a ciphertext
    **/
    class Ciphertext{

    private:
    
            uint64_t * v;           // the N bits corespoding to the encryption of plaintext (from F2 space)
            uint64_t len;           // lenght of v & bitlen
            uint64_t * bitlen;      // number of bits from each v[i]

            Context *certFHEcontext; // context in which was encrypted

            /**
             * Method for adding two ciphertexts
             * @param[in] c1: values from first ciphertext (n bits from encryption representation)
             * @param[in] c2: values from second ciphertext (n bits from encryption representation)
             * @param[in] len1: length of c1 in blocks of 8 bytes
             * @param[in] len2: length of c2 in blocks of 8 bytes
             * @param[out] newlen: the length of the returning vector, in bytes
             * @return value: the result of addition 
            **/
            uint64_t* add(uint64_t* c1,uint64_t* c2,uint64_t len1,uint64_t len2, uint64_t &newlen) const;

            /**
             * Multiply two ciphertxts with both with same dimension = defaultN
             * @param[in] c1: input values for first ciphertext
             * @param[in] c2: input values for second ciphertext
             * @param[in] len: length of c1 and c2 vector, in blocks of 8 bytes
             * @return value : result of encrypted (c1*c2). The length will be the same as len.
            **/
            uint64_t* defaultN_multiply(uint64_t* c1, uint64_t* c2, uint64_t len) const;

            /**
             * Multiply two ciphertexts which are of different dimensions
             * @param[in] ctx: certFHE context in which left operand was encrypted
             * @param[in] c1: values of first operand  
             * @param[in] c2: values of second operand
             * @param[in] len1: length of c1 vector, in blocks of 8 bytes
             * @param[in] len2: length of c2 vector, in blocks of 8 bytes 
             * @param[out] newlen: length of resulting vecotr, in blocks of 8 bytes 
             * @param[in]  bitlenin1: vector of size len1 which contains the number of bits from c1[i]
             * @param[in]  bitlenin2: vector of size len2 which contains the number of bits from c2[i]
             * @param[in]  bitlenout: vector of size newlen which containts the number of bits from resulting vector
             * @return value: vector of size newlen with the encrypted output of (c1*c2)
            **/
            uint64_t* multiply(const Context& ctx,uint64_t *c1,uint64_t*c2,uint64_t len1,uint64_t len2, uint64_t& newlen,uint64_t* bitlenin1,uint64_t* bitlenin2,uint64_t*& bitlenout) const;

    public:

        /**
         * Default constructor
        **/
        Ciphertext();

        /**
         * Customer constructor
        **/
        Ciphertext(const uint64_t* V,const uint64_t * Bitlen,const uint64_t len, const Context& context);

        /**
         * Copy constructor
        **/
        Ciphertext(const Ciphertext& ctxt);

        /**
         * Destructor
        **/
        virtual ~Ciphertext();

        /**
         * Getters and setters
        **/
        void setValues(const uint64_t * V,const uint64_t length);
        void setBitlen(const uint64_t * Bitlen,const uint64_t length);
        void setContext(const Context& context);
        uint64_t getLen() const;
        Context getContext() const;

        
        /**
         * Getter for v. 
         * @return value: v pointer stored in class. DO NOT DELETE THIS POINTER.
        **/
        uint64_t* getValues() const;

           /**
         * Getter for bitlen. 
         * @return value: bitlen pointer stored in class. DO NOT DELETE THIS POINTER.
        **/    
        uint64_t* getBitlen() const;

        /**
         * Friend class for operator<<
        **/
        friend ostream& operator<<(ostream &out, const Ciphertext &c);
        
        /**
         * Operators for addition of ciphertexts
        **/
        Ciphertext operator+(const Ciphertext& c) const;
        Ciphertext& operator+=(const Ciphertext& c);

        /**
         * Operators for multiplication of ciphertexts
        **/
        Ciphertext operator*(const Ciphertext& c) const;
        Ciphertext& operator*=(const Ciphertext& c);

        /**
         * Operator for assignment
        **/
        Ciphertext& operator=(const Ciphertext& c);

        /**
         * Apply a permutation on the current ciphertxt
         * @param[in] permutation : permutation object to be applied
        **/
        void applyPermutation_inplace(const Permutation &permutation);

        /**
         * Permute the current ciphertext and return a new object
         * @param[in] permutation: constant reference to permutation object
         * @return value : permuted ciphertext
        **/
        Ciphertext applyPermutation(const Permutation &permutation);

        /**
         * Get the size of ciphertext in bytes
         * @return value: size in bytes
        **/
        long size();
    };


}

#endif