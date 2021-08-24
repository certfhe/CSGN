#ifndef SECRET_KEY_H
#define SECRET_KEY_H

#include "utils.h"
#include "Helpers.h"

namespace certFHE {

	class Ciphertext;
	class Plaintext;
	class Permutation;
	class Context;

    /**
     * Class used for storing the secret key and to perform operations such as encrypt/decrypt
    **/
    class SecretKey{

        uint64_t * s;                    // secret positions from the vector [0,n-1]. 
		uint64_t * s_mask;				 // secret key as a bitmask

#if CERTFHE_USE_CUDA

		uint64_t * vram_s_mask;			 // s_mask copy stored in VRAM for faster GPU decryption

#endif

        uint64_t length;                 // length of the s vector, containing the secret posionts
		uint64_t mask_length;		     // length of secret key as bitmask IN UINT64 CHUNKS

        Context * certFHEContext;

		/**
		 * Useful for decryption optimization
		 * Sets key mask according to the already existing s
		 * @return value : nothing
		**/
		void set_mask_key();

		/**
		 * Encrypts the first bit from a memory address
		 * @param[in] addr: the memory address
		 * @return value: raw ciphertext chunk
		**/
		uint64_t * encrypt_raw_bit(unsigned char bit) const;

    public:

        SecretKey() = delete;

        /**
         * Custom constructor. Generates a secret key based on the context.
         * @param[in] context: a const. reference to an context
        **/
        SecretKey(const Context & context);

        SecretKey(const SecretKey & secKey);

        /**
         * Encrypts a plaintext
         * @param[in] plaintext: input to be encrypted ({0,1})
         * @return value: raw ciphertext chunk
        **/
		uint64_t * encrypt_raw(const Plaintext & plaintext) const;

		/**
		 * Encrypts the first bit from a memory address
		 * @param[in] addr: the memory address
		 * @return value: raw ciphertext chunk
		**/
		uint64_t * encrypt_raw(const void * addr) const;

		/**
		 * Encrypts a plaintext
		 * @param[in] plaintext: input to be encrypted ({0,1})
		 * @return value: Ciphertext object
		**/
		Ciphertext encrypt(const Plaintext & plaintext) const;

        /**
         * Decrypts a ciphertext
         * @param[in] ciphertext: ciphertext to be decrypted 
         * @return value: decrypted plaintext
        **/
		Plaintext decrypt(const Ciphertext & ciphertext) const; 

        /**
         * Apply the permutation on current secret key
         * @param[in] permutation: Permutation object
        **/
        void applyPermutation_inplace(const Permutation & permutation);

        /**
         * Apply a permutation on the current secret key and return a new object
         * @param[in] permutation: permutation object to be applied
         * @return value: a permuted secret key object
        **/
        SecretKey applyPermutation(const Permutation & permutation);

        /**
         * Friend class for operator <<
        **/
        friend std::ostream & operator << (std::ostream & out, const SecretKey & c);

        /**
         * Assignment operator
         * @param[in] secKey: a constant copy of an secret key object
        **/
        SecretKey & operator = (const SecretKey & secKey);

        virtual ~SecretKey();

        /**
         * @return value: number of elements in the secret key (s vector length)
        **/
		uint64_t getLength() const { return this->length; }

		/**
		* DO NOT DELETE THIS POINTER
	   **/
		Context * getContext() const { return this->certFHEContext; }

        /**
         * DO NOT DELETE THIS POINTER
        **/
		uint64_t * getKey() const { return this->s; }

		/**
		 * DO NOT DELETE THIS POINTER
		**/
		uint64_t * getMaskKey() const { return this->s_mask; }

#if CERTFHE_USE_CUDA

		/**
		 * DO NOT DELETE THIS POINTER
		**/
		uint64_t * getVramMaskKey() const { return this->vram_s_mask; }

#endif

    };

}

#endif