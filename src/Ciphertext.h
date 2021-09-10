#ifndef CIPHERTEXT_H
#define CIPHERTEXT_H

#include "utils.h"

namespace certFHE{

	class CNODE;
	class Permutation;
	class SecretKey;
	class Context;
	class Plaintext;

#if CERTFHE_MULTITHREADING_EXTENDED_SUPPORT

	class CNODE_disjoint_set;

#endif

    /**
     * Class used for storing a ciphertext
    **/
	class Ciphertext{

	public:
    
		/**
		 * CNODE associated with the ciphertext
		 * It can be of any type (CCC, CMUL, CADD) or null
		**/
		CNODE * node;

#if CERTFHE_MULTITHREADING_EXTENDED_SUPPORT

		/**
		 * Mutex for synchronization of operations on disjoint sets
		**/
		static std::mutex op_mutex;

		/**
		 * Used to get a common mutex for all ciphertexts 
		 * that (might) share a common internal CNODE
		**/
		mutable CNODE_disjoint_set * concurrency_guard;

#endif

		/**
			* Method for adding two ciphertexts
			* @param[in] fst: node corresponding to the first ciphertext
			* @param[in] snd: node corresponding to the second ciphertext
			* @return value: the result CNODE as a pointer
		**/
		static CNODE * add(CNODE * fst, CNODE * snd);

		/**
			* Method for multiplying two ciphertexts
			* @param[in] fst: node corresponding to the first ciphertext
			* @param[in] snd: node corresponding to the second ciphertext
			* @return value: the result CNODE as a pointer
		**/
		static CNODE * multiply(CNODE * fst, CNODE * snd);


#if CERTFHE_MULTITHREADING_EXTENDED_SUPPORT

		/**
		 * Method to manually rebuild the CNODE_disjoint_set structure
		 * When deserializing a serialization created inside an implementation without extended multithreading support
		 * 
		 * NOTE: it has the potential of significantly slowing down the deserialization 
		**/
		static void concurrency_guard_structure_rebuild(const int ctxt_count, Ciphertext ** deserialized);

		/**
		 * Method for finding the root and locking its mutex under the op_mutex
		**/
		static std::unique_lock <std::mutex> * lock_guard(const Ciphertext * ctxt);

		/**
		 * Method that finds the fst and snd roots, locks them and then performs union between res and fst, and res and snd
		 * (It does NOT lock res guard)
		 *
		 * NOTES: -> Currently used for +, *, +=, *=
		 *		  -> It also performs the CCC op shortcut check
		**/
		static std::pair <std::unique_lock <std::mutex> *, std::unique_lock <std::mutex> *> lock_guard_and_union(const Ciphertext * fst, const Ciphertext * snd, const Ciphertext * res, bool CCC_shortcut);

#endif

	public:

		/**
		 * Serialization (into bytes) function
		 * This function ASSUMES all the ciphertexts were encrypted under the same context (or at least an equal one)
		 * Returns a pointer to the serialization array and its byte length
		**/
		static std::pair <unsigned char *, int> serialize(const int ctxt_count, Ciphertext ** to_serialize_arr);

		/**
		 * This method takes a full serialization array (containing one or more serialized ciphertexts)
		 * And returns an array of pointers to heap-allocated deserialized ciphertexts
		 * It ASSUMES all the serialized Ciphertexts / CNODEs do not have duplicates inside the same serialization
		**/
		static std::pair <Ciphertext **, Context> deserialize(unsigned char * serialization);

		Ciphertext();

		/**
			* Custom constructor
			* @param[in] plaintext: plaintext to be encrypted 
			* @param[in] sk: secret key under which the encryption takes place
		**/
		Ciphertext(const Plaintext & plaintext, const SecretKey & sk);

		/**
			* Custom constructor
			* @param[in] plaintext: plaintext to be encrypted (first bit starting from any memory address)
			* @param[in] sk: secret key under which the encryption takes place
		**/
		Ciphertext(const void * plaintext, const SecretKey & sk);

		Ciphertext(const Ciphertext & ctxt);

		Ciphertext(Ciphertext && ctxt);

		virtual ~Ciphertext();

		/**
			* @return value: (estimated) ciphertext number of default length chunks, 
			*				if the ciphertext were stored (real number of ciphertext chunks might be smaller
			*												due to lazy operations and copy-on-write)
			*							
		**/
		uint64_t getLen() const;

		Context getContext() const;
        
		friend std::ostream & operator << (std::ostream & out, const Ciphertext & c);
        
		Ciphertext operator + (const Ciphertext & c) const;

		Ciphertext & operator += (const Ciphertext & c);

		Ciphertext operator * (const Ciphertext & c) const;

		Ciphertext & operator *= (const Ciphertext & c);

		Ciphertext & operator = (const Ciphertext & c);

		Ciphertext & operator = (Ciphertext && c);

		/**
			* Apply a permutation on the current ciphertxt 
			* @param[in] permutation : permutation object to be applied
		**/
		void applyPermutation_inplace(const Permutation & permutation);

		/**
			* Permute the current ciphertext and return a new object
			* @param[in] permutation: constant reference to permutation object
			* @return value: permuted ciphertext
		**/
		Ciphertext applyPermutation(const Permutation & permutation);

		/**
			* Creates a deep copy for the current ciphertext
			* This might be useful in a multithreading situation,
			* When one wants to parralelise operations on different ctxt
			* That originally shared at least a common CNODE node 
			* (usually when one of them was obtained by applying an operation on the other)
			* @return value: new ciphertext
		**/
		Ciphertext make_deep_copy() const;

		/**
			* Method for decrypting current ciphertext
			* @param[in] sk: key under which decryption takes place
			* @return value: decrypted value as an uint64_t (0 or 1)
		**/
		uint64_t decrypt_raw(const SecretKey & sk) const;

		/**
			* Method for decrypting current ciphertext
			* @param[in] sk: key under which decryption takes place
			* @return value: decrypted value as a plaintext object
		**/
		Plaintext decrypt(const SecretKey & sk) const; 

		// Other

		friend class CCC;
		friend class COP;
		friend class CNODE_disjoint_set;

	};
}

#endif