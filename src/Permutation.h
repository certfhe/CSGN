#ifndef PERMUTATION_H
#define PERMUTATION_H

#include "utils.h"
#include "Helpers.h"
#include "Context.h"

namespace certFHE{

    /**
     * Class used to store permutations further applied on secret keys or ciphertexts
    **/
    class Permutation{

        uint64_t * permutation;				// vector used to store permutation
		PermInversion * inversions;			// permutation as inversions on a default len chunk -- for optimized permutation op --

#if CERTFHE_USE_CUDA

		PermInversion * vram_inversions;	// inversions copy inside VRAM for faster permutation on GPU

#endif
        
		uint64_t length;					// size of permutation vector
		uint64_t inversions_cnt;			// number of inversions

		Permutation(const uint64_t * perm, const uint64_t len, const PermInversion * invs, const uint64_t inv_cnt);

    public:

        Permutation();

        /**
         * Custom constructor - generates a random permutation using the N from context
        **/
        Permutation(const Context & context) : Permutation(context.getN()) {}

        /**
         * Custom constructor - generates a random permutation of size len
        **/
        Permutation(uint64_t len);

        Permutation(const Permutation & perm);

		~Permutation();

		/**
		 * Getters and setters
		**/
		uint64_t getLength() const { return this->length; }
		uint64_t getInversionsCnt() const { return this->inversions_cnt; }

		void setLength(uint64_t len) { this->length = len; }
		void setInversionsCnt(uint64_t inv_cnt) { this->inversions_cnt = inversions_cnt; }
		void setPermutation(const uint64_t * perm, uint64_t len, uint64_t inv_cnt, const PermInversion * invs);

		/**
		 * DO NOT DELETE THE RETUNING POINTER
		**/
		uint64_t * getPermutation() const { return this->permutation; }

		/**
		 * DO NOT DELETE THE RETUNING POINTER
		**/
		PermInversion * getInversions() const { return this->inversions; }

#if CERTFHE_USE_CUDA

		/**
		 * DO NOT DELETE THE RETUNING POINTER
		**/
		PermInversion * getVramInversions() const { return this->vram_inversions; }

#endif

        /**
         * Friend class for operator <<
        **/
        friend std::ostream & operator << (std::ostream & out, const Permutation & c);

        /**
         * Asignment operator
        **/
        Permutation & operator = (const Permutation & perm);

        /**
         * Method to return the inverse of current permutation
         * @return value: inverse of current permutation
        **/
        Permutation getInverse();

        /**
         * Combine two permutations
         * @param[in] permB: the second permutation to combine
         * @return value : a permutatuion with value equal to this o permB
        **/
       Permutation operator + (const Permutation & other) const;
       Permutation & operator += (const Permutation & other);

	   std::pair<unsigned char *, int> serialize() const;

	   static Permutation deserialize(unsigned char * serialization);
    };

}

#endif