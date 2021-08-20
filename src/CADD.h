#ifndef CADD_HEADER
#define CADD_HEADER

#include "COP.h"

namespace certFHE {

	class CMUL;

	/**
	 * Class that marks an addition operation
	 * Every node contained in this->nodes list is (/should eventually be) added
	 * (CADD = Ciphertext Addition)
	 * NOTE: check GlobalParams for parametrization of this class
	**/
	class CADD : public COP {

	protected:

		// Constructors & destructor

		CADD() = delete;
		CADD(Context * context): COP(context) {}

		/**
		 * Creates (intentional) shallow copy
		 * GOOD to use, at least in a single threaded environment
		**/
		CADD(const CADD & other): COP(other) {}
		CADD(const CADD && other): COP(other) {}

		virtual ~CADD() {}

		// Operators

		CADD & operator = (const CADD & other) = delete;
		CADD & operator = (const CADD && other) = delete;

		friend std::ostream & operator << (std::ostream & out, const CADD & cadd);

		// Getters, setters and methods

		void upstream_merging() override;

		uint64_t decrypt(const SecretKey & sk) override;

		CNODE * permute(const Permutation & perm, bool force_deep_copy) override;

		CNODE * make_copy() override;

		CNODE * make_deep_copy() override;

		// Methods that merge two nodes
		// Only called internally by other methods of this class

		static CNODE * upstream_merging(CNODE * fst, CNODE * snd);

		static CNODE * __upstream_merging(CADD * fst, CADD * snd);
		static CNODE * __upstream_merging(CADD * fst, CMUL * snd);
		static CNODE * __upstream_merging(CMUL * fst, CMUL * snd);

		static CNODE * __upstream_merging(CADD * fst, CCC * snd);
		static CNODE * __upstream_merging(CCC * fst, CCC * snd);
		static CNODE * __upstream_merging(CMUL * fst, CCC * snd);

		// Others

		friend class CMUL;
		friend class Ciphertext;
	};
}

#endif