#ifndef CMUL_HEADER
#define CMUL_HEADER

#include "COP.h"

namespace certFHE {

	class CADD;

	/**
	 * Class that marks an addition operation
	 * Every node contained in this->nodes list is (/should eventually be) multiplied
	 * (CMUL = Ciphertext Multiplication)
	 * NOTE: check GlobalParams for parametrization of this class
	**/
	class CMUL : public COP {

	protected:

		// Constructors - destructors

		CMUL() = delete;
		CMUL(Context * context): COP(context) {}

		/**
		 * Creates (intentional) shallow copy
		 * GOOD to use, at least in a single threaded environment
		**/
		CMUL(const CMUL & other): COP(other) {}
		CMUL(const CMUL && other): COP(other) {}

		virtual ~CMUL() {}

		// Operators

		CMUL & operator = (const CMUL & other) = delete;
		CMUL & operator = (const CMUL && other) = delete;

		friend std::ostream & operator << (std::ostream & out, const CMUL & cmul);

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

		// Other

		friend class CADD;
		friend class Ciphertext;
	};

}

#endif