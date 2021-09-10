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

#if CERTFHE_USE_CUDA
		uint64_t decrypt(const SecretKey & sk, std::unordered_map <CNODE *, unsigned char> * decryption_cached_values, std::unordered_map <CNODE *, unsigned char> * vram_decryption_cached_values) override;
#else
		uint64_t decrypt(const SecretKey & sk, std::unordered_map <CNODE *, unsigned char> * decryption_cached_values) override;
#endif

		CNODE * permute(const Permutation & perm, bool force_deep_copy) override;

		CNODE * make_copy() override;

		CNODE * make_deep_copy() override;

		void serialize_recon(std::unordered_map <void *, std::pair<uint32_t, int>> & addr_to_id) override;

		/**
		 * Deserialization function
		 *
		 * already_created == false -> It ONLY creates the CADD object, but DOES NOT populate the CNODE_list
		 * already_created == true -> It searches in the unordered map the already created CADD object and populates its CNODE_list
		 *
		 * Returns the offset IN MULTIPLES OF SIZEOF(UINT32_T) BYTES (relative to the received pointer) to the next serialization ID
		**/
		static int deserialize(unsigned char * deserialization_buffer, std::unordered_map <uint32_t, void *> & id_to_addr, Context & context, bool already_created);

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