#ifndef COP_HEADER
#define COP_HEADER

#include "CNODE.h"
#include "CNODE_list.h"
#include "CCC.h"

namespace certFHE {

	/**
	 * Abstract base class that marks the execution of an operation (addition / multiplication)
	 * (COP = Ciphertext Operation)
	**/
	class COP : public CNODE {

	protected:

		/**
		 * ALWAYS the first element is a dummy, 
		 * to avoid changing first element address when doing operations
		**/
		CNODE_list * nodes;

		// Constructors - destructors

		COP() = delete;
		COP(Context * context);

		virtual ~COP();

		/**
		 * Creates (intentional) shallow copy
		 * GOOD to use, at least in a single threaded environment
		**/
		COP(const COP & other);
		COP(const COP && other);

		// Operators

		COP & operator = (const COP & other) = delete;
		COP & operator = (const COP && other) = delete;

		friend std::ostream & operator << (std::ostream & out, const COP & cop);

		// Getters, setters and methods

		void upstream_merging() override = 0;

		CNODE * upstream_shortening() override;

		CNODE * make_copy() override = 0;

		CNODE * make_deep_copy() override  = 0;

#if CERTFHE_USE_CUDA
		uint64_t decrypt(const SecretKey & sk, std::unordered_map <CNODE *, unsigned char> * decryption_cached_values, std::unordered_map <CNODE *, unsigned char> * vram_decryption_cached_values) = 0;
#else
		uint64_t decrypt(const SecretKey & sk, std::unordered_map <CNODE *, unsigned char> * decryption_cached_values) = 0;
#endif

		CNODE * permute(const Permutation & perm, bool force_deep_copy) override = 0;

		void serialize_recon(std::unordered_map <void *, std::pair<uint32_t, int>> & addr_to_id) override = 0;

#if CERTFHE_MULTITHREADING_EXTENDED_SUPPORT

		void concurrency_guard_structure_rebuild(std::unordered_map <CNODE *, Ciphertext *> & node_to_ctxt, Ciphertext * associated_ctxt) override;
#endif

		void serialize(unsigned char * serialization_buffer, std::unordered_map <void *, std::pair<uint32_t, int>> & addr_to_id) override;

		// Other

		friend class CMUL;
		friend class CADD;
		friend class Ciphertext;
	};
}

#endif