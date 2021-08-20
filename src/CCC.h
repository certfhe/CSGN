#ifndef CCC_HEADER
#define CCC_HEADER

#include "CNODE.h"

namespace certFHE {

	/**
	 * Class that stores the actual ciphertext chunks in memory
	 * (CCC = Contiguous Ciphertext Chunk)
	**/
	class CCC : public CNODE {

	protected:

		/**
		 * Ciphertext as uint64_t array
		 * Check GlobalParams for parametrization of its length
		**/
		uint64_t * ctxt; 

		// Constructors - destructors

		CCC() = delete;
		CCC(Context * context, uint64_t * ctxt, uint64_t deflen_cnt);

		CCC(const CCC & other);
		CCC(const CCC && other);

		virtual ~CCC();

		// Operators

		CCC & operator = (const CCC & other) = delete;
		CCC & operator = (const CCC && other) = delete;

		friend std::ostream & operator << (std::ostream & out, const CCC & ccc);

		// Getters, setters and methods

		/**
		 * Nothing to merge, CCC nodes are always "leaves" (top of the chain) 
		 * and DO NOT refer to anything upstream
		**/
		void upstream_merging() override {}

		/**
		 * Nothing to shorten
		**/
		CNODE * upstream_shortening() override { return 0; }

		/**
		 * Makes a DEEP COPY (copies ctxt array into a new one and wraps it into a new CCC object)
		**/
		CNODE * make_copy() override { return new CCC(*this); }

		/**
		 * (ONLY for CCC) same as make_copy
		**/
		CNODE * make_deep_copy() override { return new CCC(*this); }

		/**
			* Add two chunks of ciphertxts --- for multithreading only ---
			* @param[in] args: input sent as a pointer to an AddArgs object
			* @return value : nothing
		**/
		static void chunk_add(Args * raw_args);

		/**
			* Multiply two chunks of ciphertxts --- for multithreading only ---
			* @param[in] args: input sent as a pointer to a MulArgs object
			* @return value : nothing
		**/
		static void chunk_multiply(Args * raw_args);

		/**
			* Permute two chunks of ciphertxts --- for multithreading only ---
			* @param[in] args: input sent as a pointer to a PermArgs object
			* @return value : nothing
		**/
		static void chunk_permute(Args * raw_args);

		/**
			* Decrypt two chunks of ciphertxts --- for multithreading only ---
			* @param[in] args: input sent as a pointer to an DecArgs object
			* @return value : nothing
		**/
		static void chunk_decrypt(Args * raw_args);

		/**
		 * It will add WITHOUT ANY CHECK
		 * Proper checks are expected to be managed by the caller function
		 * It will create a new CCC object everytime
		**/
		static CCC * add(CCC * fst, CCC * snd);

		/**
		 * It will multiply WITHOUT ANY CHECK
		 * Proper checks are expected to be managed by the caller function
		 * It will create a new CCC object everytime
		**/
		static CCC * multiply(CCC * fst, CCC * snd);

		uint64_t decrypt(const SecretKey & sk) override;

		/**
		 * It will create a copy and permute it if the ref count is > 1
		 * And permute inplace only if ref count == 1
		**/
		CNODE * permute(const Permutation & perm, bool force_deep_copy) override;

		// Other

		friend class COP;
		friend class CMUL;
		friend class CADD;
		friend class Ciphertext;
	};

}

#endif