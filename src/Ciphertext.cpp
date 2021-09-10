#include "Ciphertext.h"
#include "GlobalParams.h"
#include "Threadpool.h"
#include "SecretKey.h"
#include "Permutation.h"
#include "Plaintext.h"
#include "Context.h"
#include "CMUL.h"
#include "CADD.h"

#if CERTFHE_MULTITHREADING_EXTENDED_SUPPORT

#include "CNODE_disjoint_set.h"

namespace certFHE {

#pragma region Private multithreading related methods

	std::mutex Ciphertext::op_mutex;

	std::unique_lock <std::mutex> * Ciphertext::lock_guard(const Ciphertext * ctxt) {

		std::lock_guard <std::mutex> guard(op_mutex);

		std::unique_lock <std::mutex> * lock = new std::unique_lock <std::mutex>(ctxt->concurrency_guard->get_root()->mtx);
		return lock;
	}

	std::pair <std::unique_lock <std::mutex> *, std::unique_lock <std::mutex> *> Ciphertext::lock_guard_and_union(const Ciphertext * fst, const Ciphertext * snd, const Ciphertext * res, bool CCC_shortcut) {

		std::lock_guard <std::mutex> guard(op_mutex);

		std::mutex * mtx_fst = &(fst->concurrency_guard->get_root()->mtx);
		std::mutex * mtx_snd = &(snd->concurrency_guard->get_root()->mtx);

		std::unique_lock <std::mutex> * lock_fst;
		std::unique_lock <std::mutex> * lock_snd;

		if (mtx_fst != mtx_snd) {

			if (mtx_fst > mtx_snd)
				std::swap(mtx_fst, mtx_snd);

			lock_fst = new std::unique_lock <std::mutex>(*mtx_fst);
			lock_snd = new std::unique_lock <std::mutex>(*mtx_snd);

			if (!(CCC_shortcut && (fst->node->deflen_count * snd->node->deflen_count < OPValues::max_ccc_deflen_size))) {

				res->concurrency_guard->set_union(fst->concurrency_guard);
				res->concurrency_guard->set_union(snd->concurrency_guard);
			}
		}
		else {

			lock_fst = new std::unique_lock <std::mutex>(*mtx_fst);
			lock_snd = 0;

			if (!(CCC_shortcut && (fst->node->deflen_count * snd->node->deflen_count < OPValues::max_ccc_deflen_size))) 
				res->concurrency_guard->set_union(fst->concurrency_guard);
		}

		return { lock_fst, lock_snd };
	}

#pragma endregion

#pragma region Public methods

	Plaintext Ciphertext::decrypt(const SecretKey & sk) const {

		return Plaintext(this->decrypt_raw(sk));
	}

	std::pair <unsigned char *, int> Ciphertext::serialize(const int ctxt_count, Ciphertext ** to_serialize_arr) {

		/**
		 * For multithreading extended support, before anything else all mutexes are locked
		 * Corresponding mutexes are found and sorted (by memory address) and then locked inside multiple std::unique_lock objects
		**/

		std::unique_lock <std::mutex> ** locks; 
		std::mutex ** mtxs_arr = new std::mutex *[ctxt_count];

		int locks_cnt;

		{
			std::lock_guard <std::mutex> guard(op_mutex);

			std::set <std::mutex *> mtxs;
			for (int i = 0; i < ctxt_count; i++) {

				if (to_serialize_arr[i]->concurrency_guard == 0)
					throw std::runtime_error("concurrency guard cannot be null");

				std::mutex * mtx = &(to_serialize_arr[i]->concurrency_guard->get_root()->mtx);
				mtxs_arr[i] = mtx;

				if (mtxs.find(mtx) == mtxs.end())
					mtxs.insert(mtx);
			}

			locks = new std::unique_lock <std::mutex> *[mtxs.size()];

			int aux_i = 0;
			for (auto mtx_addr : mtxs) {

				locks[aux_i] = new std::unique_lock <std::mutex>(*mtx_addr);
				aux_i += 1;
			}

			locks_cnt = mtxs.size();
		}

		/**
		 * Serialization for:
		 *		Ciphertext: id 4 bytes, node id 4 bytes, concurrency guard 4 bytes (0 if multithreading support is disabled)
		 *		CCC: id 4 bytes, deflen cnt 8 bytes, ctxt (deflen cnt * deflen to u64 * sizeof(u64)) bytes
		 *		CADD, CMUL: id 4 bytes, deflen cnt 8 bytes, upstream ref cnt 8 bytes, upstream ref IDs (sizeof(u32) * upstream ref cnt) bytes
		**/

		/**
		 * It contains the (temporary) IDs for a Ciphertext object
		 *
		 * ID restrictions:
		 *		CCC: first 2 bits 00
		 *		CADD: first 2 bits 01
		 *		CMUL: first 2 bits 10
		 *		Ciphertext: first 2 bits 11
		 *
		 * NOTE: to conserve this restriction, the IDs will be incremented by 0b100
		**/

		static uint32_t temp_ctxt_id = 3; // 0b00....000 11

		/**
		 * Guard ID to help rebuild the CNODE_disjoin_forest structure
		 * If the implementation which deserializez the following serialization supports extended multithreading
		 *
		 * NOTES: -> this field inside the serialization will be used
		 *           even if the current implementation DOES NOT support extended multithreading
		 *			 this will be marked by having all guard IDs 0
		 *	      -> the guard ID 0 is reserved for usage only in the situation described above
		 *
		 * This field alone helps implement the transition from
		 *		no extended multithreading -> no extended multithreading
		 *		extended multithreading    -> extended multithreading
		 *		extended multithreading    -> no extended multithreading
		 *
		 * For the last case (no extended multithreading -> extended multithreading), an additional (way slower) function is required
		 * to manually rebuild the disjoint set forest on the receiver (deserialization) implementation
		**/
		static uint32_t temp_guard_id = 1;

		/**
		 * Associates an (id, byte length) for every Ciphertext / CNODE (address)
		 * The associated id is local to the current serialization
		 * And the byte length is the size that node will occupy in the serialization
		 * It also helps to eliminate duplicates in the current serialization
		**/
		std::unordered_map <void *, std::pair <uint32_t, int>> addr_to_id;

		/**
		 * Associates a guard ID with a Ciphertext's guard mutex address
		**/
		std::unordered_map <std::mutex *, uint32_t> addr_to_guard_id;

		for (int i = 0; i < ctxt_count; i++) {

			if (to_serialize_arr[i]->node == 0)
				throw std::invalid_argument("Cannot serialize ciphertext with no value");

			if (addr_to_id.find(to_serialize_arr[i]) != addr_to_id.end())
				throw std::invalid_argument("Duplicate Ciphertext object found when trying to serialize");

			addr_to_id[to_serialize_arr[i]] = { temp_ctxt_id, (int)(3 * sizeof(uint32_t)) }; // ID of the current Ciphertext, ID of its associated CNODE, guard ID
			temp_ctxt_id += 0b100;

			if (addr_to_guard_id.find(mtxs_arr[i]) == addr_to_guard_id.end()) {

				addr_to_guard_id[mtxs_arr[i]] = temp_guard_id;

				temp_guard_id += 1;
				if (temp_guard_id == 0)
					temp_guard_id += 1;
			}

			if (addr_to_id.find(to_serialize_arr[i]->node) == addr_to_id.end())
				to_serialize_arr[i]->node->serialize_recon(addr_to_id);
		}

		/**
		 * Serialization byte array total length
		 * It is incremented with the help of the "serialization recon" recursive calls
		**/
		int ser_byte_length = 0;

		/**
		 * First elements in a serialization array are ALWAYS its Ciphertext object count, total CNODE + Ciphertxt count, and context attributes
		**/
		ser_byte_length += 2 * sizeof(uint32_t) + 4 * sizeof(uint64_t);

		for (auto entry : addr_to_id)
			ser_byte_length += entry.second.second;

		unsigned char * serialization = new unsigned char[ser_byte_length];

		uint32_t * ser_int32 = (uint32_t *)serialization;
		ser_int32[0] = (uint32_t)ctxt_count;
		// ser_int32[1] completed later in the execution (after the next for loop)

		uint64_t * ser_int64 = (uint64_t *)(serialization + 2 * sizeof(uint32_t));

		Context * context = to_serialize_arr[0]->node->context;

		ser_int64[0] = context->getN();
		ser_int64[1] = context->getD();
		ser_int64[2] = context->getS();
		ser_int64[3] = context->getDefaultN();

		int ser_offset = 2 * sizeof(uint32_t) + 4 * sizeof(uint64_t);

		/**
		 * The ciphertexts are serialized in the same order as in to_serialize_arr
		**/

		for (int i = 0; i < ctxt_count; i++) {

			ser_int32 = (uint32_t *)(serialization + ser_offset);

			ser_int32[0] = addr_to_id.at(to_serialize_arr[i]).first;
			ser_int32[1] = addr_to_id.at(to_serialize_arr[i]->node).first;
			ser_int32[2] = addr_to_guard_id.at(mtxs_arr[i]);

			ser_offset += 3 * sizeof(uint32_t);
		}

		for (auto entry : addr_to_id) {

			if (!CERTFHE_CTXT_ID(entry.second.first)) {

				CNODE * node = (CNODE *)entry.first;

				node->serialize(serialization + ser_offset, addr_to_id);
				ser_offset += entry.second.second;
			}
		}

		ser_int32 = (uint32_t *)serialization;
		ser_int32[1] = (uint32_t)addr_to_id.size();

		// DEBUG-----------------------------
		/*for (auto entry : addr_to_id) {

			if (CERTFHE_CTXT_ID(entry.second.first))
				std::cout << "Ciphertext " << entry.second.first << " assoc " << addr_to_id[((Ciphertext *)entry.first)->node].first << "\n";

			if (CERTFHE_CCC_ID(entry.second.first))
				std::cout << "CCC " << entry.second.first << '\n';

			if (CERTFHE_CADD_ID(entry.second.first))
				std::cout << "CADD " << entry.second.first << '\n';

			if (CERTFHE_CMUL_ID(entry.second.first))
				std::cout << "CMUL " << entry.second.first << '\n';
		}
		std::cout << "\n";*/

		for (int i = 0; i < locks_cnt; i++)
			delete locks[i];

		delete[] locks;
		delete[] mtxs_arr;

		return { serialization, ser_byte_length };
	}

	std::pair <Ciphertext **, Context> Ciphertext::deserialize(unsigned char * serialization) {

		std::unordered_map <uint32_t, void *> id_to_addr;

		uint32_t * ser_int32 = (uint32_t *)serialization;

		uint32_t ctxt_cnt = ser_int32[0];
		uint32_t total_ser_cnt = ser_int32[1];

		uint64_t * ser_int64 = (uint64_t *)(serialization + 2 * sizeof(uint32_t));
		Context  * context = new Context(ser_int64[0], ser_int64[1]);

		Ciphertext ** deserialized = new Ciphertext *[ctxt_cnt];

		/**
		 * For multithreading extended support,
		 * A map that associates a guard ID from the serialization array a CNODE_disjoint_set object
		**/
		std::unordered_map <uint32_t, CNODE_disjoint_set *> guard_id_to_addr;

		/**
		 * Iterating two times through the serialization array
		 *
		 * The first time, it creates the corresponding Ciphertext / CNODE objects in memory,
		 * but does NOT link them
		 *
		 * The second time, it links the CNODE objects between them
		 * and also links Ciphertext objects with their nodes
		**/

		ser_int32 = (uint32_t *)(serialization + 10 * sizeof(uint32_t));
		int ser32_offset = 0;

		uint32_t current_id = ser_int32[0];
		int ctxt_i = 0;

		for (uint32_t ser_cnt = 0; ser_cnt < total_ser_cnt; ser_cnt++) {

			if (CERTFHE_CTXT_ID(current_id)) {

				deserialized[ctxt_i] = new Ciphertext();
				id_to_addr[current_id] = deserialized[ctxt_i];

				ser32_offset += 3;
				current_id = ser_int32[ser32_offset];

				ctxt_i += 1;
			}
			else if (CERTFHE_CCC_ID(current_id)) {

				ser32_offset += CCC::deserialize((unsigned char *)(ser_int32 + ser32_offset), id_to_addr, *context, false);
				current_id = ser_int32[ser32_offset];
			}
			else if (CERTFHE_CADD_ID(current_id)) {

				ser32_offset += CADD::deserialize((unsigned char *)(ser_int32 + ser32_offset), id_to_addr, *context, false);
				current_id = ser_int32[ser32_offset];
			}
			else if (CERTFHE_CMUL_ID(current_id)) {

				ser32_offset += CMUL::deserialize((unsigned char *)(ser_int32 + ser32_offset), id_to_addr, *context, false);
				current_id = ser_int32[ser32_offset];
			}
		}

		/**
		 * If true, an additional function is called at the end,
		 * to manually reconstruct the disjoint set forest
		**/
		bool serialized_no_extended_multithreading_support = false;

		ser_int32 = (uint32_t *)(serialization + 10 * sizeof(uint32_t));
		ser32_offset = 0;

		current_id = ser_int32[0];
		ctxt_i = 0;

		for (uint32_t ser_cnt = 0; ser_cnt < total_ser_cnt; ser_cnt++) {

			if (CERTFHE_CTXT_ID(current_id)) {

				uint32_t node_id = ser_int32[ser32_offset + 1];
				uint32_t guard_id = ser_int32[ser32_offset + 2];

				deserialized[ctxt_i]->node = (CNODE *)id_to_addr.at(node_id);
				deserialized[ctxt_i]->node->downstream_reference_count += 1;

				if (guard_id) {

					if (guard_id_to_addr.find(guard_id) == guard_id_to_addr.end())
						guard_id_to_addr[guard_id] = deserialized[ctxt_i]->concurrency_guard;
					else
						deserialized[ctxt_i]->concurrency_guard->set_union(guard_id_to_addr.at(guard_id));
				}
				else
					serialized_no_extended_multithreading_support = true;

				ser32_offset += 3;
				current_id = ser_int32[ser32_offset];

				ctxt_i += 1;
			}
			else if (CERTFHE_CCC_ID(current_id)) {

				ser32_offset += CCC::deserialize((unsigned char *)(ser_int32 + ser32_offset), id_to_addr, *context, true);
				current_id = ser_int32[ser32_offset];
			}
			else if (CERTFHE_CADD_ID(current_id)) {

				ser32_offset += CADD::deserialize((unsigned char *)(ser_int32 + ser32_offset), id_to_addr, *context, true);
				current_id = ser_int32[ser32_offset];
			}
			else if (CERTFHE_CMUL_ID(current_id)) {

				ser32_offset += CMUL::deserialize((unsigned char *)(ser_int32 + ser32_offset), id_to_addr, *context, true);
				current_id = ser_int32[ser32_offset];
			}
		}

		if (serialized_no_extended_multithreading_support)
			concurrency_guard_structure_rebuild(ctxt_cnt, deserialized);

		return { deserialized, *context };
	}

	void Ciphertext::concurrency_guard_structure_rebuild(const int ctxt_count, Ciphertext ** deserialized) {

		/**
		 * Map that will temporarily directly associate every CNODE with a Ciphertext "root"
		 * When a CNODE is recursively found to have already been associated with a Ciphertext,
		 * The merge operation is called on the guards of those two Ciphertexts
		**/
		std::unordered_map <CNODE *, Ciphertext *> node_to_ctxt;

		for (int i = 0; i < ctxt_count; i++)
			deserialized[i]->node->concurrency_guard_structure_rebuild(node_to_ctxt, deserialized[i]);
	}

	uint64_t Ciphertext::decrypt_raw(const SecretKey & sk) const {

		if (this->concurrency_guard == 0)
			throw std::runtime_error("concurrency guard cannot be null");

		std::unique_lock <std::mutex> * lock = Ciphertext::lock_guard(this);

		if (this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		if (*this->node->context != *sk.getContext())
			throw std::runtime_error("ciphertext and secret key do not have the same context");

		std::unordered_map <CNODE *, unsigned char> decryption_cached_values;

#if CERTFHE_USE_CUDA
		std::unordered_map <CNODE *, unsigned char> vram_decryption_cached_values;
		uint64_t dec = this->node->decrypt(sk, &decryption_cached_values, &vram_decryption_cached_values);
#else
		uint64_t dec = this->node->decrypt(sk, &decryption_cached_values);
#endif

		delete lock;

		return dec;
	}

	Ciphertext Ciphertext::applyPermutation(const Permutation & permutation) {

		if (this->concurrency_guard == 0)
			throw std::runtime_error("concurrency guard cannot be null");

		// guard locked inside copy constructor
		Ciphertext permuted_ciphertext(*this);

		std::unique_lock <std::mutex> * lock = Ciphertext::lock_guard(&permuted_ciphertext);

		if (permuted_ciphertext.node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		CNODE * permuted = permuted_ciphertext.node->permute(permutation, true);

		permuted_ciphertext.node->try_delete();
		permuted_ciphertext.node = permuted;

		delete lock;

		return permuted_ciphertext;
	}

	void Ciphertext::applyPermutation_inplace(const Permutation & permutation) {

		if (this->concurrency_guard == 0)
			throw std::runtime_error("concurrency guard cannot be null");

		std::unique_lock <std::mutex> * lock = Ciphertext::lock_guard(this);

		if (this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		CNODE * permuted = this->node->permute(permutation, false);

		this->node->try_delete();
		this->node = permuted;

		delete lock;
	}

	Ciphertext Ciphertext::make_deep_copy() const {

		if (this->concurrency_guard == 0)
			throw std::runtime_error("concurrency guard cannot be null");

		std::unique_lock <std::mutex> * lock = Ciphertext::lock_guard(this);

		if (this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		Ciphertext deepcopy;
		deepcopy.node = this->node->make_deep_copy();

		delete lock;

		return deepcopy;
	}

#pragma endregion

#pragma region Private methods

	CNODE * Ciphertext::add(CNODE * fst, CNODE * snd) {

		CADD * addition_result = new CADD(fst->context);

		/**
		 * From now on, fst and snd nodes
		 * are referenced inside mul_result
		 * so the reference count increases for both of them
		**/
		fst->downstream_reference_count += 1;
		snd->downstream_reference_count += 1;

		addition_result->nodes->insert_next_element(fst);
		addition_result->nodes->insert_next_element(snd);

		addition_result->deflen_count = fst->deflen_count + snd->deflen_count;

		addition_result->upstream_merging();

		/**
		 * Shorten any chain of nodes formed during upstream merging
		**/
		CNODE * shortened = addition_result->upstream_shortening();
		if (shortened != 0) {

			addition_result->try_delete();
			return shortened;
		}

		return addition_result;
	}

	CNODE * Ciphertext::multiply(CNODE * fst, CNODE * snd) {

		CMUL * mul_result = new CMUL(fst->context);

		/**
		 * From now on, fst and snd nodes
		 * are referenced inside mul_result
		 * so the reference count increases for both of them
		**/
		fst->downstream_reference_count += 1;
		snd->downstream_reference_count += 1;

		mul_result->nodes->insert_next_element(fst);
		mul_result->nodes->insert_next_element(snd);

		mul_result->deflen_count = fst->deflen_count * snd->deflen_count;

		mul_result->upstream_merging();

		/**
		 * Shorten any chain of nodes formed during upstream merging
		**/
		CNODE * shortened = mul_result->upstream_shortening();
		if (shortened != 0) {

			mul_result->try_delete();
			return shortened;
		}

		return mul_result;
	}

#pragma endregion

#pragma region Operators

	Ciphertext Ciphertext::operator + (const Ciphertext & c) const {

		if (c.concurrency_guard == 0 || this->concurrency_guard == 0)
			throw std::runtime_error("concurrency guard cannot be null");

		if (c.node == 0 || this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		if (*this->node->context != *c.node->context)
			throw std::runtime_error("ciphertexts do not have the same context");

		Ciphertext add_result_c;

		CCC * ccc_thisnode = dynamic_cast <CCC *> (this->node);
		CCC * ccc_othernode = dynamic_cast <CCC *> (c.node);

		/**
		 * When two ctxt refer to a CCC, operations are performed directly
		 * NOTE: the result CCC is always a different one, so there is no need for concurrency_guard union
		**/
		bool CCC_shortcut = ccc_thisnode && ccc_othernode;

		auto lock_pair = Ciphertext::lock_guard_and_union(this, &c, &add_result_c, CCC_shortcut);

		CNODE * addition_result;
		
		if (CCC_shortcut && this->node->deflen_count * c.node->deflen_count < OPValues::max_ccc_deflen_size)
			addition_result = CCC::add(ccc_thisnode, ccc_othernode);

		else {

			/**
				* The called method will treat arguments as different nodes
				* So the reference count temporarily increases
				* (although not necessary ???)
			**/
			if (this->node == c.node)
				this->node->downstream_reference_count += 1;

			addition_result = Ciphertext::add(this->node, c.node);

			if (this->node == c.node)
				this->node->downstream_reference_count -= 1;
		}

		delete lock_pair.first;

		if (lock_pair.second)
			delete lock_pair.second;

		add_result_c.node = addition_result;
		return add_result_c;
	}

	Ciphertext Ciphertext::operator * (const Ciphertext & c) const {

		if (c.concurrency_guard == 0 || this->concurrency_guard == 0)
			throw std::runtime_error("concurrency guard cannot be null");

		if (c.node == 0 || this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		if (*this->node->context != *c.node->context)
			throw std::runtime_error("ciphertexts do not have the same context");

		Ciphertext mul_result_c;

		CCC * ccc_thisnode = dynamic_cast <CCC *> (this->node);
		CCC * ccc_othernode = dynamic_cast <CCC *> (c.node);

		bool CCC_shortcut = ccc_thisnode && ccc_othernode;

		auto lock_pair = Ciphertext::lock_guard_and_union(this, &c, &mul_result_c, CCC_shortcut);

		CNODE * mul_result;

		if (CCC_shortcut && this->node->deflen_count * c.node->deflen_count < OPValues::max_ccc_deflen_size)
			mul_result = CCC::multiply(ccc_thisnode, ccc_othernode);

		else {

			/**
				* The called method will treat arguments as different nodes
				* So the reference count temporarily increases
				* (although not necessary ???)
			**/
			if (this->node == c.node)
				this->node->downstream_reference_count += 1;

			mul_result = Ciphertext::multiply(this->node, c.node);

			if (this->node == c.node)
				this->node->downstream_reference_count -= 1;
		}

		delete lock_pair.first;

		if (lock_pair.second)
			delete lock_pair.second;

		mul_result_c.node = mul_result;
		return mul_result_c;
	}

	Ciphertext & Ciphertext::operator += (const Ciphertext & c) {

		if (c.concurrency_guard == 0 || this->concurrency_guard == 0)
			throw std::runtime_error("concurrency guard cannot be null");

		if (c.node == 0 || this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		if (*this->node->context != *c.node->context)
			throw std::runtime_error("ciphertexts do not have the same context");

		CCC * ccc_thisnode = dynamic_cast <CCC *> (this->node);
		CCC * ccc_othernode = dynamic_cast <CCC *> (c.node);

		bool CCC_shortcut = ccc_thisnode && ccc_othernode;

		auto lock_pair = Ciphertext::lock_guard_and_union(this, &c, this, CCC_shortcut);

		CNODE * addition_result;

		if (CCC_shortcut && this->node->deflen_count * c.node->deflen_count < OPValues::max_ccc_deflen_size)
			addition_result = CCC::add(ccc_thisnode, ccc_othernode);

		else {

			if (this->node == c.node)
				this->node->downstream_reference_count += 1;

			addition_result = Ciphertext::add(this->node, c.node);

			if (this->node == c.node)
				this->node->downstream_reference_count -= 1;
		}

		this->node->try_delete();
		this->node = addition_result;

		delete lock_pair.first;

		if (lock_pair.second)
			delete lock_pair.second;

		return *this;
	}

	Ciphertext & Ciphertext::operator *= (const Ciphertext & c) {

		if (c.concurrency_guard == 0 || this->concurrency_guard == 0)
			throw std::runtime_error("concurrency guard cannot be null");

		if (c.node == 0 || this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		if (*this->node->context != *c.node->context)
			throw std::runtime_error("ciphertexts do not have the same context");

		CCC * ccc_thisnode = dynamic_cast <CCC *> (this->node);
		CCC * ccc_othernode = dynamic_cast <CCC *> (c.node);

		bool CCC_shortcut = ccc_thisnode && ccc_othernode;

		auto lock_pair = Ciphertext::lock_guard_and_union(this, &c, this, CCC_shortcut);

		CNODE * mul_result;

		if (CCC_shortcut && this->node->deflen_count * c.node->deflen_count < OPValues::max_ccc_deflen_size)
			mul_result = CCC::multiply(ccc_thisnode, ccc_othernode);

		else {

			if (this->node == c.node)
				this->node->downstream_reference_count += 1;

			mul_result = Ciphertext::multiply(this->node, c.node);

			if (this->node == c.node)
				this->node->downstream_reference_count -= 1;
		}

		this->node->try_delete();
		this->node = mul_result;

		delete lock_pair.first;

		if (lock_pair.second)
			delete lock_pair.second;

		return *this;
	}

	std::ostream & operator << (std::ostream & out, const Ciphertext & c) {

		if (c.concurrency_guard == 0)
			throw std::runtime_error("concurrency guard cannot be null");

		std::unique_lock <std::mutex> * lock = Ciphertext::lock_guard(&c);

		if (c.node == 0)
			out << "EMPTY CIPHERTEXT";

		CCC * ccc_node = dynamic_cast <CCC *> (c.node);
		if (ccc_node != 0)
			out << *ccc_node << '\n';

		else {

			COP * cop_node = dynamic_cast <COP *> (c.node);
			if (cop_node != 0)
				out << *cop_node << '\n';
		}

		delete lock;

		return out;
	}

	Ciphertext & Ciphertext::operator = (const Ciphertext & c) {

		if (this->node != 0 && c.node != 0 && *this->node->context != *c.node->context)
			throw std::runtime_error("ciphertexts do not have the same context");

		if (this->concurrency_guard == 0 || c.concurrency_guard == 0)
			throw std::runtime_error("concurrency guard cannot be null");

		std::unique_lock <std::mutex> * fst_lock;
		std::unique_lock <std::mutex> * snd_lock;

		CNODE_disjoint_set * removed;

		{
			std::lock_guard <std::mutex> guard(op_mutex);

			std::mutex * fst_mtx = &(this->concurrency_guard->get_root()->mtx);
			std::mutex * snd_mtx = &(c.concurrency_guard->get_root()->mtx);

			if (fst_mtx != snd_mtx) {

				if (fst_mtx > snd_mtx)
					std::swap(fst_mtx, snd_mtx);

				fst_lock = new std::unique_lock <std::mutex>(*fst_mtx);
				snd_lock = new std::unique_lock <std::mutex>(*snd_mtx);

				removed = this->concurrency_guard->remove_from_set();

				this->concurrency_guard = new CNODE_disjoint_set(this);
				this->concurrency_guard->set_union(c.concurrency_guard);
			}
			else {

				fst_lock = new std::unique_lock <std::mutex>(*fst_mtx);
				snd_lock = 0;

				removed = 0;
			}
		}
		
		if (this->node != 0)
			this->node->try_delete();

		if (c.node != 0)
			c.node->downstream_reference_count += 1;

		this->node = c.node;

		delete fst_lock;

		if(snd_lock)
			delete snd_lock;

		if(removed)
			delete removed;
		
		return *this;
	}

	Ciphertext & Ciphertext::operator = (Ciphertext && c) {

		if (this->node != 0 && c.node != 0 && *this->node->context != *c.node->context)
			throw std::runtime_error("ciphertexts do not have the same context");

		if (this->concurrency_guard == 0 || c.concurrency_guard == 0)
			throw std::runtime_error("concurrency guard cannot be null");

		std::unique_lock <std::mutex> * fst_lock;
		std::unique_lock <std::mutex> * snd_lock;

		CNODE_disjoint_set * removed;

		{
			std::lock_guard <std::mutex> guard(op_mutex);

			std::mutex * fst_mtx = &(this->concurrency_guard->get_root()->mtx);
			std::mutex * snd_mtx = &(c.concurrency_guard->get_root()->mtx);

			if (fst_mtx != snd_mtx) {

				if (fst_mtx > snd_mtx)
					std::swap(fst_mtx, snd_mtx);

				fst_lock = new std::unique_lock <std::mutex>(*fst_mtx);
				snd_lock = new std::unique_lock <std::mutex>(*snd_mtx);

				removed = this->concurrency_guard->remove_from_set();

				this->concurrency_guard = c.concurrency_guard;
				this->concurrency_guard->current = this;

				c.concurrency_guard = 0;
			}
			else {

				fst_lock = new std::unique_lock <std::mutex>(*fst_mtx);
				snd_lock = 0;

				removed = 0;
			}
		}

		if (this->node != 0)
			this->node->try_delete();

		this->node = c.node;
		c.node = 0;

		delete fst_lock;

		if (snd_lock)
			delete snd_lock;

		if (removed)
			delete removed;

		return *this;
	}

#pragma endregion

#pragma region Constructors and destructor

	Ciphertext::Ciphertext() : node(0), concurrency_guard(new CNODE_disjoint_set(this)) {}

	Ciphertext::Ciphertext(const Plaintext & plaintext, const SecretKey & sk) {

		uint64_t * raw_ctxt = sk.encrypt_raw(plaintext);

#if CERTFHE_USE_CUDA
		this->node = new CCC(sk.getContext(), raw_ctxt, 1, false);
#else
		this->node = new CCC(sk.getContext(), raw_ctxt, 1);
#endif

		this->concurrency_guard = new CNODE_disjoint_set(this);
	}

	Ciphertext::Ciphertext(const void * plaintext, const SecretKey & sk) {

		uint64_t * raw_ctxt = sk.encrypt_raw(plaintext);
#if CERTFHE_USE_CUDA
		this->node = new CCC(sk.getContext(), raw_ctxt, 1, false);
#else
		this->node = new CCC(sk.getContext(), raw_ctxt, 1);
#endif

		this->concurrency_guard = new CNODE_disjoint_set(this);
	}

	Ciphertext::Ciphertext(const Ciphertext & ctxt) {

		if (ctxt.concurrency_guard == 0)
			throw std::runtime_error("concurrency guard cannot be null");

		if (ctxt.node == 0)
			this->node = 0;

		else {

			this->concurrency_guard = new CNODE_disjoint_set(this);

			std::unique_lock <std::mutex> * lock;

			{
				std::lock_guard <std::mutex> guard(op_mutex);

				lock = new std::unique_lock <std::mutex>(ctxt.concurrency_guard->get_root()->mtx);

				this->concurrency_guard->set_union(ctxt.concurrency_guard);
			}

			ctxt.node->downstream_reference_count += 1;
			this->node = ctxt.node;

			delete lock;
		}
	}

	Ciphertext::Ciphertext(Ciphertext && ctxt) {

		if (ctxt.node == 0)
			this->node = 0;

		else {

			std::unique_lock <std::mutex> * lock;

			{
				std::lock_guard <std::mutex> guard(op_mutex);

				lock = new std::unique_lock <std::mutex>(ctxt.concurrency_guard->get_root()->mtx);

				this->concurrency_guard = ctxt.concurrency_guard;
				this->concurrency_guard->current = this;

				ctxt.concurrency_guard = 0;
			}

			this->node = ctxt.node;
			ctxt.node = 0;

			delete lock;
		}
	}

	Ciphertext::~Ciphertext() {

		if (this->concurrency_guard != 0) {

			std::unique_lock <std::mutex> * lock;

			CNODE_disjoint_set * removed;

			{	
				std::lock_guard <std::mutex> guard(op_mutex);

				lock = new std::unique_lock <std::mutex>(this->concurrency_guard->get_root()->mtx);

				removed = this->concurrency_guard->remove_from_set();
			}

			if (this->node != 0)
				this->node->try_delete();

			delete lock;

			/**
			 * In the case the set only has one element, the lock needs to be released
			 * before it can be deleted with the entire node
			 * so the delete statement is outside the lock scope
			**/
			delete removed;
		}
		else if (this->node != 0)
			std::cout << "concurrency guard is null but node is not null (check the rest of the code)";
	}

#pragma endregion

#pragma region Getters

	uint64_t Ciphertext::getLen() const {

		if (this->concurrency_guard == 0)
			throw std::runtime_error("concurrency guard cannot be null");

		if (this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		return this->node->getDeflenCnt();
	}

	Context Ciphertext::getContext() const {

		if (this->concurrency_guard == 0)
			throw std::runtime_error("concurrency guard cannot be null");

		if (this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		return this->node->getContext();
	}

#pragma endregion

}

#else

namespace certFHE {

#pragma region Public methods

	Plaintext Ciphertext::decrypt(const SecretKey & sk) const {

		return Plaintext(this->decrypt_raw(sk));
	}

	std::pair <unsigned char *, int> Ciphertext::serialize(const int ctxt_count, Ciphertext ** to_serialize_arr) {

		/**
		 * Serialization for:
		 *		Ciphertext: id 4 bytes, node id 4 bytes, concurrency guard 4 bytes (0 if multithreading support is disabled)
		 *		CCC: id 4 bytes, deflen cnt 8 bytes, ctxt (deflen cnt * deflen to u64 * sizeof(u64)) bytes
		 *		CADD, CMUL: id 4 bytes, deflen cnt 8 bytes, upstream ref cnt 8 bytes, upstream ref IDs (sizeof(u32) * upstream ref cnt) bytes
		**/

		/**
		 * It contains the (temporary) IDs for a Ciphertext object
		 *
		 * ID restrictions:
		 *		CCC: first 2 bits 00
		 *		CADD: first 2 bits 01
		 *		CMUL: first 2 bits 10
		 *		Ciphertext: first 2 bits 11
		 *
		 * NOTE: to conserve this restriction, the IDs will be incremented by 0b100
		**/

		static uint32_t temp_ctxt_id = 3; // 0b00....000 11

		/**
		 * Associates an (id, byte length) for every Ciphertext / CNODE (address)
		 * The associated id is local to the current serialization
		 * And the byte length is the size that node will occupy in the serialization
		 * It also helps to eliminate duplicates in the current serialization
		**/
		std::unordered_map <void *, std::pair <uint32_t, int>> addr_to_id;

		for (int i = 0; i < ctxt_count; i++) {

			if (to_serialize_arr[i]->node == 0)
				throw std::invalid_argument("Cannot serialize ciphertext with no value");

			if (addr_to_id.find(to_serialize_arr[i]) != addr_to_id.end())
				throw std::invalid_argument("Duplicate Ciphertext object found when trying to serialize");

			addr_to_id[to_serialize_arr[i]] = { temp_ctxt_id, (int)(3 * sizeof(uint32_t)) }; // ID of the current Ciphertext, ID of its associated CNODE, guard ID (0) for extended multithreading compatibility
			temp_ctxt_id += 0b100;

			if (addr_to_id.find(to_serialize_arr[i]->node) == addr_to_id.end())
				to_serialize_arr[i]->node->serialize_recon(addr_to_id);
		}

		/**
		 * Serialization byte array total length
		 * It is incremented with the help of the "serialization recon" recursive calls
		**/
		int ser_byte_length = 0;

		/**
		 * First elements in a serialization array are ALWAYS its Ciphertext object count, total CNODE + Ciphertxt count, and context attributes
		**/
		ser_byte_length += 2 * sizeof(uint32_t) + 4 * sizeof(uint64_t);

		for (auto entry : addr_to_id)
			ser_byte_length += entry.second.second;

		unsigned char * serialization = new unsigned char[ser_byte_length];

		uint32_t * ser_int32 = (uint32_t *)serialization;
		ser_int32[0] = (uint32_t)ctxt_count;
		// ser_int32[1] completed later in the execution (after the next for loop)

		uint64_t * ser_int64 = (uint64_t *)(serialization + 2 * sizeof(uint32_t));

		Context * context = to_serialize_arr[0]->node->context;

		ser_int64[0] = context->getN();
		ser_int64[1] = context->getD();
		ser_int64[2] = context->getS();
		ser_int64[3] = context->getDefaultN();

		int ser_offset = 2 * sizeof(uint32_t) + 4 * sizeof(uint64_t);

		/**
		 * The ciphertexts are serialized in the same order as in to_serialize_arr
		**/

		for (int i = 0; i < ctxt_count; i++) {

			ser_int32 = (uint32_t *)(serialization + ser_offset);

			ser_int32[0] = addr_to_id.at(to_serialize_arr[i]).first;
			ser_int32[1] = addr_to_id.at(to_serialize_arr[i]->node).first;
			ser_int32[2] = 0; // for extended multithreading compatibility

			ser_offset += 3 * sizeof(uint32_t);
		}

		for (auto entry : addr_to_id) {

			if (!CERTFHE_CTXT_ID(entry.second.first)) {

				CNODE * node = (CNODE *)entry.first;

				node->serialize(serialization + ser_offset, addr_to_id);
				ser_offset += entry.second.second;
			}
		}

		ser_int32 = (uint32_t *)serialization;
		ser_int32[1] = (uint32_t)addr_to_id.size();

		// DEBUG-----------------------------
		/*for (auto entry : addr_to_id) {

			if (CERTFHE_CTXT_ID(entry.second.first))
				std::cout << "Ciphertext " << entry.second.first << " assoc " << addr_to_id[((Ciphertext *)entry.first)->node].first << "\n";

			if (CERTFHE_CCC_ID(entry.second.first))
				std::cout << "CCC " << entry.second.first << '\n';

			if (CERTFHE_CADD_ID(entry.second.first))
				std::cout << "CADD " << entry.second.first << '\n';

			if (CERTFHE_CMUL_ID(entry.second.first))
				std::cout << "CMUL " << entry.second.first << '\n';
		}
		std::cout << "\n";*/

		return { serialization, ser_byte_length };
	}

	std::pair <Ciphertext **, Context> Ciphertext::deserialize(unsigned char * serialization) {

		std::unordered_map <uint32_t, void *> id_to_addr;

		uint32_t * ser_int32 = (uint32_t *)serialization;

		uint32_t ctxt_cnt = ser_int32[0];
		uint32_t total_ser_cnt = ser_int32[1];

		uint64_t * ser_int64 = (uint64_t *)(serialization + 2 * sizeof(uint32_t));
		Context  * context = new Context(ser_int64[0], ser_int64[1]);

		Ciphertext ** deserialized = new Ciphertext *[ctxt_cnt];

		/**
		 * Iterating two times through the serialization array
		 *
		 * The first time, it creates the corresponding Ciphertext / CNODE objects in memory,
		 * but does NOT link them
		 *
		 * The second time, it links the CNODE objects between them
		 * and also links Ciphertext objects with their nodes
		**/

		ser_int32 = (uint32_t *)(serialization + 10 * sizeof(uint32_t));
		int ser32_offset = 0;

		uint32_t current_id = ser_int32[0];
		int ctxt_i = 0;

		for (uint32_t ser_cnt = 0; ser_cnt < total_ser_cnt; ser_cnt++) {

			if (CERTFHE_CTXT_ID(current_id)) {

				deserialized[ctxt_i] = new Ciphertext();
				id_to_addr[current_id] = deserialized[ctxt_i];

				ser32_offset += 3;
				current_id = ser_int32[ser32_offset];

				ctxt_i += 1;
			}
			else if (CERTFHE_CCC_ID(current_id)) {

				ser32_offset += CCC::deserialize((unsigned char *)(ser_int32 + ser32_offset), id_to_addr, *context, false);
				current_id = ser_int32[ser32_offset];
			}
			else if (CERTFHE_CADD_ID(current_id)) {

				ser32_offset += CADD::deserialize((unsigned char *)(ser_int32 + ser32_offset), id_to_addr, *context, false);
				current_id = ser_int32[ser32_offset];
			}
			else if (CERTFHE_CMUL_ID(current_id)) {

				ser32_offset += CMUL::deserialize((unsigned char *)(ser_int32 + ser32_offset), id_to_addr, *context, false);
				current_id = ser_int32[ser32_offset];
			}
		}

		ser_int32 = (uint32_t *)(serialization + 10 * sizeof(uint32_t));
		ser32_offset = 0;

		current_id = ser_int32[0];
		ctxt_i = 0;

		for (uint32_t ser_cnt = 0; ser_cnt < total_ser_cnt; ser_cnt++) {

			if (CERTFHE_CTXT_ID(current_id)) {

				uint32_t node_id = ser_int32[ser32_offset + 1];

				deserialized[ctxt_i]->node = (CNODE *)id_to_addr.at(node_id);
				deserialized[ctxt_i]->node->downstream_reference_count += 1;

				ser32_offset += 3;
				current_id = ser_int32[ser32_offset];

				ctxt_i += 1;
			}
			else if (CERTFHE_CCC_ID(current_id)) {

				ser32_offset += CCC::deserialize((unsigned char *)(ser_int32 + ser32_offset), id_to_addr, *context, true);
				current_id = ser_int32[ser32_offset];
			}
			else if (CERTFHE_CADD_ID(current_id)) {

				ser32_offset += CADD::deserialize((unsigned char *)(ser_int32 + ser32_offset), id_to_addr, *context, true);
				current_id = ser_int32[ser32_offset];
			}
			else if (CERTFHE_CMUL_ID(current_id)) {

				ser32_offset += CMUL::deserialize((unsigned char *)(ser_int32 + ser32_offset), id_to_addr, *context, true);
				current_id = ser_int32[ser32_offset];
			}
		}

		return { deserialized, *context };
	}

	uint64_t Ciphertext::decrypt_raw(const SecretKey & sk) const {

		if (this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		if (*this->node->context != *sk.getContext())
			throw std::runtime_error("ciphertext and secret key do not have the same context");

		std::unordered_map <CNODE *, unsigned char> decryption_cached_values;

#if CERTFHE_USE_CUDA
		std::unordered_map <CNODE *, unsigned char> vram_decryption_cached_values;
		uint64_t dec = this->node->decrypt(sk, &decryption_cached_values, &vram_decryption_cached_values);
#else
		uint64_t dec = this->node->decrypt(sk, &decryption_cached_values);
#endif

		return dec;
	}

	Ciphertext Ciphertext::applyPermutation(const Permutation & permutation) {

		if (this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		Ciphertext permuted_ciphertext(*this);

		CNODE * permuted = permuted_ciphertext.node->permute(permutation, true);

		permuted_ciphertext.node->try_delete();
		permuted_ciphertext.node = permuted;

		return permuted_ciphertext;
	}

	void Ciphertext::applyPermutation_inplace(const Permutation & permutation) {

		if (this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		CNODE * permuted = this->node->permute(permutation, false);

		this->node->try_delete();
		this->node = permuted;
	}

	Ciphertext Ciphertext::make_deep_copy() const {

		if (this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		Ciphertext deepcopy;
		deepcopy.node = this->node->make_deep_copy();

		return deepcopy;
	}

#pragma endregion

#pragma region Private methods

	CNODE * Ciphertext::add(CNODE * fst, CNODE * snd) {

		CADD * addition_result = new CADD(fst->context);

		/**
		 * From now on, fst and snd nodes
		 * are referenced inside mul_result
		 * so the reference count increases for both of them
		**/
		fst->downstream_reference_count += 1;
		snd->downstream_reference_count += 1;

		addition_result->nodes->insert_next_element(fst);
		addition_result->nodes->insert_next_element(snd);

		addition_result->deflen_count = fst->deflen_count + snd->deflen_count;

		addition_result->upstream_merging();

		/**
		 * Shorten any chain of nodes formed during upstream merging
		**/
		CNODE * shortened = addition_result->upstream_shortening();
		if (shortened != 0) {

			addition_result->try_delete();
			return shortened;
		}

		return addition_result;
	}

	CNODE * Ciphertext::multiply(CNODE * fst, CNODE * snd) {

		CMUL * mul_result = new CMUL(fst->context);

		fst->downstream_reference_count += 1;
		snd->downstream_reference_count += 1;

		mul_result->nodes->insert_next_element(fst);
		mul_result->nodes->insert_next_element(snd);

		mul_result->deflen_count = fst->deflen_count * snd->deflen_count;

		mul_result->upstream_merging();

		/**
		 * Shorten any chain of nodes formed during upstream merging
		**/
		CNODE * shortened = mul_result->upstream_shortening();
		if (shortened != 0) {

			mul_result->try_delete();
			return shortened;
		}

		return mul_result;
	}

#pragma endregion

#pragma region Operators

	Ciphertext Ciphertext::operator + (const Ciphertext & c) const {

		if (c.node == 0 || this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		if (*this->node->context != *c.node->context)
			throw std::runtime_error("ciphertexts do not have the same context");

		CNODE * addition_result;

		CCC * ccc_thisnode = dynamic_cast <CCC *> (this->node);
		CCC * ccc_othernode = dynamic_cast <CCC *> (c.node);

		/**
		 * When two ctxt refer to a CCC, operations are performed directly
		**/
		if (ccc_thisnode && ccc_othernode && this->node->deflen_count * c.node->deflen_count < OPValues::max_ccc_deflen_size)
			addition_result = CCC::add(ccc_thisnode, ccc_othernode);

		else
			addition_result = Ciphertext::add(this->node, c.node);

		Ciphertext add_result_c;
		add_result_c.node = addition_result;

		return add_result_c;
	}

	Ciphertext Ciphertext::operator * (const Ciphertext & c) const {

		if (c.node == 0 || this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		if (*this->node->context != *c.node->context)
			throw std::runtime_error("ciphertexts do not have the same context");

		CNODE * mul_result;

		CCC * ccc_thisnode = dynamic_cast <CCC *> (this->node);
		CCC * ccc_othernode = dynamic_cast <CCC *> (c.node);

		/**
		 * When two ctxt refer to a CCC, operations are performed directly
		**/
		if (ccc_thisnode && ccc_othernode && this->node->deflen_count * c.node->deflen_count < OPValues::max_ccc_deflen_size)
			mul_result = CCC::multiply(ccc_thisnode, ccc_othernode);

		else
			mul_result = Ciphertext::multiply(this->node, c.node);

		Ciphertext mul_result_c;
		mul_result_c.node = mul_result;

		return mul_result_c;
	}

	Ciphertext & Ciphertext::operator += (const Ciphertext & c) {

		if (c.node == 0 || this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		if (*this->node->context != *c.node->context)
			throw std::runtime_error("ciphertexts do not have the same context");

		CNODE * addition_result;

		CCC * ccc_thisnode = dynamic_cast <CCC *> (this->node);
		CCC * ccc_othernode = dynamic_cast <CCC *> (c.node);

		if (ccc_thisnode && ccc_othernode && this->node->deflen_count * c.node->deflen_count < OPValues::max_ccc_deflen_size)
			addition_result = CCC::add(ccc_thisnode, ccc_othernode);

		else
			addition_result = Ciphertext::add(this->node, c.node);

		this->node->try_delete();
		this->node = addition_result;

		return *this;
	}

	Ciphertext & Ciphertext::operator *= (const Ciphertext & c) {

		if (c.node == 0 || this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		if (*this->node->context != *c.node->context)
			throw std::runtime_error("ciphertexts do not have the same context");

		CNODE * mul_result;

		CCC * ccc_thisnode = dynamic_cast <CCC *> (this->node);
		CCC * ccc_othernode = dynamic_cast <CCC *> (c.node);

		if (ccc_thisnode && ccc_othernode && this->node->deflen_count * c.node->deflen_count < OPValues::max_ccc_deflen_size)
			mul_result = CCC::multiply(ccc_thisnode, ccc_othernode);

		else
			mul_result = Ciphertext::multiply(this->node, c.node);

		this->node->try_delete();
		this->node = mul_result;

		return *this;
	}

	std::ostream & operator << (std::ostream & out, const Ciphertext & c) {

		if (c.node == 0)
			out << "EMPTY CIPHERTEXT";

		CCC * ccc_node = dynamic_cast <CCC *> (c.node);
		if (ccc_node != 0)
			out << *ccc_node << '\n';

		else {

			COP * cop_node = dynamic_cast <COP *> (c.node);
			if (cop_node != 0)
				out << *cop_node << '\n';
		}

		return out;
	}

	Ciphertext & Ciphertext::operator = (const Ciphertext & c) {

		if (this->node != 0 && c.node != 0 && *this->node->context != *c.node->context)
			throw std::runtime_error("ciphertexts do not have the same context");

		if (&c == this)
			return *this;

		if (this->node != 0)
			this->node->try_delete();

		if (c.node != 0)
			c.node->downstream_reference_count += 1;

		this->node = c.node;

		return *this;
	}

	Ciphertext & Ciphertext::operator = (Ciphertext && c) {

		if (this->node != 0 && c.node != 0 && *this->node->context != *c.node->context)
			throw std::runtime_error("ciphertexts do not have the same context");

		if (this->node != 0)
			this->node->try_delete();

		this->node = c.node;
		c.node = 0;

		return *this;
	}

#pragma endregion

#pragma region Constructors and destructor

	Ciphertext::Ciphertext() : node(0) {}

	Ciphertext::Ciphertext(const Plaintext & plaintext, const SecretKey & sk) {

		uint64_t * raw_ctxt = sk.encrypt_raw(plaintext);

#if CERTFHE_USE_CUDA
		this->node = new CCC(sk.getContext(), raw_ctxt, 1, false, false);
#else
		this->node = new CCC(sk.getContext(), raw_ctxt, 1);
#endif
	}

	Ciphertext::Ciphertext(const void * plaintext, const SecretKey & sk) {

		uint64_t * raw_ctxt = sk.encrypt_raw(plaintext);

#if CERTFHE_USE_CUDA
		this->node = new CCC(sk.getContext(), raw_ctxt, 1, false, false);
#else
		this->node = new CCC(sk.getContext(), raw_ctxt, 1);
#endif
	}

	Ciphertext::Ciphertext(const Ciphertext & ctxt) {

		if (ctxt.node != 0)
			ctxt.node->downstream_reference_count += 1;

		this->node = ctxt.node;
	}

	Ciphertext::Ciphertext(Ciphertext && ctxt) {

		this->node = ctxt.node;
		ctxt.node = 0;
	}

	Ciphertext::~Ciphertext() {

		if (this->node != 0)
			this->node->try_delete();
	}

#pragma endregion

#pragma region Getters

	uint64_t Ciphertext::getLen() const {

		if (this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		return this->node->getDeflenCnt();
	}

	Context Ciphertext::getContext() const {

		if (this->node == 0)
			throw std::invalid_argument("Cannot operate on ciphertext with no value");

		return this->node->getContext();
	}

#pragma endregion

}

#endif



