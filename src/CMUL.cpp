#include "CMUL.h"
#include "CADD.h"

namespace certFHE {

	void CMUL::upstream_merging() {

		if (OPValues::no_merging)
			return;

		CNODE_list * thisnodes = this->nodes->next; // skipping dummy element

		if (thisnodes == 0 || thisnodes->current == 0)
			return;

		/**
		 * Iterating through all upstream referenced nodes and trying to merge as much as possible
		**/
		CNODE_list * node_i = thisnodes;
		while (node_i != 0 && node_i->next != 0) {

			CNODE_list * node_j = node_i->next;
			while (node_j != 0 && node_i != 0) {

				/**
				 * (optional) Check for duplicate nodes to be removed (a + a = a)
				**/
				if (OPValues::remove_duplicates_onmul && node_i != node_j && node_i->current == node_j->current) {

					node_j = node_j->pop_current_node();
					continue;
				}

				CNODE * merged = CMUL::upstream_merging(node_i->current, node_j->current);

				/**
				 * If nothing has been returned, it means no merge happened, so everything stays the same
				**/
				if (merged == 0) {

					node_j = node_j->next;
					continue;
				}

				/**
				 * If merged has deflen_cnt = 0, it means
				 * that by multiplying by that node, you obtain 0
				 * so EVERY NODE IS REMOVED
				**/
				if (merged->deflen_count == 0) {

					this->deflen_count = 0;

					CNODE_list * thisnodes_aux = this->nodes->next;
					while (thisnodes_aux != 0)
						thisnodes_aux = thisnodes_aux->pop_current_node();

					merged->try_delete();

					return;
				}

				/**
				 * try to delete the current node
				 * if there is another reference to it, it will remain in memory
				 * but in any case the current pointer will be overwritten with the new node
				**/
				node_i->current->try_delete();
				node_i->current = merged;

				node_j = node_j->pop_current_node(); // try_delete included
			}

			if (node_i != 0)
				node_i = node_i->next;
		}

		/**
		 * If at least one of the options is activated, size of any node can shrink when merging
		 * So the recalculation of deflen_cnt is necessary
		**/
		//if (OPValues::remove_duplicates_onadd || OPValues::remove_duplicates_onmul) {

			thisnodes = this->nodes->next;

			this->deflen_count = 0;
			if (thisnodes != 0 && thisnodes->current != 0)
				this->deflen_count = 1;
			
			while (thisnodes != 0 && thisnodes->current != 0) {

				this->deflen_count *= thisnodes->current->deflen_count;  
				thisnodes = thisnodes->next;
			}
		//}
	}

#if CERTFHE_USE_CUDA
	uint64_t CMUL::decrypt(const SecretKey & sk, std::unordered_map <CNODE *, unsigned char> * decryption_cached_values, std::unordered_map <CNODE *, unsigned char> * vram_decryption_cached_values) {
#else
	uint64_t CMUL::decrypt(const SecretKey & sk, std::unordered_map <CNODE *, unsigned char> * decryption_cached_values) {
#endif
		if (OPValues::decryption_cache) {

			auto cache_entry = decryption_cached_values->find(this);

			if (cache_entry != decryption_cached_values->end())
				return (uint64_t)cache_entry->second;
		}

		CNODE_list * thisnodes = this->nodes->next;

		if (thisnodes == 0 || thisnodes->current == 0)
			return 0;

		uint64_t rez = 1;

		while (thisnodes != 0 && thisnodes->current != 0) {

#if CERTFHE_USE_CUDA
			rez &= thisnodes->current->decrypt(sk, decryption_cached_values, vram_decryption_cached_values);
#else
			rez &= thisnodes->current->decrypt(sk, decryption_cached_values);
#endif
			thisnodes = thisnodes->next;
		}

		if (OPValues::decryption_cache)
			(*decryption_cached_values)[this] = (unsigned char)rez;

		return rez;
	}

	CNODE * CMUL::make_copy() {

		return new CMUL(*this);
	}

	CNODE * CMUL::make_deep_copy() {

		CMUL * deepcopy = new CMUL(this->context);
		deepcopy->deflen_count = this->deflen_count;

		CNODE_list * deepcopy_nodes = deepcopy->nodes->next;
		CNODE_list * thisnodes = this->nodes->next;

		while (thisnodes != 0 && thisnodes->current != 0) {

			CNODE * current_deepcopy = thisnodes->current->make_deep_copy();
			deepcopy_nodes->insert_next_element(current_deepcopy);

			thisnodes = thisnodes->next;
		}

		return deepcopy;
	}

	void CMUL::serialize_recon(std::unordered_map <void *, std::pair<uint32_t, int>> & addr_to_id) {

		static uint32_t temp_CMUL_id = 0b10; 

		uint64_t upstream_ref_cnt = 0; // number of nodes in CNODE_list WITHOUT dummy (first) element

		CNODE_list * thisnodes = this->nodes->next;
		while (thisnodes != 0 && thisnodes->current != 0) {

			if (addr_to_id.find(thisnodes->current) == addr_to_id.end())
				thisnodes->current->serialize_recon(addr_to_id);

			upstream_ref_cnt += 1;
			thisnodes = thisnodes->next;
		}

		addr_to_id[this] = { temp_CMUL_id, (int)(sizeof(uint32_t) + 2 * sizeof(uint64_t) + upstream_ref_cnt * sizeof(uint32_t)) };
		temp_CMUL_id += 0b100;
	}

	int CMUL::deserialize(unsigned char * serialized, std::unordered_map <uint32_t, void *> & id_to_addr, Context & context, bool already_created) {

		uint32_t * ser_int32 = (uint32_t *)serialized;
		uint32_t id = ser_int32[0];

		uint64_t * ser_int64 = (uint64_t *)(serialized + sizeof(uint32_t));

		uint64_t deflen_cnt = ser_int64[0];
		uint64_t deflen_to_u64 = context.getDefaultN();

		uint64_t upstream_ref_cnt = ser_int64[1];

		if (!already_created) {

			CMUL * deserialized = new CMUL(&context);
			deserialized->downstream_reference_count = 0; // it will be set later

			id_to_addr[id] = deserialized;
		}
		else {

			CMUL * deserialized = (CMUL *)id_to_addr.at(id);

			for (int i = 0; i < upstream_ref_cnt; i++) {

				uint32_t upstream_ref_id = ser_int32[5 + i];
				CNODE * upstream_ref = (CNODE *)id_to_addr.at(upstream_ref_id);

				upstream_ref->downstream_reference_count += 1;

				deserialized->nodes->insert_next_element(upstream_ref);
			}
		}

		return (int)(upstream_ref_cnt + 5);
	}

	std::ostream & operator << (std::ostream & out, const CMUL & cmul) {

		out << "CADD\n" << static_cast <const COP &> (cmul) << '\n';
		return out;
	}

	CNODE * CMUL::permute(const Permutation & perm, bool force_deep_copy) {

		CMUL * to_permute;
		if (this->downstream_reference_count == 1 && !force_deep_copy) {

			to_permute = this;
			this->downstream_reference_count += 1; // the caller function will see the returned result as a different node
		}
		else
			to_permute = new CMUL(*this);

		CNODE_list * topermute_nodes = to_permute->nodes->next;

		if (topermute_nodes == 0 || topermute_nodes->current == 0)
			return to_permute;

		while (topermute_nodes != 0 && topermute_nodes->current != 0) {

			CNODE * current_permuted = topermute_nodes->current->permute(perm, force_deep_copy);

			topermute_nodes->insert_next_element(current_permuted);
			topermute_nodes = topermute_nodes->pop_current_node()->next;
		}

		return to_permute;
	}

	CNODE * CMUL::upstream_merging(CNODE * fst, CNODE * snd) {

		CCC * fst_c = dynamic_cast<CCC *>(fst);
		if (fst_c != 0) {

			CCC * snd_c = dynamic_cast<CCC *>(snd);
			if (snd_c != 0)
				return CMUL::__upstream_merging((CCC *)fst_c, (CCC *)snd_c);

			else {

				CADD * snd_c = dynamic_cast<CADD *>(snd);
				if (snd_c != 0)
					return CMUL::__upstream_merging((CADD *)snd_c, (CCC *)fst_c);

				else {

					CMUL * snd_c = dynamic_cast<CMUL *>(snd);
					return CMUL::__upstream_merging((CMUL *)snd_c, (CCC *)fst_c);
				}
			}
		}
		else {

			CADD * fst_c = dynamic_cast<CADD *>(fst);
			if (fst_c != 0) {

				CCC * snd_c = dynamic_cast<CCC *>(snd);
				if (snd_c != 0)
					return CMUL::__upstream_merging((CADD *)fst_c, (CCC *)snd_c);

				else {

					CADD * snd_c = dynamic_cast<CADD *>(snd);
					if (snd_c != 0)
						return CMUL::__upstream_merging((CADD *)fst_c, (CADD *)snd_c);

					else {

						CMUL * snd_c = dynamic_cast<CMUL *>(snd);
						return CMUL::__upstream_merging((CADD *)fst_c, (CMUL *)snd_c);
					}
				}
			}
			else {

				CMUL * fst_c = dynamic_cast<CMUL *>(fst);
				CCC * snd_c = dynamic_cast<CCC *>(snd);
				if (snd_c != 0)
					return CMUL::__upstream_merging((CMUL *)fst_c, (CCC *)snd_c);

				else {

					CADD * snd_c = dynamic_cast<CADD *>(snd);
					if (snd_c != 0)
						return CMUL::__upstream_merging((CADD *)snd_c, (CMUL *)fst_c);

					else {

						CMUL * snd_c = dynamic_cast<CMUL *>(snd);
						return CMUL::__upstream_merging((CMUL *)fst_c, (CMUL *)snd_c);
					}
				}
			}
		}

		return 0;
	}
	
	CNODE * CMUL::__upstream_merging(CADD * fst, CADD * snd) { 

		/**
		 * Check maximum operation size for when to try to merge or not
		**/
		if ((fst->deflen_count * snd->deflen_count > OPValues::max_cmul_merge_size) &&
				(OPValues::always_default_multiplication == false || 
					(OPValues::always_default_multiplication && (fst->deflen_count != 1) && (snd->deflen_count != 1))
				)
			)
			return 0;

		/**
		 * a * 0 = 0
		**/
		if (fst->deflen_count == 0) {

			fst->downstream_reference_count += 1;
			return fst;
		}

		if (snd->deflen_count == 0) {

			snd->downstream_reference_count += 1;
			return snd;
		}

		/**
		 * Distributing multiplication with snd node to each sum term from fst
		**/
		CADD * distributed_mul = new CADD(fst->context);
		//distributed_mul->deflen_count = 1; ?

		CNODE_list * fst_nodes = fst->nodes->next;
		while (fst_nodes != 0 && fst_nodes->current != 0) {

			CNODE_list * snd_nodes = snd->nodes->next;
			while (snd_nodes != 0 && snd_nodes->current != 0) {

				CMUL * term_mul = new CMUL(fst->context);

				CNODE * new_pointer_same_fst_node = fst_nodes->current;
				CNODE * new_pointer_same_snd_node = snd_nodes->current; // fst_nodes->current ????

				new_pointer_same_fst_node->downstream_reference_count += 1;
				new_pointer_same_snd_node->downstream_reference_count += 1;

				term_mul->nodes->insert_next_element(new_pointer_same_fst_node);
				term_mul->nodes->insert_next_element(new_pointer_same_snd_node);

				term_mul->deflen_count = new_pointer_same_fst_node->deflen_count * new_pointer_same_snd_node->deflen_count;

				term_mul->upstream_merging();

				CNODE * final_term_mul;

				if (OPValues::shorten_on_recursive_cmul_merging) {

					CNODE * shortened = term_mul->upstream_shortening();
					if (shortened != 0) {

						term_mul->try_delete();
						final_term_mul = shortened;
					}
					else
						final_term_mul = term_mul;
				}
				else
					final_term_mul = term_mul;

				if (final_term_mul->deflen_count != 0) {

					distributed_mul->nodes->insert_next_element(final_term_mul);
					distributed_mul->deflen_count += final_term_mul->deflen_count;
				}
				else // ?
					final_term_mul->try_delete();

				snd_nodes = snd_nodes->next; 
			}

			fst_nodes = fst_nodes->next; 
		}

		if (OPValues::shorten_on_recursive_cmul_merging) {

			/**
			 * if shorten on rec is deactivated, 
			 * all the direct upstream nodes will be CMUL (all the term_mul)
			 * but distributed_mul is always CADD so there will be no merging anyways
			 * so the upstream merging call should remain here and not outside the if
			**/
			distributed_mul->upstream_merging(); 

			CNODE * shortened = distributed_mul->upstream_shortening();
			if (shortened != 0) {

				distributed_mul->try_delete();
				return shortened;
			}
		}

		return distributed_mul;
	}
	
	CNODE * CMUL::__upstream_merging(CADD * fst, CMUL * snd) { 
		
		/**
		 * Check maximum operation size for when to try to merge or not
		**/
		if ((fst->deflen_count * snd->deflen_count > OPValues::max_cmul_merge_size) &&
				(OPValues::always_default_multiplication == false ||
					(OPValues::always_default_multiplication && (fst->deflen_count != 1) && (snd->deflen_count != 1))
				)
			)
			return 0;

		/**
		 * a * 0 = 0
		**/
		if (fst->deflen_count == 0) {

			fst->downstream_reference_count += 1;
			return fst;
		}

		if (snd->deflen_count == 0) {

			snd->downstream_reference_count += 1;
			return snd;
		}

		/**
		 * Distributing multiplication with snd node to each sum term from fst
		**/
		CADD * distributed_mul = new CADD(fst->context);
		//distributed_mul->deflen_count = 1; ???

		CNODE_list * fst_nodes = fst->nodes->next;
		while (fst_nodes != 0 && fst_nodes->current != 0) {

			CMUL * term_mul = new CMUL(fst->context);

			CNODE * new_pointer_same_node = fst_nodes->current;

			new_pointer_same_node->downstream_reference_count += 1;
			snd->downstream_reference_count += 1;

			term_mul->nodes->insert_next_element(new_pointer_same_node);
			term_mul->nodes->insert_next_element(snd);

			term_mul->deflen_count = new_pointer_same_node->deflen_count * snd->deflen_count;

			term_mul->upstream_merging();

			CNODE * final_term_mul;

			if (OPValues::shorten_on_recursive_cmul_merging) {

				CNODE * shortened = term_mul->upstream_shortening();
				if (shortened != 0) {

					term_mul->try_delete();
					final_term_mul = shortened;
				}
				else
					final_term_mul = term_mul;
			}
			else
				final_term_mul = term_mul;

			if (final_term_mul->deflen_count != 0) {

				distributed_mul->nodes->insert_next_element(final_term_mul);
				distributed_mul->deflen_count += final_term_mul->deflen_count;
			}
			else // ?
				final_term_mul->try_delete();

			fst_nodes = fst_nodes->next; 
		}

		if (OPValues::shorten_on_recursive_cmul_merging) {

			/**
			 * if shorten on rec is deactivated,
			 * all the direct upstream nodes will be CMUL (all the term_mul)
			 * but distributed_mul is always CADD so there will be no merging anyways
			 * so the upstream merging call should remain here and not outside the if
			**/
			distributed_mul->upstream_merging(); 

			CNODE * shortened = distributed_mul->upstream_shortening();
			if (shortened != 0) {

				distributed_mul->try_delete();
				return shortened;
			}
		}

		return distributed_mul;
	}

	CNODE * CMUL::__upstream_merging(CMUL * fst, CMUL * snd) { 
		
		/**
		 * Check maximum operation size for when to try to merge or not
		**/
		if ((fst->deflen_count * snd->deflen_count > OPValues::max_cmul_merge_size) &&
				(OPValues::always_default_multiplication == false ||
					(OPValues::always_default_multiplication && (fst->deflen_count != 1) && (snd->deflen_count != 1))
				)
			)
			return 0;

		CNODE_list * nodes_fst = fst->nodes->next; // skipping dummy elements
		CNODE_list * nodes_snd = snd->nodes->next;

		/**
		 * When one of the input nodes is empty
		 * return the empty one (0 * a = 0)
		 * but the caller function will see it as a "different node"
		 * so also increase ref count
		 * (copy constructor avoided for efficiency)
		**/
		if (fst->deflen_count == 0) {

			fst->downstream_reference_count += 1;
			return fst;
		}

		if (snd->deflen_count == 0) {

			snd->downstream_reference_count += 1;
			return snd;
		}

		CMUL * merged = new CMUL(fst->context); // fst->context == snd->context assumed

		/**
		 * If one of them has no upstream reference, 
		 * its value is 0, so the multiplication result is also 0
		**/ 
		if (nodes_fst == 0 || nodes_fst->current == 0 || nodes_snd == 0 || nodes_snd->current == 0)
			return merged;

		merged->deflen_count = 1;

		if (OPValues::remove_duplicates_onmul) {

			std::unordered_set <CNODE *> freq;

			while (nodes_fst != 0 && nodes_fst->current != 0) {

				if (freq.find(nodes_fst->current) == freq.end()) {

					CNODE * new_pointer_same_node = nodes_fst->current;
					merged->nodes->insert_next_element(new_pointer_same_node);

					new_pointer_same_node->downstream_reference_count += 1;
					merged->deflen_count *= new_pointer_same_node->deflen_count;

					freq.insert(nodes_fst->current);
				}

				nodes_fst = nodes_fst->next;
			}

			while (nodes_snd != 0 && nodes_snd->current != 0) {

				if (freq.find(nodes_snd->current) == freq.end()) {

					CNODE * new_pointer_same_node = nodes_snd->current;
					merged->nodes->insert_next_element(new_pointer_same_node);

					new_pointer_same_node->downstream_reference_count += 1;
					merged->deflen_count *= new_pointer_same_node->deflen_count;

					freq.insert(nodes_snd->current);
				}

				nodes_snd = nodes_snd->next;
			}
		}
		else {

			while (nodes_fst != 0 && nodes_fst->current != 0) {

				CNODE * new_pointer_same_node = nodes_fst->current;
				merged->nodes->insert_next_element(new_pointer_same_node);

				new_pointer_same_node->downstream_reference_count += 1;
				merged->deflen_count *= new_pointer_same_node->deflen_count;

				nodes_fst = nodes_fst->next;
			}

			while (nodes_snd != 0 && nodes_snd->current != 0) {

				CNODE * new_pointer_same_node = nodes_snd->current;
				merged->nodes->insert_next_element(new_pointer_same_node);

				new_pointer_same_node->downstream_reference_count += 1;
				merged->deflen_count *= new_pointer_same_node->deflen_count;

				nodes_snd = nodes_snd->next;
			}
		}

		/**
		 * Recursive call that stops when max_merge_size < merging size
		**/
		merged->upstream_merging();

		if (OPValues::shorten_on_recursive_cmul_merging) {

			CNODE * shortened = merged->upstream_shortening();
			if (shortened != 0) {

				merged->try_delete();
				return shortened;
			}
		}

		return merged;
	}
	
	CNODE * CMUL::__upstream_merging(CADD * fst, CCC * snd) { 
		
		/**
		 * Check maximum operation size for when to try to merge or not
		**/
		if ((fst->deflen_count * snd->deflen_count > OPValues::max_cmul_merge_size) &&
				(OPValues::always_default_multiplication == false ||
					(OPValues::always_default_multiplication && (fst->deflen_count != 1) && (snd->deflen_count != 1))
				)
			)
			return 0;

		/**
		 * a * 0 = 0
		**/
		if (fst->deflen_count == 0) {

			fst->downstream_reference_count += 1;
			return fst;
		}

		/**
		 * snd is not tested to be 0
		 * because in current implementation
		 * it is guaranteed it cannot be 0
		**/ 

		CNODE_list * fst_nodes = fst->nodes->next;

		/**
		 * Distributing multiplication with snd node to each sum term from fst
		**/
		CADD * distributed_mul = new CADD(fst->context);
		//distributed_mul->deflen_count = 1; ???

		while (fst_nodes != 0 && fst_nodes->current != 0) {

			CMUL * term_mul = new CMUL(fst->context);

			CNODE * new_pointer_same_node = fst_nodes->current;

			new_pointer_same_node->downstream_reference_count += 1;
			snd->downstream_reference_count += 1;

			term_mul->nodes->insert_next_element(new_pointer_same_node);
			term_mul->nodes->insert_next_element(snd);

			term_mul->upstream_merging();

			CNODE * final_term_mul;

			if (OPValues::shorten_on_recursive_cmul_merging) {

				CNODE * shortened = term_mul->upstream_shortening();
				if (shortened != 0) {

					term_mul->try_delete();
					final_term_mul = shortened;
				}
				else
					final_term_mul = term_mul;
			}
			else
				final_term_mul = term_mul;

			if (final_term_mul->deflen_count != 0) {

				distributed_mul->nodes->insert_next_element(final_term_mul);
				distributed_mul->deflen_count += final_term_mul->deflen_count;
			}
			else // ?
				final_term_mul->try_delete();

			fst_nodes = fst_nodes->next;
		}

		if (OPValues::shorten_on_recursive_cmul_merging) {

			distributed_mul->upstream_merging();

			CNODE * shortened = distributed_mul->upstream_shortening();
			if (shortened != 0) {

				distributed_mul->try_delete();
				return shortened;
			}
		}

		return distributed_mul;
	}

	CNODE * CMUL::__upstream_merging(CCC * fst, CCC * snd) { 
		
		if ((fst->deflen_count * snd->deflen_count > OPValues::max_ccc_deflen_size) &&
			(OPValues::always_default_multiplication == false ||
				(OPValues::always_default_multiplication && (fst->deflen_count != 1) && (snd->deflen_count != 1))
				)
			)
			return 0;

		else
			return CCC::multiply(fst, snd);
	}

	CNODE * CMUL::__upstream_merging(CMUL * fst, CCC * snd) { 
		
		/**
		 * Check maximum operation size for when to try to merge or not
		**/
		if ((fst->deflen_count * snd->deflen_count > OPValues::max_cmul_merge_size) &&
				(OPValues::always_default_multiplication == false ||
					(OPValues::always_default_multiplication && (fst->deflen_count != 1) && (snd->deflen_count != 1))
				)
			)
			return 0;

		/**
		 * a * 0 = 0
		**/
		if (fst->nodes->next == 0 || fst->nodes->next->current == 0) {

			fst->downstream_reference_count += 1;
			return fst;
		}

		/**
		 * snd is not tested to be 0
		 * because in current implementation
		 * it is guaranteed it cannot be 0
		**/

		CMUL * merged;

		if (fst->downstream_reference_count == 1) {

			fst->downstream_reference_count += 1;

			snd->downstream_reference_count += 1;
			fst->nodes->insert_next_element(snd);
			fst->deflen_count *= snd->deflen_count;

			merged = fst;
		}
		else {

			merged = new CMUL(*fst);

			snd->downstream_reference_count += 1;
			merged->nodes->insert_next_element(snd);
			merged->deflen_count *= snd->deflen_count;
		}

		merged->upstream_merging();

		if (OPValues::shorten_on_recursive_cmul_merging) {

			CNODE * shortened = merged->upstream_shortening();
			if (shortened != 0) {

				merged->try_delete();
				return shortened;
			}
		}

		return merged;
	}
}


