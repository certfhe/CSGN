#include "COP.h"

#if CERTFHE_MULTITHREADING_EXTENDED_SUPPORT

#include "Ciphertext.h"
#include "CNODE_disjoint_set.h"

#endif

namespace certFHE {

	COP::COP(Context * context): CNODE(context) {

		this->nodes = new CNODE_list;
		this->nodes->prev = 0;
		this->nodes->next = 0;
		this->nodes->current = (CNODE *)0xDEADBEEFDEADBEEF;
	}

	COP::~COP() {

		try {

			nodes->current = 0; // dummy current node set to 0
			while (nodes != 0) 
				nodes = nodes->pop_current_node();

		}
		catch (std::exception e) {

			std::cout << "ERROR in destructor of COP node: " << e.what() << '\n';
		}
	}

	COP::COP(const COP & other) : CNODE(other) {

		this->nodes = new CNODE_list;
		this->nodes->prev = 0;
		this->nodes->next = 0;
		this->nodes->current = (CNODE *)0xDEADBEEFDEADBEEF;

		CNODE_list * othernodes = other.nodes->next;
		
		while (othernodes != 0 && othernodes->current != 0) {

			this->nodes->insert_next_element(othernodes->current);
			othernodes->current->downstream_reference_count += 1;

			othernodes = othernodes->next;
		}
	}

	COP::COP(const COP && other) : CNODE(other) {

		this->nodes = other.nodes;
	}

	std::ostream & operator << (std::ostream & out, const COP & cop) {

		out << "COP\n" << static_cast <const CNODE &> (cop);
		out << "***NODES LIST:***\n";

		CNODE_list * copnodes = cop.nodes->next;
		while (copnodes != 0 && copnodes->current != 0) {

			CCC * ccc_current = dynamic_cast <CCC *> (copnodes->current);
			if (ccc_current != 0) 
				out << *ccc_current << "----------\n";
			
			else {

				COP * cop_current = dynamic_cast <COP *> (copnodes->current);
				out << *cop_current << "----------\n";
			}

			copnodes = copnodes->next;
		}

		return out;
	}

	CNODE * COP::upstream_shortening() {

		CNODE_list * thisnodes = this->nodes->next;
		
		/**
		 * Check to see whether this node has only one upstream reference or not
		**/
		if (thisnodes != 0 && thisnodes->next == 0 && thisnodes->current != 0) {

			CNODE * shortened = thisnodes->current->upstream_shortening();

			if (shortened != 0) {

				thisnodes = thisnodes->pop_current_node(); // always becames NULL pointer
				this->nodes->insert_next_element(shortened);
			}

			this->nodes->next->current->downstream_reference_count += 1;
			return this->nodes->next->current;
		}
		else
			return 0;
	}

	void COP::serialize(unsigned char * serialization_buffer, std::unordered_map <void *, std::pair<uint32_t, int>> & addr_to_id) {

		uint32_t * ser_int32 = (uint32_t *)serialization_buffer;
		ser_int32[0] = addr_to_id[this].first;

		uint64_t * ser_int64 = (uint64_t *)(serialization_buffer + sizeof(uint32_t));

		ser_int64[0] = this->deflen_count;
		// ser_int64[1] completed after the next while loop

		uint64_t upstream_ref_cnt = 0; 

		CNODE_list * thisnodes = this->nodes->next;
		while (thisnodes != 0 && thisnodes->current != 0) {

			ser_int32[5 + upstream_ref_cnt] = addr_to_id[thisnodes->current].first;

			upstream_ref_cnt += 1;
			thisnodes = thisnodes->next;
		}

		ser_int64[1] = upstream_ref_cnt;
	}

#if CERTFHE_MULTITHREADING_EXTENDED_SUPPORT

	void COP::concurrency_guard_structure_rebuild(std::unordered_map <CNODE *, Ciphertext *> & node_to_ctxt, Ciphertext * associated_ctxt) {

		if (node_to_ctxt.find(this) == node_to_ctxt.end()) {

			node_to_ctxt[this] = associated_ctxt;

			CNODE_list * thisnodes = this->nodes->next;
			while (thisnodes != 0 && thisnodes->current != 0) {

				thisnodes->current->concurrency_guard_structure_rebuild(node_to_ctxt, associated_ctxt);
				thisnodes = thisnodes->next;
			}
		}
		else
			associated_ctxt->concurrency_guard->set_union(node_to_ctxt.at(this)->concurrency_guard);
	}

#endif

}




