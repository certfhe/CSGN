#include "CNODE.h"

#if CERTFHE_MULTITHREADING_EXTENDED_SUPPORT

#ifndef CNODE_DISJOIN_SET_H 
#define CNODE_DISJOIN_SET_H

namespace certFHE {

	/**
	 * Class that implements disjoint set forest 
	 * With path compression, union by rank
	 * And CUSTOM deletion
	 * (currently) used for multithreading mutex selection
	**/
	class CNODE_disjoint_set {

		/**
		 * mutex that is required to be locked in order to do ANY operation on ANY set
		 * (so, there can only be one thread at a time that searches root / does union / removes)
		**/
		static std::mutex op_mutex; 

	public:

		std::mutex mtx;

		Ciphertext * current; // associated Ciphertext object

		int rank;  // upper bound for depth of the current set

		CNODE_disjoint_set * parent;  // parent of the node, root has this field 0
		CNODE_disjoint_set * child;   // one of the children of this node
		CNODE_disjoint_set * prev;  // one of the neighbours = some other child of this->parent
		CNODE_disjoint_set * next;  // same as prev

		CNODE_disjoint_set() : current(0), rank(0), parent(0), child(0), prev(0), next(0) {}

		CNODE_disjoint_set(Ciphertext * current_raw) : current(current_raw),
			rank(0), parent(0), child(0), prev(0), next(0) {}

		CNODE_disjoint_set(const CNODE_disjoint_set & other) = delete;
		CNODE_disjoint_set(const CNODE_disjoint_set && other) = delete;

		CNODE_disjoint_set & operator = (const CNODE_disjoint_set & other) = delete;
		CNODE_disjoint_set & operator = (const CNODE_disjoint_set && other) = delete;

		~CNODE_disjoint_set() {}

		// set operations WITHOUT thread safety

		/**
		 * NO OP_MUTEX LOCK
		**/
		CNODE_disjoint_set * __get_root();

		/**
		 * NO OP_MUTEX LOCK
		**/
		void __set_union(CNODE_disjoint_set * other);

		/**
		 * NO OP_MUTEX LOCK
		**/
		CNODE_disjoint_set * __remove_from_set();

		/**
		 * Get the root of the set
		**/
		CNODE_disjoint_set * get_root() {

			std::lock_guard <std::mutex> guard(op_mutex);
			return this->__get_root();
		}

		/**
		 * Union of two sets (this, other)
		**/
		void set_union(CNODE_disjoint_set * other) {

			std::lock_guard <std::mutex> guard(op_mutex);
			this->__set_union(other);
		}

		/**
		 * CUSTOM remove operation
		 * Swaps associated Ciphertext object with a child node until a leaf is found
		 * When the node is a leaf, it is deleted
		**/
		CNODE_disjoint_set * remove_from_set() {

			std::lock_guard <std::mutex> guard(op_mutex);
			return this->__remove_from_set();
		}
	};
}

#endif

#endif

