#include "CNODE.h"

#if CERTFHE_MULTITHREADING_EXTENDED_SUPPORT

#ifndef CNODE_DISJOIN_SET_H 
#define CNODE_DISJOIN_SET_H

namespace certFHE {

	/**
	 * Class that implements disjoint set forest 
	 * With path compression, union by rank
	 * And CUSTOM deletion
	 * (currently) only used for multithreading mutex selection
	**/
	class CNODE_disjoint_set {

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

		/**
		 * Get the root of the set
		 * With path compression
		**/
		CNODE_disjoint_set * get_root();

		/**
		 * Union (by rank) of two sets (this, other)
		**/
		void set_union(CNODE_disjoint_set * other);

		/**
		 * CUSTOM remove operation
		 * Swaps associated Ciphertext object with a child node until a leaf is found
		 * When the node is a leaf, it is deleted
		**/
		CNODE_disjoint_set * remove_from_set();
	};
}

#endif

#endif

