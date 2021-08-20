#ifndef CNODE_LIST_HEADER 
#define CNODE_LIST_HEADER

#include "CNODE.h"

namespace certFHE {

	/**
	 * Double linked list for CNODE elements
	**/
	class CNODE_list {

	public:

		CNODE_list * prev;  // previous list element
		CNODE_list * next;  // next list element

		CNODE * current;  // CNODE element pointed by current list element

		CNODE_list() : prev(0), current(0), next(0) {}

		CNODE_list(CNODE * first_node_raw) : prev(0), current(first_node_raw), next(0) {}

		CNODE_list(const CNODE_list & other) = delete;
		CNODE_list(const CNODE_list && other) = delete;

		CNODE_list & operator = (const CNODE_list & other) = delete;
		CNODE_list & operator = (const CNODE_list && other) = delete;

		/**
		 * DOES NOT DELETE THE ENTIRE LIST
		 * the list of elements must be manually deleted
		 * to distinguish between the deletion of current node
		 * and the deletion of all chained nodes with the current one
		**/
		~CNODE_list() {}

		/**
		 * returns THE NEXT ELEMENT from the list, or NULL if this one was the last
		**/
		CNODE_list * pop_current_node();

		/**
		 * inserts an element between the current and the next after it,
		 * or at the head of the list if it is the last
		 * or makes it the first element if current element is null
		**/
		void insert_next_element(CNODE * to_insert_raw);
	};

}

#endif