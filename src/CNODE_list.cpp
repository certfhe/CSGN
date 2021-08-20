#include "CNODE_list.h"

namespace certFHE {
	
	CNODE_list * CNODE_list::pop_current_node() {

		CNODE_list * to_return = this->next;

		if(this->prev != 0)
			this->prev->next = this->next;

		if(this->next != 0)
			this->next->prev = this->prev;

		this->next = 0;
		this->prev = 0;

		if (this->current != 0) {

			this->current->try_delete();
			this->current = 0;
		}

		delete this;

		return to_return;
	}

	void CNODE_list::insert_next_element(CNODE * to_insert_raw) {

		if (this->current == 0) {

			this->current = to_insert_raw;
			return;
		}

		CNODE_list * to_insert = new CNODE_list(to_insert_raw);

		to_insert->prev = this;
		to_insert->next = this->next;

		if (this->next != 0)
			this->next->prev = to_insert;

		this->next = to_insert;
	}
}
