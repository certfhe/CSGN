#include "CNODE.h"

namespace certFHE {

	std::unordered_map <CNODE *, unsigned char> CNODE::decryption_cached_values;

	CNODE::CNODE(const CNODE & other) {

		this->deflen_count = other.deflen_count;
		this->context = other.context;
		this->downstream_reference_count = 1;
	}

	CNODE::CNODE(const CNODE && other) {

		this->deflen_count = other.deflen_count;
		this->context = other.context;
		this->downstream_reference_count = 1; // ??? other.downstream_reference_count;
	}

	void CNODE::try_delete() {

		if (this->downstream_reference_count == 1)
			delete this;

		else if (this->downstream_reference_count < 1)
			std::cout << "ERROR in try_delete: reference count smaller than 1 (nothing got deleted)\n";

		else
			this->downstream_reference_count -= 1;
	}

	Context CNODE::getContext() {

		return *(this->context);
	}

	uint64_t CNODE::getDeflenCnt() {

		return this->deflen_count;
	}

	std::ostream & operator << (std::ostream & out, const CNODE & cnode) {

		out << "deflen_count=" << cnode.deflen_count << " " << "ref_cnt=" << cnode.downstream_reference_count << '\n';

		return out;
	}
}

