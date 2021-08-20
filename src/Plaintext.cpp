#include "Plaintext.h"

using namespace certFHE;

namespace certFHE {

#pragma region Operators

	std::ostream & operator << (std::ostream & out, const Plaintext & c) {
   
		char val = c.getValue();
		out << (val | 30) << '\n';

		return out;
	}

#pragma endregion

}