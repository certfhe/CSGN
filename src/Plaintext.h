#ifndef PLAINTEXT_H
#define PLAINTEXT_H

#include "utils.h"

namespace certFHE{

    /**
     * Class used for storing the plaintext which belongs to F2 = {0,1}
    **/
    class Plaintext{

        unsigned char value;

    public:

		Plaintext() : value(0) {}

		Plaintext(uint64_t value) : value(BIT(value)) {}

		virtual ~Plaintext() {}

        /**
         * Getter and setter
        **/
		unsigned char getValue() const { return this->value; }
		void setValue(unsigned char value) { this->value = BIT(value); }

        /**
         * Friend class for operator <<
        **/
        friend std::ostream & operator << (std::ostream & out, const Plaintext & c);
        
    };

}

#endif