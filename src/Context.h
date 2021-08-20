#ifndef CONTEXT_H
#define CONTEXT_H

#include "utils.h"
#include "Helpers.h"

namespace certFHE{

    /**
     * Context of the certFHE HE scheme 
    **/
    class Context {

    private:

        uint64_t N;             // The length of the (default) ciphertext in bits. Usually n = 2sd.
        uint64_t D;             // Number of secret positions ([0,N-1])
        uint64_t S;             // n = 2sd
        uint64_t defaultLen;    //Default length in UL's (chunks of 64 bit).

    public:

        /**
         * Deleted default constructor
        **/
        Context()  = delete;

        /**
         * Copy constructor
        **/
        Context(const Context& context);

        /**
         * Constructor
         * @param[in] N: Dimension parameter n(lambda)
         * @param[in] D: Number of secret positions
        **/
        Context(const uint64_t pN, const uint64_t pD);

        /**
         * Destructor
        **/
		virtual ~Context() {}

        /**
         * Assignment operator
         * @param[in] context: a const reference to a Context object
         * @return value : a deep copy of the context parameter
        **/
        Context & operator = (const Context & context);

		bool operator == (const Context & other) const {

			return this->N == other.N && this->D == other.D
				&& this->S == other.S && this->defaultLen == other.defaultLen;
		}

		bool operator != (const Context & other) const { return !(*this == other); }

        friend std::ostream & operator << (std::ostream & out, const Context & c);

        /**
         * Getters and setters
        **/
		uint64_t getN() const { return this->N; }
		uint64_t getD() const { return this->D; }
		uint64_t getS() const { return this->S; }
		uint64_t getDefaultN() const { return this->defaultLen; }

        void setN(uint64_t n) {

			this->N = n;
			this->S = n / (2 * this->D);
		}

		void setD(uint64_t d) {

			this->D = d;
			this->S = this->N / (2 * this->D);
		}

    };

}

#endif