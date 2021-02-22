#ifndef CONTEXT_H
#define CONTEXT_H

#include "utils.h"
#include "Helpers.h"

using namespace std;

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
        Context(const uint64_t pN,const uint64_t pD);

        /**
         * Destructor
        **/
        virtual ~Context();

        /**
         * Equal operator
         * @param[in] context: a const. ref. to a Context object
         * @return value : a deep copy of the context parameter
        **/
        Context& operator=(const Context& context);

        /**
         * Friend class for operator<<
        **/
        friend ostream& operator<<(ostream &out, const Context &c);


        /**
         * Getters and setters
        **/
        uint64_t getN() const;
        uint64_t getD() const;
        uint64_t getS() const;
        uint64_t getDefaultN() const;

        void setN(uint64_t n);
        void setD(uint64_t d);        




    };

}

#endif