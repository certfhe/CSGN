#ifndef PLAINTEXT_H
#define PLAINTEXT_H

#include "utils.h"

using namespace std;

namespace certFHE{

    /**
     * Class used for storing the plaintext which belongs to F2 = {0,1}
    **/
    class Plaintext{

    private:

        unsigned char value;

    public:

        /**
         * Default constructor
        **/
        Plaintext();

        /**
         * Custom constructor
        **/
        Plaintext(const int value);

        /**
         * Destructor
        **/
        virtual ~Plaintext();

        /**
         * Getter and setter
        **/
        unsigned char getValue() const;
        void setValue(unsigned char value);

        /**
         * Friend class for operator<<
        **/
        friend ostream& operator<<(ostream &out, const Plaintext &c);
        
    };






}

#endif