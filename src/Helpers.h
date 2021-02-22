#ifndef HELPERS_H
#define HELPERS_H

#include "utils.h"

namespace certFHE{

    /**
     * Library clased, used to perform operations at the library level, such as library initialization
    **/
    class Library{

        private:

            Library() {}
        public:

        /**
         * Initialize the library by seeding the PRNG with local time
        **/
        static void initializeLibrary();

    };

    /**
     * Helper class
    **/
    class Helper{
    
    private:

        Helper() {}
    public:

        /**
         * Static function to validate if a vector contains a specific value
        **/
        static bool exists(const uint64_t*v,const uint64_t len, const uint64_t value);

        /**
         * Deletes a pointer allocated through the certFHE library
        **/
        static void deletePointer(void* pointer, bool isArray);
    };






}


#endif