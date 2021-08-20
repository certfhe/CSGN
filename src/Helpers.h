#ifndef HELPERS_H
#define HELPERS_H

#include "utils.h"
#include "ArgClasses.h"
#include "Threadpool.h"

namespace certFHE{

    /**
     * Library clased, used to perform operations at the library level, such as library initialization
    **/
    class Library{

        Library() {}

		/**
			* Threadpool for multithreading multiplication at the library level
		**/
		static Threadpool <Args *> * threadpool;

    public:

        /**
         * Initialize the library by seeding the PRNG with local time
		 * and optionally initialize threadpool
        **/
		static void initializeLibrary(bool initPools = true);

		/**
		 * Getter for multiplication threadpool
		**/
		static Threadpool <Args *> * getThreadpool();

    };

    /**
     * Helper class
    **/
    class Helper{

        Helper() {}

		/**
		 * Internal function called only by u64_multithread_cpy
		**/
		static void u64_chunk_cpy(Args * raw_args);

    public:

        /**
         * Static function to validate if a vector contains a specific value
        **/
        static bool exists(const uint64_t * v, const uint64_t len, const uint64_t value);

		/**
		 * Function that uses threads from threadpool 
		 * to simultaneously copy unit64_t values from one array to another
		 * NOTE: it does not check whether the use of multithreading is efficient or not
		 *		 this should be checked before calling this function
		**/
		static void u64_multithread_cpy(const uint64_t * src, uint64_t * dest, uint64_t to_cpy_len);
    };

}

#endif