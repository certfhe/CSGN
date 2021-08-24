#ifndef CUDA_INTERFACE_H
#define CUDA_INTERFACE_H

/**
 * Macro to enable (parametrized) CUDA for CCC operations and storage on VRAM
**/
#define CERTFHE_USE_CUDA false

#if CERTFHE_USE_CUDA

#include <stdint.h>
#include "ArgClasses.h"

namespace certFHE {

	/**
	 * Class that provides (the complete) interface for any GPU operation or Video RAM manipulation
	 * inside the certFHE namespace
	**/
	class CUDA_interface {

		/**
		 * Maximum number of threads per block
		 * ("block" and "thread" have the same meaning as in official CUDA documentation)
		**/
		static const int MAX_THREADS_PER_BLOCK;

	public:

		/**
		 * NOTES: -> ALL functions declared below are HOST functions
		 *		  -> VRAM refers only to Video RAM (and not virtual memory)
		 *		  -> RAM refers to "normal" / "host" virtual memory or physical memory
		 *		  -> in this class (only), ciphertext generally refers to raw ciphertext array chunk,
		 *			 stored in either RAM or VRAM
		 *		  -> pointers received as arguments that should point to VRAM are assumed to point to VRAM, NO CHECK IS PERFORMED
		**/

		/**
		 * NAMING CONVENTIONS:
		 *						-> for ciphertext copying: X_TO_Y_copy, X - location from where to copy, Y - location of the copy
		 *																				X, Y = RAM / VRAM
		 *
		 *						-> for ciphertext multiply: X_Y_Z_ciphertext_multiply, X - location of fst, Y - location of snd, Z - location of result,
		 *																				X, Y, Z = RAM / VRAM
		**/

		/****************** COPYINGS AND DELETION ******************/

		/**
		 * allocate VRAM and copy values to it from RAM
		**/
		static void * RAM_TO_VRAM_copy(void * ram_address, uint64_t size_to_copy, void * vram_address = 0);

		/**
		 * allocate RAM and copy values to it from VRAM
		**/
		static void * VRAM_TO_RAM_copy(void * vram_address, uint64_t size_to_copy, void * ram_address = 0);

		/**
		 * allocate VRAM and copy values to it from VRAM
		**/
		static void * VRAM_TO_VRAM_copy(void * vram_address, uint64_t size_to_copy, void * vram_new_address = 0);

		/**
		 * Wrapper around cudaFree, that deallocates memory from VRAM
		**/
		static void VRAM_delete(void * vram_address);

		/****************** MULTIPLICATION ******************/

		/**
		 * multiplies two ciphertext chunks, both residing in VRAM, and stores the result in VRAM
		**/
		static uint64_t * VRAM_VRAM_VRAM_chiphertext_multiply(uint64_t deflen_to_uint64, uint64_t fst_deflen_cnt, uint64_t snd_deflen_cnt,
			const uint64_t * fst, const uint64_t * snd);

		/**
		 * multiplies two ciphertext chunks, one of them residing in RAM and the other in VRAM, and stores the result in VRAM
		 * the ciphertext chunk which is not in VRAM is temporarily copied in VRAM, and after the result is obtained that copy is deleted
		**/
		static uint64_t * RAM_VRAM_VRAM_chiphertext_multiply(uint64_t deflen_to_uint64, uint64_t fst_deflen_cnt, uint64_t snd_deflen_cnt,
			const uint64_t * fst, const uint64_t * snd);

		/**
		 * multiplies two ciphertext chunks, both residing in RAM, and stores the result in VRAM
		 * both ciphertext chunk operands are copied in VRAM, and after the result is obtained the copies are deleted
		**/
		static uint64_t * RAM_RAM_VRAM_chiphertext_multiply(uint64_t deflen_to_uint64, uint64_t fst_deflen_cnt, uint64_t snd_deflen_cnt,
			const uint64_t * fst, const uint64_t * snd);

		/****************** ADDITION ******************/

		/**
		 * adds two ciphertext chunks, both residing in VRAM, and stores the result in VRAM
		**/
		static uint64_t * VRAM_VRAM_VRAM_chiphertext_addition(uint64_t deflen_to_uint64, uint64_t fst_deflen_cnt, uint64_t snd_deflen_cnt,
			const uint64_t * fst, const uint64_t * snd);

		/**
		 * adds two ciphertext chunks, one of them residing in RAM and the other in VRAM, and stores the result in VRAM
		 * unlike multiplication analogue case, no temporary copies are created
		**/
		static uint64_t * RAM_VRAM_VRAM_chiphertext_addition(uint64_t deflen_to_uint64, uint64_t fst_deflen_cnt, uint64_t snd_deflen_cnt,
			const uint64_t * fst, const uint64_t * snd);

		/**
		 * adds two ciphertext chunks, both residing in RAM, and stores the result in VRAM
		 * unlike multiplication analogue case, no temporary copies are created
		**/
		static uint64_t * RAM_RAM_VRAM_chiphertext_addition(uint64_t deflen_to_uint64, uint64_t fst_deflen_cnt, uint64_t snd_deflen_cnt,
			const uint64_t * fst, const uint64_t * snd);

		/****************** DECRYPTION ******************/

		/**
		 * NOTE: to_decrypt and sk_mask are expected to already reside in VRAM
		**/
		static int VRAM_ciphertext_decryption(uint64_t deflen_to_uint64, uint64_t to_decrypt_deflen_cnt, const uint64_t * to_decrypt, const uint64_t * sk_mask);

		/****************** PERMUTATION ******************/

		/**
		 * It permutes INPLACE
		 * NOTE: to_permute and perm_inversions are expected to already reside in VRAM
		**/
		static void VRAM_ciphertext_permutation(uint64_t deflen_to_uint64, uint64_t to_permute_deflen_cnt, uint64_t * to_permute, const PermInversion * perm_inversions, uint64_t inv_cnt);
	};
}



#endif
#endif
