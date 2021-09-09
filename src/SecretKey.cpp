#include "SecretKey.h"
#include "GlobalParams.h"
#include "Ciphertext.h"
#include "Plaintext.h"
#include "Permutation.h"
#include "Context.h"
#include "CCC.h"

namespace certFHE{

#pragma region Operators

	SecretKey & SecretKey::operator = (const SecretKey & secKey) {

		if (this->s != nullptr)
			delete [] this->s;
		
		if (this->s_mask != nullptr)
			delete [] this->s_mask;

		this->length = secKey.length;
		this->s = new uint64_t[secKey.length];

		for(uint64_t i = 0; i < secKey.length; i++)
			this->s[i] = secKey.s[i];

#if CERTFHE_USE_CUDA

		if (this->vram_s_mask != nullptr)
			CUDA_interface::VRAM_delete(this->vram_s_mask);
#endif

		this->set_mask_key();

		return *this;
	}

	std::ostream & operator << (std::ostream & out, const SecretKey & c) {

		uint64_t * key = c.getKey();

		for(uint64_t i = 0; i < c.getLength(); i++)
			out << key[i] << " ";
		out << '\n';

		return out;
	}

#pragma endregion

#pragma region Private functions

	void SecretKey::set_mask_key() {

		uint64_t length = this->length;
		uint64_t default_len = this->certFHEContext->getDefaultN();

		uint64_t * mask = new uint64_t[default_len];
		memset(mask, 0, sizeof(uint64_t) * default_len);
		
		for (uint64_t j = 0; j < length; j++) {

			uint64_t u64_j = s[j] / 64;
			uint64_t b = 63 - (s[j] % 64);

			mask[u64_j] |= (uint64_t)1 << b;
		}

		this->s_mask = mask;
		this->mask_length = default_len;

#if CERTFHE_USE_CUDA
		this->vram_s_mask = (uint64_t *)CUDA_interface::RAM_TO_VRAM_copy(this->s_mask, default_len * sizeof(uint64_t), 0);
#endif

	}

	uint64_t * SecretKey::encrypt_raw_bit(unsigned char bit) const {

		uint64_t n = this->certFHEContext->getN();
		uint64_t d = this->certFHEContext->getD();
		uint64_t * s = this->s;

		//@TODO: generate only a random of size n-d instead of n-d randoms()
		uint64_t * res = new uint64_t[n];

		if (bit == 0x01) {

			for (uint64_t i = 0; i < n; i++)
				if (Helper::exists(s, d, i))
					res[i] = 0x01;
				else
					res[i] = rand() % 2;
		}
		else {

			uint64_t sRandom = (uint64_t)rand() % d;
			uint64_t v = 0x00;
			bool vNok = true;

			for (uint64_t i = 0; i < n; i++)

				if (i != s[sRandom]){

					res[i] = rand() % 2;

					if (Helper::exists(s, d, i)) {

						if (vNok) {

							v = res[i];
							vNok = false;
						}
						v = v & res[i];
					}
				}

			if (v == 0x01)
				res[s[sRandom]] = 0;
			else
				res[s[sRandom]] = rand() % 2;

		}
		return res;
	}

#pragma endregion

#pragma region Public methods

	Ciphertext SecretKey::encrypt(const Plaintext & plaintext) const {

		return Ciphertext(plaintext, *this); 
	}

	Plaintext SecretKey::decrypt(const Ciphertext & ciphertext) const {

		return ciphertext.decrypt(*this); 
	}

	uint64_t * SecretKey::encrypt_raw(const Plaintext & plaintext) const {

		uint64_t n = this->certFHEContext->getN();
		uint64_t d = this->certFHEContext->getD();

		uint64_t div = n / (sizeof(uint64_t) * 8);
		uint64_t rem = n % (sizeof(uint64_t) * 8);
		uint64_t len = div;
		if (rem != 0)
			len++;

		unsigned char value = plaintext.getValue();
		uint64_t * vect = this->encrypt_raw_bit(value);

		uint64_t * _encValues = new uint64_t[len];

		uint64_t uint64index = 0;
		for (uint64_t step = 0; step < div; step++) {

			_encValues[uint64index] = 0x00;
			for (uint64_t s = 0; s < 64; s++) {

				uint64_t inter = (vect[step * 64 + s] & 0x01) << (sizeof(uint64_t) * 8 - 1 - s);
				_encValues[uint64index] = _encValues[uint64index] | inter;
			}
			uint64index++;
		}

		if (rem != 0) {

			_encValues[uint64index] = 0x00;
			for (uint64_t r = 0; r < rem; r++) {

				uint64_t inter = (vect[div * 64 + r] & 0x01) << (sizeof(uint64_t) * 8 - 1 - r);
				_encValues[uint64index] = _encValues[uint64index] | inter;

			}
		}

		delete[] vect;

		return _encValues;
	}

	uint64_t * SecretKey::encrypt_raw(const void * addr) const {

		uint64_t n = this->certFHEContext->getN();
		uint64_t d = this->certFHEContext->getD();

		uint64_t div = n / (sizeof(uint64_t) * 8);
		uint64_t rem = n % (sizeof(uint64_t) * 8);
		uint64_t len = div;
		if (rem != 0)
			len++;

		unsigned char value = (*(unsigned char *)addr) & 0x01;
		uint64_t * vect = this->encrypt_raw_bit(value);

		uint64_t * _encValues = new uint64_t[len];

		uint64_t uint64index = 0;
		for (uint64_t step = 0; step < div; step++) {

			_encValues[uint64index] = 0x00;
			for (uint64_t s = 0; s < 64; s++) {

				uint64_t inter = (vect[step * 64 + s] & 0x01) << (sizeof(uint64_t) * 8 - 1 - s);
				_encValues[uint64index] = _encValues[uint64index] | inter;
			}
			uint64index++;
		}

		if (rem != 0) {

			_encValues[uint64index] = 0x00;
			for (uint64_t r = 0; r < rem; r++) {

				uint64_t inter = (vect[div * 64 + r] & 0x01) << (sizeof(uint64_t) * 8 - 1 - r);
				_encValues[uint64index] = _encValues[uint64index] | inter;
			}
		}

		delete[] vect;

		return _encValues;
	}

	void SecretKey::applyPermutation_inplace(const Permutation & permutation){

		uint64_t * perm = permutation.getPermutation();

		uint64_t * current_key = new uint64_t[this->certFHEContext->getN()];
		
		for(uint64_t i = 0; i < this->certFHEContext->getN(); i++)
			current_key[i] = 0;

		for(uint64_t i = 0; i < length; i++)
			current_key[s[i]] = 1;

		uint64_t * temp = new uint64_t[this->certFHEContext->getN()];

		for (uint64_t i = 0; i < this->certFHEContext->getN(); i++)
			temp[i] = current_key[perm[i]];

		uint64_t * newKey = new uint64_t[length];
		uint64_t index = 0; 
		for(uint64_t i = 0; i < this->certFHEContext->getN(); i++) {

			if (temp[i] == 1)
				newKey[index++] = i;
		}

		delete [] this->s;
		this->s = newKey;

		delete [] this->s_mask;

#if CERTFHE_USE_CUDA
		CUDA_interface::VRAM_delete(this->vram_s_mask);
#endif

		this->set_mask_key();

		delete [] current_key;
		delete [] temp;
	}

	SecretKey SecretKey::applyPermutation(const Permutation & permutation) {

		SecretKey secKey(*this);
		secKey.applyPermutation_inplace(permutation);
		return secKey;
	}

	std::pair<unsigned char *, int> SecretKey::serialize() const {

		int ser_length = 4 + 2 + (int)this->length + (int)this->mask_length;

		uint64_t * serialization = new uint64_t[ser_length];

		Context * context = this->certFHEContext;

		serialization[0] = context->getN();
		serialization[1] = context->getD();
		serialization[2] = context->getS();
		serialization[3] = context->getDefaultN();

		serialization[4] = this->length;
		serialization[5] = this->mask_length;

		for (int i = 0; i < serialization[4]; i++)
			serialization[6 + i] = this->s[i];

		for (int i = 0; i < serialization[5]; i++)
			serialization[6 + this->length + i] = this->s_mask[i];

		return { (unsigned char *)serialization, (int)(ser_length * sizeof(uint64_t)) };
	}

	std::pair <SecretKey, Context> SecretKey::deserialize(unsigned char * serialization) {

		uint64_t * ser_int64 = (uint64_t *)serialization;

		Context context(ser_int64[0], ser_int64[1]);

		uint64_t length = ser_int64[4];
		uint64_t mask_length = ser_int64[5];

		uint64_t * s = new uint64_t[length];
		uint64_t * s_mask = new uint64_t[mask_length];

		for (int i = 0; i < length; i++)
			s[i] = ser_int64[6 + i];

		for (int i = 0; i < mask_length; i++)
			s_mask[i] = ser_int64[6 + length + i];

		SecretKey to_return(s, length, s_mask, mask_length, &context);

		for (int i = 0; i < length; i++)
			s[i] = 0;

		for (int i = 0; i < mask_length; i++)
			s_mask[i] = 0;

		delete[] s;
		delete[] s_mask;

		return { to_return, context };
	}

#pragma endregion

#pragma region Constructors and destructor

	SecretKey::SecretKey(const uint64_t * s, const uint64_t length, const uint64_t * s_mask, const uint64_t mask_length, const Context * context) {

		this->certFHEContext = new Context(*context);

		this->s = new uint64_t[length];
		this->length = length;

		this->s_mask = new uint64_t[mask_length];
		this->mask_length = mask_length;

		for (int i = 0; i < length; i++)
			this->s[i] = s[i];

		for (int i = 0; i < mask_length; i++)
			this->s_mask[i] = s_mask[i];
	}

	SecretKey::SecretKey(const Context & context) {	

		// seed once again the PRNG with local time
		srand((unsigned int)time(0));

		this->certFHEContext = new Context(context);

		uint64_t _d = certFHEContext->getD();
		uint64_t _n = certFHEContext->getN();

		this->s =  new uint64_t[_d];
		this->length = _d;

		uint64_t count = 0;
		bool go = true;
		while (go) {

			uint64_t temp = rand() % _n;
			if (Helper::exists(s,_d, temp))
				continue;

			s[count] = temp;
			count++;
			if (count == _d)
				go = false;
		}
		
		this->set_mask_key();

	}

	SecretKey::SecretKey(const SecretKey & secKey) {

		this->certFHEContext = new Context(*secKey.certFHEContext);

		this->s = new uint64_t [secKey.length];
		this->length = secKey.length;

		for(uint64_t i = 0; i < secKey.length; i++)
			this->s[i] = secKey.s[i];
		
		this->set_mask_key();
	}

	SecretKey::~SecretKey() { 	

		for (uint64_t i = 0; i < length; i++)
			s[i] = 0;

		uint64_t default_len = this->certFHEContext->getDefaultN();
		for (uint64_t i = 0; i < default_len; i++)
			s_mask[i] = 0;

		if (this->s != nullptr) {

			delete [] this->s;
			this->s = nullptr;
		}

		if (this->s_mask != nullptr) {

			delete[] this->s_mask;
			this->s_mask = nullptr;
		}
		
		this->length = -1;

		if (this->certFHEContext != nullptr) {

			delete this->certFHEContext;
			this->certFHEContext = nullptr;
		}

#if CERTFHE_USE_CUDA

		if (this->vram_s_mask != nullptr)
			CUDA_interface::VRAM_delete(this->vram_s_mask);
#endif

	}

#pragma endregion

}
