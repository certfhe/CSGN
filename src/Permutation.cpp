#include "Permutation.h"
#include "GlobalParams.h"

namespace certFHE{

#pragma region Public methods
	
	Permutation Permutation::getInverse() {

		uint64_t * p = new uint64_t[length];

		for (uint64_t i = 0; i < length; i++) {
			for (uint64_t j = 0; j < length; j++) {
				

				if (permutation[j] == i) {

					p[i] = j; 
					break;
				}
			}
		}

		uint64_t this_invcnt = this->inversions_cnt;

		PermInversion * inverseInvs = new PermInversion[this_invcnt];
		for (int i = 0; i < this_invcnt; i++)
			inverseInvs[i] = this->inversions[this_invcnt - 1 - i];
    
		Permutation invP(p, length, inverseInvs, this_invcnt);
		delete[] p;

		return invP;
	}

	std::pair<unsigned char *, int> Permutation::serialize() const {

		int ser_byte_length = 2 + (int)this->length + 4 * (int)this->inversions_cnt;

		uint64_t * serialization = new uint64_t[ser_byte_length];

		serialization[0] = this->length;
		serialization[1] = this->inversions_cnt;

		for (int i = 0; i < serialization[0]; i++)
			serialization[2 + i] = this->permutation[i];
		
		for (int i = 0; i < serialization[1]; i++) {

			serialization[2 + this->length + 4 * i] = this->inversions[i].fst_u64_ch;
			serialization[2 + this->length + 4 * i + 1] = this->inversions[i].fst_u64_r;
			serialization[2 + this->length + 4 * i + 2] = this->inversions[i].snd_u64_ch;
			serialization[2 + this->length + 4 * i + 3] = this->inversions[i].snd_u64_r;
		}

		return { (unsigned char *)serialization, ser_byte_length };
	}

	Permutation Permutation::deserialize(unsigned char * serialization) {

		uint64_t * ser_int64 = (uint64_t *)serialization;

		uint64_t length = ser_int64[0];
		uint64_t inv_cnt = ser_int64[1];

		uint64_t * perm = new uint64_t[length];
		PermInversion * invs = new PermInversion[inv_cnt];

		for (int i = 0; i < length; i++)
			perm[i] = ser_int64[2 + i];

		for (int i = 0; i < inv_cnt; i++) {

			invs[i].fst_u64_ch = serialization[2 + length + 4 * i];
			invs[i].fst_u64_r = serialization[2 + length + 4 * i + 1];
			invs[i].snd_u64_ch = serialization[2 + length + 4 * i + 2];
			invs[i].snd_u64_r = serialization[2 + length + 4 * i + 3];
		}

		Permutation to_return(perm, length, invs, inv_cnt);

		delete[] perm;
		delete[] invs;

		return to_return;
	}

#pragma endregion

#pragma region Operators

	std::ostream & operator << (std::ostream & out, const Permutation & p) {

		uint64_t * _p = p.getPermutation();
		uint64_t l = p.getLength();

		out << "(";
		for(uint64_t i = 0; i < l; i++)
			out << i << " ";
		out << ")" << '\n';

		out << "(";
		for(uint64_t i = 0; i < l; i++)
			out << _p[i] << " ";
		out << ")" << '\n';

		return out;
	}

	Permutation & Permutation::operator = (const Permutation & perm) {

		this->length = perm.getLength();
		this->inversions_cnt = perm.getInversionsCnt();

		if (this->permutation != nullptr)
			delete[] this->permutation;

		if (this->inversions != nullptr)
			delete[] this->inversions;

		this->permutation = new uint64_t [this->length];
		this->inversions = new PermInversion[perm.inversions_cnt];

		for (uint64_t i = 0; i < this->length; i++)
			this->permutation[i] = perm.permutation[i];

		for (uint64_t i = 0; i < this->inversions_cnt; i++)
			this->inversions[i] = perm.inversions[i];

		this->inversions_cnt = perm.inversions_cnt;

#if CERTFHE_USE_CUDA
		this->vram_inversions = (PermInversion *)CUDA_interface::RAM_TO_VRAM_copy(this->vram_inversions, perm.inversions_cnt * sizeof(PermInversion), 0);
#endif

		return *this;
	}

	Permutation Permutation::operator + (const Permutation & other) const {

		if (length != other.getLength())
			throw std::invalid_argument("cannot add permutations with different length");

		uint64_t * p = new uint64_t[length];
		uint64_t * p_other = other.getPermutation();

		for (uint64_t i = 0; i < length; i++)
			p[i] = this->permutation[p_other[i]];

		uint64_t this_invcnt = this->inversions_cnt;
		uint64_t other_invcnt = other.inversions_cnt;

		PermInversion * resultInvs = new PermInversion[this_invcnt + other_invcnt];
		int i;

		for (i = 0; i < this_invcnt; i++)
			resultInvs[i] = this->inversions[i];

		for (i; i < this_invcnt + other_invcnt; i++)
			resultInvs[i] = other.inversions[i - this_invcnt];

		Permutation result(p, length, resultInvs, this_invcnt + other_invcnt);

		delete[] p;
		delete[] resultInvs;

		return result;
	}

	Permutation & Permutation::operator += (const Permutation & other) {

		if (length != other.getLength())
			throw std::invalid_argument("cannot add permutations with different length");

		uint64_t * p = new uint64_t[length];
		uint64_t * p_other = other.getPermutation();

		for (uint64_t i = 0; i < length; i++)
			p[i] = this->permutation[p_other[i]];

		uint64_t this_invcnt = this->inversions_cnt;
		uint64_t other_invcnt = other.inversions_cnt;

		PermInversion * thisNewInvs = new PermInversion[this_invcnt + other_invcnt];
		int i;

		for (i = 0; i < this_invcnt; i++)
			thisNewInvs[i] = this->inversions[i];

		for (i; i < this_invcnt + other_invcnt; i++)
			thisNewInvs[i] = other.inversions[i - this_invcnt];

		this->inversions_cnt += other.inversions_cnt;

		delete[] this->permutation;
		this->permutation = p;

		delete[] this->inversions;
		this->inversions = thisNewInvs;

		this->inversions_cnt += other_invcnt;

#if CERTFHE_USE_CUDA

		CUDA_interface::VRAM_delete(this->vram_inversions);
		this->vram_inversions = (PermInversion *)CUDA_interface::RAM_TO_VRAM_copy((void *)thisNewInvs, this->inversions_cnt * sizeof(PermInversion), 0);
#endif

		return *this;
	}

#pragma endregion

#pragma region Getters and setters

	void Permutation::setPermutation(const uint64_t * perm, uint64_t len, uint64_t inv_cnt, const PermInversion * invs) {

		if (this->permutation != nullptr)
			delete[] this->permutation;

		if (this->inversions != nullptr)
			delete[] this->inversions;

		this->permutation = new uint64_t[len];
		this->inversions = new PermInversion[inv_cnt];

		this->length = len;
		this->inversions_cnt = inv_cnt;

		for (uint64_t i = 0; i < len; i++)
			this->permutation[i] = perm[i];

		for (uint64_t i = 0; i < len; i++)
			this->inversions[i] = invs[i];
	}

#pragma endregion

#pragma region Constructors and destructor

	Permutation::Permutation() {

		this->length = 0;
		this->inversions_cnt = 0;

		this->permutation = nullptr;
		this->inversions = nullptr;
	}

	Permutation::Permutation(uint64_t len) {

		this->permutation = new uint64_t[len];
		this->inversions = new PermInversion[len]; // allocating for maximum number of inversions

		this->length = len;
		this->inversions_cnt = 0;

		for (uint64_t i = 0; i < len; i++)
			permutation[i] = i;

#if CERTFHE_MSVC_COMPILER_MACRO // std::random_devide guaranteed by MSVC to be criptographically secure

		std::random_device csprng;

		for (uint64_t pos = 0; pos < length - 2; pos++) {

			uint64_t newpos = (uint64_t)(pos + csprng() % (length - pos));
			std::swap(permutation[pos], permutation[newpos]);

			if (newpos != pos) {
				
				inversions[inversions_cnt].fst_u64_ch = pos / 64;
				inversions[inversions_cnt].fst_u64_r = 63 - (pos % 64);

				inversions[inversions_cnt].snd_u64_ch = newpos / 64;
				inversions[inversions_cnt].snd_u64_r = 63 - (newpos % 64);

				inversions_cnt += 1;
			}
		}
			
#else // for now, the default (insecure) rand

		for (uint64_t pos = 0; pos < length - 2; pos++) {

			uint64_t newpos = (uint64_t)(pos + rand() % (length - pos));
			std::swap(permutation[pos], permutation[newpos]);

			if (newpos != pos) {

				inversions[inversions_cnt].fst_u64_ch = pos / 64;
				inversions[inversions_cnt].fst_u64_r = 63 - (pos % 64);

				inversions[inversions_cnt].snd_u64_ch = newpos / 64;
				inversions[inversions_cnt].snd_u64_r = 63 - (newpos % 64);

				inversions_cnt += 1;
			}
		}

#endif

#if CERTFHE_USE_CUDA
		this->vram_inversions = (PermInversion *)CUDA_interface::RAM_TO_VRAM_copy((void *)this->inversions, this->inversions_cnt * sizeof(PermInversion), 0);
#endif

	}

	Permutation::Permutation(const uint64_t * perm, const uint64_t len, const PermInversion * invs, const uint64_t inv_cnt) {

		this->permutation = new uint64_t[len];
		this->inversions = new PermInversion[inv_cnt];

		this->length = len;
		this->inversions_cnt = inv_cnt;

		for (uint64_t i = 0; i < len; i++)
			this->permutation[i] = perm[i];

		for (uint64_t i = 0; i < inv_cnt; i++)
			this->inversions[i] = invs[i];

#if CERTFHE_USE_CUDA
		this->vram_inversions = (PermInversion *)CUDA_interface::RAM_TO_VRAM_copy((void *)this->inversions, this->inversions_cnt * sizeof(PermInversion), 0);
#endif

	}

	Permutation::Permutation(const Permutation & perm) {

		this->length = perm.getLength();
		this->inversions_cnt = perm.getInversionsCnt();

		this->permutation = new uint64_t[this->length];
		this->inversions = new PermInversion[this->inversions_cnt];

		uint64_t * _perm = perm.getPermutation();
		PermInversion * _invs = perm.getInversions();

		for(uint64_t i = 0; i < this->length; i++)
			this->permutation[i] = _perm[i];
		
		for (uint64_t i = 0; i < this->inversions_cnt; i++)
			this->inversions[i] = _invs[i];

#if CERTFHE_USE_CUDA
		this->vram_inversions = (PermInversion *)CUDA_interface::RAM_TO_VRAM_copy((void *)this->inversions, this->inversions_cnt * sizeof(PermInversion), 0);
#endif

	}

	Permutation::~Permutation(){

		if (this->permutation != nullptr) {

			delete[] this->permutation;
			this->permutation = nullptr;
		}

		if (this->inversions != nullptr) {

			delete[] this->inversions;
			this->inversions = nullptr;
		}

#if CERTFHE_USE_CUDA

		CUDA_interface::VRAM_delete(this->vram_inversions);
		this->vram_inversions = nullptr;
#endif

		this->length = 0;
		this->inversions_cnt = 0;
	}

 #pragma endregion
 
}