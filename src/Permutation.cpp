#include "Permutation.h"

using namespace certFHE;
using namespace std;

#pragma region Public methods

Permutation Permutation::getInverse()
{
    uint64_t *p = new uint64_t[length];

	for (int i = 0; i <length; i++)
	{
		for (int j = 0; j <length; j++)
		{
			if (permutation[j] == i)
			{
				p[i] = j; 
				break;
			}
		}
	}
    
	Permutation invP (p,length);
    delete[] p;
    return invP;
}

#pragma endregion

#pragma region Operators

ostream& certFHE::operator<<(ostream &out, const Permutation &p)
{
    uint64_t* _p = p.getPermutation();
    uint64_t l = p.getLength();
    out <<"(";
    for(uint64_t i = 0; i<l;i++)
        out<<i<<" ";
    out<<")"<<endl;
     out <<"(";
    for(uint64_t i = 0; i<l;i++)
        out<<_p[i]<<" ";
    out<<")"<<endl;
    return out;
}

Permutation& Permutation::operator=(const Permutation& perm)
{
    this->length = perm.getLength();


    if (this->permutation != nullptr)
        delete [] this->permutation;

    this->permutation = new uint64_t [this->length];
    for(uint64_t i=0;i<this->length;i++)
        this->permutation[i] = perm.permutation[i];

    return *this;
}

Permutation Permutation::operator+(const Permutation& permB) const
{
    if ( length != permB.getLength())
        return Permutation();         

    uint64_t *p = new uint64_t[length];
    uint64_t *pB = permB.getPermutation();
	for (int i = 0; i < length; i++)
	{
		p[i] = this->permutation[pB[i]];
	}

    Permutation result(p,length);
    delete [] p;
	return result;
}

Permutation& Permutation::operator+=(const Permutation& permB)
{
    if (length != permB.getLength())
        return *this;         

    uint64_t *p = new uint64_t[length];
    uint64_t *pB = permB.getPermutation();
	for (int i = 0; i < length; i++)
	{
		p[i] = this->permutation[pB[i]];
	}

    delete [] this->permutation;
    this->permutation = p;

   return *this;
}

#pragma endregion

#pragma region Getters and setters

uint64_t Permutation::getLength() const
{
    return this->length;
}

uint64_t* Permutation::getPermutation() const
{
    return this->permutation;
}

void Permutation::setLength(uint64_t len)
{
    this->length = len;
}

void Permutation::setPermutation(uint64_t* perm,uint64_t len)
{
    if (this->permutation != nullptr)
        delete [] this->permutation;
    
    this->permutation = new uint64_t [len];
    this->length = len;
    for(uint64_t i = 0; i<len;i++)
        this->permutation[i] = perm[i];
}

#pragma endregion

#pragma region Constructors and destructor

Permutation::Permutation()
{
    this->length = 0;
    this->permutation = nullptr;

}

Permutation::Permutation(const uint64_t size) : Permutation()
{
     this->permutation = new uint64_t[size];
     this->length = size;

	uint64_t sRandom = 0;
	for (int i = 0; i < size; i++)
		permutation[i] = -1;

	for (int i = 0; i < size; i++)
	{
		sRandom = rand() % size;
		while (Helper::exists(permutation, size, sRandom))
		{
			sRandom = rand() % size;
		}
		permutation[i] = sRandom;
	}
}

Permutation::Permutation(const Context& context) : Permutation(context.getN())
{

}        


Permutation::Permutation(const uint64_t *perm, const uint64_t len) : Permutation()
{
    this->length = len ;
    this->permutation  = new uint64_t [len];
    for(uint64_t i=0;i<len;i++)
        this->permutation[i] = perm[i];
}

Permutation::Permutation(const Permutation& perm)
{

    this->permutation = new uint64_t [perm.getLength()];
    this->length = perm.getLength();

    uint64_t * _perm = perm.getPermutation();

    for(uint64_t i =0 ;i <this->length ;i++)
        this->permutation[i] = _perm[i];
}


 Permutation::~Permutation()
 {
     if (this->permutation != nullptr)
        {
            delete [] this->permutation;
            this->permutation = nullptr;
        }
    this->length = 0;
 }

 #pragma endregion