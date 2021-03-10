#include "SecretKey.h"

using namespace certFHE;
using namespace std;

#pragma region Operators

SecretKey& SecretKey::operator=(const SecretKey& secKey)
{
	if (this->s != nullptr)
	{
		delete [] this->s;
	}

	this->length = secKey.length;
	this->s = new uint64_t [secKey.length];
	for(uint64_t i =0 ;i<secKey.length;i++)
		this->s[i] = secKey.s[i];
	return *this;
}

ostream& certFHE::operator<<(ostream &out, const SecretKey &c)
  {
	  uint64_t* key = c.getKey();
	  for(long i =0;i<c.getLength();i++)
	  	out<<key[i]<<" ";
	  out<<endl;
	  return out;
  }

#pragma endregion

#pragma region Private functions

uint64_t* SecretKey::encrypt(unsigned char bit, uint64_t n, uint64_t d, uint64_t*s)
{
     //@TODO: generate only a random of size n-d instead of n-d randoms()
	uint64_t* res = new uint64_t[n];
	bit = BIT(bit);

	if (bit == 0x01)
	{
		for (int i = 0; i < n; i++)
			if (Helper::exists(s, d, i))
				res[i] = 0x01;
			else
				res[i] = rand() % 2;
	}
	else
	{
		uint64_t sRandom = rand() % d;
		uint64_t v = 0x00;
		bool vNok = true;

		for (int i = 0; i < n; i++)
			if (i != s[sRandom])
			{
				res[i] = rand() % 2;

				if (Helper::exists(s,d,i))
				{
					if (vNok)
					{
						v = res[i];
						vNok = false;
					}
					v = v & res[i];

				}

			}

		if (v == 0x01)
		res[s[sRandom]] = 0;
		else
		res[s[sRandom]] = rand() %2;

	}
	return res;
}

uint64_t SecretKey::defaultN_decrypt(uint64_t* v,uint64_t len, uint64_t n, uint64_t d, uint64_t* s,uint64_t* bitlen)
{
  int totalLen = 0;
	for (int i = 0;  i < len; i++)
		totalLen = totalLen + bitlen[i];
	uint8_t *values = new uint8_t [totalLen];
	int index = 0;
	for (int i = 0;  i < len; i++)
		for (int k = 0;  k < bitlen[i]; k++)
		{
			int shifts = sizeof(uint64_t)*8-1 -k ;
			values[index] =  ( v[i] >> shifts) & 0x01;
			index++;
		}

    uint64_t dec = values[s[0]];
	for (int i = 1;  i <d; i++)
		dec = dec && values[s[i]];
	delete [] values;
	return dec;   
}

uint64_t SecretKey::decrypt(uint64_t* v,uint64_t len,uint64_t defLen, uint64_t n, uint64_t d, uint64_t* s,uint64_t* bitlen)
{
      if (len == defLen)
        return defaultN_decrypt(v,len,n,d,s,bitlen);


	int totalLen = 0;
	for (int i = 0;  i < len; i++)
		totalLen = totalLen + bitlen[i];
	uint8_t *values = new uint8_t [totalLen];

	int index = 0;
	for (int i = 0;  i < len; i++)
		for (int k = 0;  k < bitlen[i]; k++)
		{
			int shifts = sizeof(uint64_t)*8-1 -k ;
			values[index] =  ( v[i] >> shifts) & 0x01;
		
			index++;
		
		}

    uint64_t times = len/defLen;

    uint64_t dec = values[s[0]];
	uint64_t _dec = 0;

    for (int k=0;k<times;k++)
    {
        dec =  values[n*k+s[0]];
        for (int i = 1;  i < d; i++)
	    {
            dec = dec & values[n*k+s[i]];
        }
		
        _dec = (dec+_dec)%2;
    }

    dec =_dec;

	delete [] values;

	return dec;
}

#pragma endregion

#pragma region Public methods

Ciphertext SecretKey::encrypt(Plaintext &plaintext)
{
    uint64_t len;

	uint64_t n = this->certFHEContext->getN();
	uint64_t d = this->certFHEContext->getD();

	uint64_t div = n / (sizeof(uint64_t)*8);
	uint64_t rem = n % (sizeof(uint64_t)*8);
    len = div;
	if ( rem != 0)
		len++;	

    unsigned char value = BIT(plaintext.getValue());
    uint64_t * vect =  encrypt(value,n,d,s);
	uint64_t * _bitlen = new uint64_t [len];
    uint64_t * _encValues = new uint64_t [len];

	for (int i = 0;i<div;i++)
		_bitlen[i] = sizeof(uint64_t)*8;
	_bitlen[div] = rem;

	int uint64index = 0;
	for (int step =0;step<div;step++)
	{
		    _encValues[uint64index]= 0x00;
			for (int s = 0;s< 64;s++)
			{
				uint64_t inter = ((vect[step*64+s]  ) & 0x01)<<sizeof(uint64_t)*8 - 1 -s;
				_encValues[uint64index] = (_encValues[uint64index] ) | ( inter );
			}
			uint64index++;
	}
	
	if (rem != 0)
	{		
			_encValues[uint64index]= 0x00;
			for (int r = 0 ;r<rem;r++)
			{
				uint64_t inter = ((vect[ div*64 +r ]  ) & 0x01)<<sizeof(uint64_t)*8 - 1-r;
				_encValues[uint64index] = (_encValues[uint64index] ) | ( inter );

			}

	}
	
    Ciphertext c(_encValues,_bitlen,len,*this->certFHEContext);
    delete [] vect;
    delete [] _bitlen;    
    delete [] _encValues;

    return c;

}

Plaintext SecretKey::decrypt(Ciphertext& ciphertext)
{   
    uint64_t n = this->certFHEContext->getN();
	uint64_t d = this->certFHEContext->getD();

	uint64_t div = n/ (sizeof(uint64_t)*8);
	uint64_t rem = n % (sizeof(uint64_t)*8);
    uint64_t defLen = div;
	if ( rem != 0)
		defLen++;	

    uint64_t* _v = ciphertext.getValues();
    uint64_t* _bitlen = ciphertext.getBitlen();

    uint64_t decV =  decrypt(_v,ciphertext.getLen(),defLen,n,d,s,_bitlen);
    return Plaintext(decV);
}

void SecretKey::applyPermutation_inplace(const Permutation& permutation)
{
	uint64_t permLen = permutation.getLength();
	uint64_t *perm = permutation.getPermutation();

	uint64_t *current_key = new uint64_t[this->certFHEContext->getN()];
	
	for(uint64_t i = 0;i<this->certFHEContext->getN();i++)
		current_key[i] = 0;

	for(uint64_t i = 0;i<length;i++)
		current_key[s[i]] =1;

	uint64_t *temp = new uint64_t[this->certFHEContext->getN()];

	for (int i = 0; i < this->certFHEContext->getN(); i++)
		temp[i] = current_key[perm[i]];

	uint64_t *newKey = new uint64_t[length];
	uint64_t index = 0; 
	for(uint64_t i =0;i<this->certFHEContext->getN();i++)
	{
		if (temp[i] == 1)
			newKey[index++] = i;
	}

	delete [] this->s;
	this->s = newKey;


	delete [] current_key;
	delete [] temp;

}

SecretKey SecretKey::applyPermutation(const Permutation& permutation)
{

	SecretKey secKey(*this);
	secKey.applyPermutation_inplace(permutation);
	return secKey;
}

long SecretKey::size()
{
	long size = 0;
	size += sizeof(this->certFHEContext);
	size += sizeof(this->length);
	size += sizeof(uint64_t)*this->length;
	return size;
}

#pragma endregion

#pragma region Getters and setters

uint64_t  SecretKey::getLength() const
{
	return this->length;
}

uint64_t* SecretKey::getKey() const
{
	return this->s;
}

void SecretKey::setKey(uint64_t*s, uint64_t len)
{
	if (this->s != nullptr)
		delete [] this->s;
	
	this->s = new uint64_t[len];
	for(uint64_t i=0;i<len;i++)
		this->s[i] = s[i];

	this->length = len;
}

#pragma endregion

#pragma region Constructors and destructor

SecretKey::SecretKey(const Context &context)
{
    // seed once again the PRNG with local time
    time_t t = time(NULL);
	srand(t);

    this->certFHEContext = new certFHE::Context(context);

    uint64_t _d = certFHEContext->getD();
    uint64_t _n = certFHEContext->getN();

    this->s =  new uint64_t[_d];
    this->length = _d;

	int count = 0;
	bool go = true;
	while (go)
	{

		uint64_t temp = rand() % _n;
		if (Helper::exists(s,_d, temp))
			continue;

		s[count] = temp;
		count++;
		if (count == _d)
			go = false;
	}
    
}

SecretKey::SecretKey(const SecretKey& secKey) 
{
    this->certFHEContext = new certFHE::Context(*secKey.certFHEContext);

     if ( secKey.length < 0)
        return;
    
    this->s = new uint64_t [ secKey.length];
    this->length =  secKey.length;
    for(long i = 0;i< secKey.length;i++)
        this->s[i ] =secKey.s[i];

    
}

SecretKey::~SecretKey()
{
	for (uint64_t i = 0; i < length; i++)
		s[i] = 0;

    if (this->s != nullptr)
    {
        delete [] this->s;
        this->s = nullptr;
    }
    
    this->length =-1;

    if (this->certFHEContext != nullptr)
    {
        delete this->certFHEContext;
        this->certFHEContext = nullptr;
    }
}

#pragma endregion