#include <random>
#include <stdio.h>
#include <iostream>
#include <time.h>

#include <chrono>
#include <math.h>
#include <malloc.h>
#include <bitset>

#ifdef _WIN32
#define u_int64_t uint64_t
#endif	

#include "certFHE.h"

#define BIT(X) X & 0x01

using namespace std;

uint64_t* encrypt(char bit, uint64_t n, uint64_t d, uint64_t*s); 
uint64_t decrypt(uint64_t* v,uint64_t len, uint64_t n, uint64_t d, uint64_t* s,uint64_t* bitlen);  
uint64_t decrypt_new(uint64_t* v,uint64_t len,uint64_t defLen, uint64_t n, uint64_t d, uint64_t* s,uint64_t* bitlen); 
uint64_t* add(uint64_t* c1,uint64_t* c2,uint64_t len1,uint64_t len2, uint64_t &newlen); 
uint64_t* multiply(uint64_t* c1, uint64_t* c2, uint64_t len); 
uint64_t* multiply_new(const certFHEContext& ctx,uint64_t *c1,uint64_t*c2,uint64_t len1,uint64_t len2, uint64_t& newlen,uint64_t* bitlenin1,uint64_t* bitlenin2,uint64_t*& bitlenout); 

bool exists(uint64_t*v,uint64_t len, uint64_t value)
{
	for (int i = 0; i < len; i++)
		if (v[i] == value)
			return true;

	return false;
}

void print(uint64_t*v, uint64_t size)
{
	for (int i = 0; i < size; i++)
		printf("%x ", (int)v[i]);
	cout << endl;
	cout << endl;

}

void rotate (std::bitset<64> &b,unsigned m)
{
 	b= b << m | b >> (64-m);
}

/////////////////////////////////////////////////////// internal functions ///////////////////////////////////////////////////////////////////////

uint64_t* add(uint64_t* c1,uint64_t* c2,uint64_t len1,uint64_t len2, uint64_t &newlen)
{
	uint64_t* res = new uint64_t[len1+len2];
    newlen = len1+len2;
	for (int i = 0; i < len1; i++)
		{
            res[i] = c1[i];
        }

    for (int i = 0; i < len2; i++)
		{
            res[i+len1] = c2[i];
        }

	return res;
}

uint64_t* encrypt(char bit, uint64_t n, uint64_t d, uint64_t*s)
{
    //@TODO: generate only a random of size n-d instead of n-d randoms()
	uint64_t* res = new uint64_t[n];
	bit = BIT(bit);

	if (bit == 0x01)
	{
		for (int i = 0; i < n; i++)
			if (exists(s, d, i))
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

				if (exists(s,d,i))
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

uint64_t decrypt(uint64_t* v,uint64_t len, uint64_t n, uint64_t d, uint64_t* s,uint64_t* bitlen)
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

uint64_t decrypt_new(uint64_t* v,uint64_t len,uint64_t defLen, uint64_t n, uint64_t d, uint64_t* s,uint64_t* bitlen)
{
    if (len == defLen)
        return decrypt(v,len,n,d,s,bitlen);


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

uint64_t* multiply(uint64_t* c1, uint64_t* c2, uint64_t len)
{
	uint64_t* res = new uint64_t[len];
	for (int i = 0; i < len; i++)
		res[i] = c1[i] & c2[i];
	
	return res;
}

uint64_t* multiply_new(const certFHEContext& ctx,uint64_t *c1,uint64_t*c2,uint64_t len1,uint64_t len2, uint64_t& newlen,uint64_t* bitlenin1,uint64_t* bitlenin2,uint64_t*& bitlenout)
{
    newlen=len1;
    if (len1 == ctx._defaultLen)
   		 if (len1 == len2)
       		 {
				bitlenout = new  uint64_t [newlen];
				for(int i = 0 ; i<newlen;i++)
					bitlenout[i] = bitlenin1[i];
				return multiply(c1,c2,len1);
		  	 } 

    newlen= (len1/ctx._defaultLen *  len2/ctx._defaultLen ) * ctx._defaultLen;

	bitlenout = new  uint64_t [newlen];
	uint64_t* res = new uint64_t[newlen];
    uint64_t times1 = len1/ctx._defaultLen;
    uint64_t times2 = len2/ctx._defaultLen;

    for(int i =0;i<times1;i++)
    {
            for(int j=0;j<times2;j++)
            {
                for(int k=0;k<ctx._defaultLen;k++)
                  {  
                      res[k+ctx._defaultLen*i*times2+ctx._defaultLen*j] = c1[k+ctx._defaultLen*i]  & c2[k+ctx._defaultLen*j];
                  }

				
            }	

    }

	int index = 0;
	for(int i =0;i<times1;i++)
    {
		  for(int j=0;j<times2;j++)
		  {
			for(int k=0;k<ctx._defaultLen;k++)
			{
				bitlenout[index] = bitlenin1[k+i*ctx._defaultLen];
				index++;

			}
		  }
	}

	return res;
}   

/////////////////////////////////////////////////////// DLL_PUBLIC functions ///////////////////////////////////////////////////////////////////////

#ifdef _WIN32
void initializeLibrary()
#else
DLL_PUBLIC void initializeLibrary()
#endif
{
	//Introducing local time as seed for further pseudo random generator calls
	srand(time(NULL));
}

#ifdef _WIN32
uint64_t* inverseOfPermutation(certFHEContext ctx, uint64_t* permutation)
#else
DLL_PUBLIC uint64_t* inverseOfPermutation(certFHEContext ctx, uint64_t* permutation)
#endif
{
	uint64_t *p = new uint64_t[ctx.N];

	for (int i = 0; i < ctx.N; i++)
	{
		for (int j = 0; j < ctx.N; j++)
		{
			if (permutation[j] == i)
			{
				p[i] = j;
				break;
			}
		}
	}
	return p;
}


#ifdef _WIN32
uint64_t* combinePermutation(certFHEContext ctx, uint64_t* permutationA, uint64_t* permutationB)
#else
DLL_PUBLIC uint64_t* combinePermutation(certFHEContext ctx, uint64_t* permutationA, uint64_t* permutationB)
#endif
{
	uint64_t *p = new uint64_t[ctx.N];
	for (int i = 0; i < ctx.N; i++)
	{
		p[i] = permutationB[permutationA[i]];
	}

	return p;
}


#ifdef _WIN32
uint64_t* applyPermutation(certFHEContext ctx, uint64_t* permutation, uint64_t* secretKey)
#else
DLL_PUBLIC uint64_t* applyPermutation(certFHEContext ctx, uint64_t* permutation, uint64_t* secretKey)
#endif
{

	uint64_t *temp = new uint64_t[ctx.N];

	for (int i = 0; i < ctx.N; i++)
		temp[i] = secretKey[permutation[i]];

	return temp;
}

#ifdef _WIN32
certFHECtxt applyPermutation(certFHEContext ctx, uint64_t* permutation, certFHECtxt ciphertext)
#else
DLL_PUBLIC certFHECtxt applyPermutation(certFHEContext ctx, uint64_t* permutation, certFHECtxt ciphertext)
#endif
{
	certFHECtxt result;
	
	int size = 0;
	for (int i = 0; i < ciphertext.len; i++)
		size += ciphertext.bitlen[i];
	
	uint64_t* temp = new uint64_t[size];
	uint64_t* temp2 = new uint64_t[size];
	uint64_t tval;
	int pos = 0;
	for (int i = 0; i < ciphertext.len; i++)
	{
		for (int j = 0; j < ciphertext.bitlen[i]; j++)
		{
			tval = (ciphertext.v[i] >> (sizeof(uint64_t)*8-1 - j)) & 0x01;
			temp[pos++] = tval;
		}
	}

	for (int i = 0; i < size; i++)
		temp2[i] = temp[permutation[i%ctx.N]];

	uint64_t div = ctx.N / (sizeof(uint64_t) * 8);
	uint64_t rem = ctx.N % (sizeof(uint64_t) * 8);
	result.len = div;
	if (rem != 0)
		result.len++;

	result.bitlen = new uint64_t[result.len];
	for (int i = 0; i < div; i++)
		result.bitlen[i] = sizeof(uint64_t) * 8;
	result.bitlen[div] = rem;

	result.v = new uint64_t[result.len];
	int uint64index = 0;
	for (int step = 0; step < div; step++)
	{
		result.v[uint64index] = 0x00;
		for (int s = 0; s < 64; s++)
		{
			uint64_t inter = ((temp2[step * 64 + s]) & 0x01) << sizeof(u_int64_t) * 8 - 1 - s;
			result.v[uint64index] = (result.v[uint64index]) | (inter);
		}
		uint64index++;
	}

	if (rem != 0)
	{
		result.v[uint64index] = 0x00;
		for (int r = 0; r < rem; r++)
		{
			uint64_t inter = ((temp2[div * 64 + r]) & 0x01) << sizeof(u_int64_t) * 8 - 1 - r;
			result.v[uint64index] = (result.v[uint64index]) | (inter);
		}

	}

	if (temp)
		delete[] temp;

	if (temp2)
		delete[] temp2;

	return result;
}

#ifdef _WIN32
uint64_t* generatePermutation(certFHEContext ctx)
#else
DLL_PUBLIC uint64_t* generatePermutation(certFHEContext ctx)
#endif
{
	uint64_t * permutation = new uint64_t[ctx.N];
	time_t time;
	std::random_device r;
	std::seed_seq seed{ r(), r() };

	uint64_t sRandom = 0;
	for (int i = 0; i < ctx.N; i++)
		permutation[i] = -1;

	for (int i = 0; i < ctx.N; i++)
	{
		sRandom = rand() % ctx.N;
		while (exists(permutation, ctx.N, sRandom))
		{
			sRandom = rand() % ctx.N;
		}
		permutation[i] = sRandom;
	}

	return permutation;
}

#ifdef _WIN32
void deletePointer(void* pointer, bool isArray)
#else
DLL_PUBLIC void deletePointer(void* pointer, bool isArray)
#endif
{
	if (pointer != NULL)
		if (isArray)
			delete[] pointer;
		else
			delete pointer;
}

#ifdef _WIN32
void print(certFHECtxt ctxt)
#else
DLL_PUBLIC void print(certFHECtxt ctxt)
#endif
{
	int div = ctxt.len;
	for (int step =0;step<ctxt.len;step++)
	{
		std::bitset<64> bs (ctxt.v[step]);	
			for (int s = 0;s< ctxt.bitlen[step];s++)
			{
				cout<<bs.test(63-s);
			}
	}	
}

#ifdef _WIN32
certFHECtxt * add(certFHECtxt c1, certFHECtxt c2)
#else
DLL_PUBLIC certFHECtxt * add(certFHECtxt c1,certFHECtxt c2)
#endif
{
    certFHECtxt* result= new certFHECtxt();
	
	result->bitlen = new uint64_t [c1.len + c2.len];

    result->v = add(c1.v,c2.v,c1.len,c2.len,result->len);

	for (int i = 0;i<c1.len;i++)
	{
		result->bitlen[i] = c1.bitlen[i];

	}
	for (int i = 0;i<c2.len;i++)
	{
		result->bitlen[c1.len + i] = c2.bitlen[i];
	}

    return result;
}

#ifdef _WIN32
certFHECtxt* multiply(const certFHEContext& ctx, certFHECtxt c1, certFHECtxt c2)
#else
DLL_PUBLIC certFHECtxt* multiply(const certFHEContext& ctx,certFHECtxt c1,certFHECtxt c2)
#endif
{
    certFHECtxt* res = new certFHECtxt();
	
    res->v = multiply_new(ctx,c1.v,c2.v,c1.len,c2.len,res->len,c1.bitlen,c2.bitlen,res->bitlen);

	for (int i = 0;i<c1.len;i++)
	{
		res->bitlen[i] = c1.bitlen[i];

	}
	    
    return res;
}
#ifdef _WIN32
void setup(certFHEContext& ctx, uint64_t*& s)
#else
DLL_PUBLIC void setup(certFHEContext& ctx, uint64_t*& s)
#endif
{
	time_t t = time(NULL);
	srand(t);

	uint64_t n = ctx.N;
	uint64_t d = ctx.D;
	s = new uint64_t[d];

	uint64_t div = n/ (sizeof(uint64_t)*8);
	uint64_t rem = n % (sizeof(uint64_t)*8);
    ctx._defaultLen = div;
	if ( rem != 0)
		ctx._defaultLen++;	

	int count = 0;
	bool go = true;
	while (go)
	{

		uint64_t temp = rand() % n;
		if (exists(s,d, temp))
			continue;

		s[count] = temp;
		count++;
		if (count == d)
			go = false;
	}

}

#ifdef _WIN32
void encrypt(certFHECtxt &c, char bit, certFHEContext ctx, uint64_t *s)
#else
DLL_PUBLIC void encrypt(certFHECtxt &c,char bit,certFHEContext ctx, uint64_t *s)
#endif
{
	uint64_t n = ctx.N;
	uint64_t d = ctx.D;

	uint64_t div = n/ (sizeof(uint64_t)*8);
	uint64_t rem = n % (sizeof(uint64_t)*8);
    c.len = div;
	if ( rem != 0)
		c.len++;	

    uint64_t * vect = encrypt(bit,n,d,s);
	
	c.bitlen  = new uint64_t [ c.len];
	for (int i = 0;i<div;i++)
		c.bitlen[i] = sizeof(uint64_t)*8;
	c.bitlen[div] = rem;

	c.v = new uint64_t [ c.len];
	int uint64index = 0;
	for (int step =0;step<div;step++)
	{
			c.v[uint64index]= 0x00;
			for (int s = 0;s< 64;s++)
			{
				uint64_t inter = ((vect[step*64+s]  ) & 0x01)<<sizeof(u_int64_t)*8 - 1 -s;
				c.v[uint64index] = (c.v[uint64index] ) | ( inter );
			}
			uint64index++;
	}
	
	if (rem != 0)
	{		
			c.v[uint64index]= 0x00;
			for (int r = 0 ;r<rem;r++)
			{
				uint64_t inter = ((vect[ div*64 +r ]  ) & 0x01)<<sizeof(u_int64_t)*8 - 1-r;
				c.v[uint64index] = (c.v[uint64index] ) | ( inter );

			}

	}
	
	delete [] vect;
}	

#ifdef _WIN32
uint64_t decrypt(certFHECtxt v, certFHEContext ctx, uint64_t* s)
#else
DLL_PUBLIC uint64_t decrypt(certFHECtxt v, certFHEContext ctx, uint64_t* s)
#endif
{
	uint64_t n = ctx.N;
	uint64_t d = ctx.D;

	uint64_t div = n/ (sizeof(uint64_t)*8);
	uint64_t rem = n % (sizeof(uint64_t)*8);
    uint64_t defLen = div;
	if ( rem != 0)
		defLen++;	

    return decrypt_new(v.v,v.len,defLen,n,d,s,v.bitlen);
}


