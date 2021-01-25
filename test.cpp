#include <random>
#include <stdio.h>
#include <iostream>
#include <time.h>

#include <chrono>
#include <math.h>
#include <malloc.h>


#include "certFHE.h"

////// CERTSIGN SCHEME (non-error) - parameters setup ////////
#define N_csgn 10
#define D_csgn 2
//////////////////////////////////////////////////////////////

#define BIT(X) X & 0x01

using namespace std;

extern bool exists(uint64_t*v,uint64_t len, uint64_t value);
extern void print(uint64_t*v, uint64_t size);

void test()
{
	cout<<endl;cout<<endl;

	uint64_t n = N_csgn;
	uint64_t d = D_csgn;
	uint64_t* s = NULL;

	initializeLibrary();
	

    certFHEContext ctx;
    ctx.N = n;
    ctx.D = d;
	setup(ctx, s);
	uint64_t* ss = new uint64_t[ctx.N];
	for (int i = 0; i < ctx.N; i++)
		ss[i] = 0;
	for (int i = 0; i < ctx.D; i++)
		ss[s[i]] = 1;


	printf("Secret key: ");
	for (int i = 0; i < ctx.N; i++)
		printf("%d ", ss[i]);
	printf("\n\n");

	certFHECtxt ctxt00,ctxt11;
	certFHECtxt *ctxt01;

	char b0 = 0x00;
	char b1 = 0x01;

	printf("encrypting %d... \n Ciphertext: ",b0);
	encrypt(ctxt00,b0,ctx,s);
	print(ctxt00);
	uint64_t decctxt0 = decrypt(ctxt00,ctx,s);
	cout<<"\nDecrypting... "<<decctxt0<<endl;
	cout<<endl;	cout<<endl;
	
//	printf("Size of uint64_t : %d\n", sizeof(uint64_t));
	printf("Permutation : ");
	uint64_t * perm = generatePermutation(ctx);
	for (int i = 0; i < ctx.N; i++)
		printf("%d\t", perm[i]);
	
	printf("\nInverse of permutation : ");
	uint64_t * perm2 = inverseOfPermutation(ctx,perm);
	for (int i = 0; i < ctx.N; i++)
		printf("%d\t", perm2[i]);


	certFHECtxt a = applyPermutation(ctx, perm, ctxt00);
	printf("\nOld key: ");
	for (int i = 0; i < ctx.N; i++)
		printf("%d ", ss[i]);
	printf("\n\n");

	

	uint64_t* newkey = applyPermutation(ctx, perm, ss);
	printf("New key: ");
	for (int i = 0; i < ctx.N; i++)
		printf("%d ", newkey[i]);
	printf("\n\n");
	printf("\n Permuted ciphertext: "); print(a);

	certFHECtxt b = applyPermutation(ctx, perm2, a);
	printf("\n Permuted ciphertext with inverse of permutation: "); print(b);


	uint64_t decctxt02 = decrypt(a, ctx, newkey);
	cout << "\nDecrypting again with permuted secret key... " << decctxt02 << endl;
	cout << endl;	cout << endl;



	printf("encrypting %d... \n Ciphertext: ",b1);
	encrypt(ctxt11,b1,ctx,s);
	print(ctxt11);
	uint64_t decctxt1 = decrypt(ctxt11,ctx,s);
	cout<<"\nDecrypting... "<<decctxt1<<endl;

	cout<<endl;
	certFHECtxt *rec;// = ctxt01;
	ctxt01 = (certFHECtxt*) add(ctxt00,ctxt11);
	rec=ctxt01;
	ctxt01 = (certFHECtxt*) add(*ctxt01,ctxt00);
	delete [] rec->bitlen;
	delete [] rec->v;
	delete rec;
	rec=ctxt01;
	ctxt01 = (certFHECtxt*) add(*ctxt01,ctxt11);
	delete [] rec->bitlen;
	delete [] rec->v;
	delete  rec;
	uint64_t decCtxtCircuit = decrypt(*ctxt01,ctx,s);
	printf("enc ( %d ) + enc ( %d ) + enc ( %d ) + enc ( %d ) ) = enc ( %d )",b0,b1,b0,b1,decCtxtCircuit);
	cout<<endl;cout<<endl;

	delete [] ss;
	delete [] ctxt00.bitlen;
	delete [] ctxt00.v;
	delete [] ctxt11.bitlen;
	delete [] ctxt11.v;
	delete [] ctxt01->bitlen;
	delete [] ctxt01->v;
	delete [] ctxt01;
	delete[] s;
	delete[] a.bitlen;
	delete[] a.v;
	delete [] newkey;
	delete[] perm;
	delete[] perm2;
	delete[] b.v;
	delete[] b.bitlen;

	return;

}

int main()
{
    test();
    return 0;
}