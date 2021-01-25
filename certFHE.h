#if defined _WIN32 || defined __CYGWIN__
  #ifdef BUILDING_DLL
    #ifdef __GNUC__
      #define DLL_PUBLIC __attribute__ ((dllexport))
    #else
      #define DLL_PUBLIC __declspec(dllexport) // Note: actually gcc seems to also supports this syntax.
    #endif
  #else
    #ifdef __GNUC__
      #define DLL_PUBLIC __attribute__ ((dllimport))
    #else
      #define DLL_PUBLIC __declspec(dllimport) // Note: actually gcc seems to also supports this syntax.
    #endif
  #endif
  #define DLL_LOCAL
#else
  #if __GNUC__ >= 4
    #define DLL_PUBLIC __attribute__ ((visibility ("default")))
    #define DLL_LOCAL  __attribute__ ((visibility ("hidden")))
  #else
    #define DLL_PUBLIC
    #define DLL_LOCAL
  #endif
#endif

#ifndef uint64_t 
#define uint64_t unsigned long long
#endif

 struct certFHECtxt {
    uint64_t * v;
    uint64_t len;
    uint64_t * bitlen;
};

struct certFHEContext{
    uint64_t N;
    uint64_t D;
    uint64_t U;

    uint64_t _defaultLen;   //Default length in UL's (chunks of 64 bit)
};

DLL_PUBLIC void initializeLibrary();

DLL_PUBLIC void deletePointer(void* pointer, bool isArray);

DLL_PUBLIC void print(certFHECtxt ctxt);

DLL_PUBLIC void setup(certFHEContext& ctx, uint64_t*& s);

DLL_PUBLIC void encrypt(certFHECtxt &c,char bit,certFHEContext ctx, uint64_t *s);

DLL_PUBLIC uint64_t decrypt(certFHECtxt v, certFHEContext ctx, uint64_t* s);

DLL_PUBLIC certFHECtxt * add(certFHECtxt c1,certFHECtxt c2);

DLL_PUBLIC certFHECtxt* multiply(const certFHEContext& ctx,certFHECtxt c1,certFHECtxt c2);

DLL_PUBLIC uint64_t * generatePermutation(certFHEContext ctx);

DLL_PUBLIC certFHECtxt applyPermutation(certFHEContext ctx, uint64_t* permutation, certFHECtxt ciphertext);

DLL_PUBLIC uint64_t* applyPermutation(certFHEContext ctx, uint64_t* permutation, uint64_t* secretKey);

DLL_PUBLIC uint64_t* combinePermutation(certFHEContext ctx, uint64_t* permutationA, uint64_t* permutationB);

DLL_PUBLIC uint64_t* inverseOfPermutation(certFHEContext ctx, uint64_t* permutation);

