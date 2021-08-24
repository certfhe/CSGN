#include "certFHE.h"
#include "Threadpool.h"

void basic_init_enc_dec_examples() {

	// initialization

	certFHE::Library::initializeLibrary();
	certFHE::Context context(1247, 16);

	// creating a secret key
	certFHE::SecretKey sk(context);

	// Encryption using Plaintext objects

	certFHE::Plaintext p1(1);
	certFHE::Plaintext p0(0);

	certFHE::Ciphertext c1 = sk.encrypt(p1);
	certFHE::Ciphertext c0 = sk.encrypt(p0);

	certFHE::Ciphertext another_c1(p1, sk);
	certFHE::Ciphertext another_co(p0, sk);

	// Encryption using memory addresses
	// Note that only the first bit from the specified address will be encrypted

	int a = 200;
	int b = 8491;

	certFHE::Ciphertext c_1(&b, sk);
	certFHE::Ciphertext c_0(&a, sk);

	// Decryption using the secret key
	// reminder that this is a symmetric encryption scheme
	// where the secret key is the same for both encryption and decryption

	// Decryption that returns a new Plaintext object

	certFHE::Plaintext d0 = sk.decrypt(c0);
	certFHE::Plaintext d1 = sk.decrypt(c1);

	certFHE::Plaintext another_d0 = c0.decrypt(sk);
	certFHE::Plaintext another_d1 = c1.decrypt(sk);

	// Decryption that directly returns an uint64_t with value 0 or 1

	uint64_t d_0 = c0.decrypt_raw(sk);
	uint64_t d_1 = c1.decrypt_raw(sk);
}

void basic_add_examples() {

	// initialization and secret key generation

	certFHE::Library::initializeLibrary();
	certFHE::Context context(1247, 16);

	certFHE::SecretKey sk(context);

	// encryption

	certFHE::Plaintext p0(0);
	certFHE::Plaintext p1(1);

	certFHE::Ciphertext c0(p0, sk);
	certFHE::Ciphertext c1(p1, sk);

	// addition

	certFHE::Ciphertext c_add_result = c0 + c1;
	c1 += c0;
	c0 += c1;

	//decryption

	certFHE::Plaintext d1 = c_add_result.decrypt(sk);
	certFHE::Plaintext also_d1 = c0.decrypt(sk);
}

void basic_mul_examples() {

	// initialization and secret key generation

	certFHE::Library::initializeLibrary();
	certFHE::Context context(1247, 16);

	certFHE::SecretKey sk(context);

	// encryption

	certFHE::Plaintext p0(0);
	certFHE::Plaintext p1(1);

	certFHE::Ciphertext c0(p0, sk);
	certFHE::Ciphertext c1(p1, sk);

	// multiplication

	certFHE::Ciphertext c_mul_result = c0 * c1;
	c1 *= c1;

	//decryption

	certFHE::Plaintext d0 = c_mul_result.decrypt(sk);
	certFHE::Plaintext d1 = c1.decrypt(sk);
}

void basic_permutation_examples() {

	// initialization and permutation generation

	certFHE::Library::initializeLibrary();
	certFHE::Context context(1247, 16);

	certFHE::Permutation permutation(context);

	// secret key generation and permuting it

	certFHE::SecretKey sk1(context);

	certFHE::SecretKey sk2 = sk1.applyPermutation(permutation);

	// obtain the initial key with the inverse

	certFHE::Permutation inversePermutation = permutation.getInverse();

	certFHE::SecretKey sk1_recovered = sk2.applyPermutation(inversePermutation);

	// combining permutations 

	certFHE::Permutation perm1(context);
	certFHE::Permutation perm2(context);

	certFHE::Permutation perm1_perm2 = perm1 + perm2;

	// combining permuted keys
	// s1s2_sequentially equals s1s2_directly

	certFHE::SecretKey s1(context);

	certFHE::SecretKey s2 = s1.applyPermutation(perm1);
	certFHE::SecretKey s1s2_sequentially = s2.applyPermutation(perm2);

	certFHE::SecretKey s1s2_directly = s1.applyPermutation(perm1_perm2);
}

void basic_permutation_second_examples() {

	// initialization, secret key initialization, permutation generation

	certFHE::Library::initializeLibrary();
	certFHE::Context context(1247, 16);

	certFHE::SecretKey sk(context);

	// secret key permutation

	certFHE::Permutation permutation(context);
	certFHE::SecretKey permuted_sk = sk.applyPermutation(permutation);

	// ciphertext generation and permutation

	certFHE::Plaintext p1(1);
	
	certFHE::Ciphertext c(p1, sk);
	certFHE::Ciphertext permuted_c = c.applyPermutation(permutation);

	// permuted ciphertext decryption

	certFHE::Plaintext d1 = permuted_c.decrypt(permuted_sk);
}
