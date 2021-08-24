#include "CCC.h"

namespace certFHE {

#if CERTFHE_USE_CUDA

	CCC::CCC(Context * context, uint64_t * ctxt, uint64_t deflen_cnt, bool ctxt_on_gpu) : CNODE(context) {

		if (deflen_cnt > OPValues::max_ccc_deflen_size) {

			std::cout << "ERROR creating CCC node: deflen " << deflen_cnt
				<< " exceeds limit " << OPValues::max_ccc_deflen_size << "\n";

			throw std::invalid_argument("ERROR creating CCC node: deflen exceeds limit");
		}
		else {

			this->ctxt = ctxt;
			this->deflen_count = deflen_cnt;
			this->on_GPU = ctxt_on_gpu;
		}
	}

	CCC::CCC(const CCC & other) : CNODE(other) {

		if (other.ctxt != 0 && other.deflen_count > 0) {

			if (other.on_GPU && (other.deflen_count + GPUValues::gpu_current_vram_deflen_usage < GPUValues::gpu_max_vram_deflen_usage)) {

				uint64_t u64_length = this->deflen_count * this->context->getDefaultN();

				this->ctxt = (uint64_t *)CUDA_interface::VRAM_TO_VRAM_copy(other.ctxt, u64_length * sizeof(uint64_t), 0);
				this->on_GPU = true;
			}
			else if (other.on_GPU){

				uint64_t u64_length = this->deflen_count * this->context->getDefaultN();

				this->ctxt = (uint64_t *)CUDA_interface::VRAM_TO_RAM_copy(other.ctxt, u64_length * sizeof(uint64_t), 0);
				this->on_GPU = false;
			}
			else {

				uint64_t u64_length = this->deflen_count * this->context->getDefaultN();
				this->ctxt = new uint64_t[u64_length];

				if (u64_length < MTValues::cpy_m_threshold)
					for (uint64_t i = 0; i < u64_length; i++)
						this->ctxt[i] = other.ctxt[i];
				else
					Helper::u64_multithread_cpy(other.ctxt, this->ctxt, u64_length);

				this->on_GPU = false;
			}
		}
		else {

			this->ctxt = 0;
			this->on_GPU = false;
		}

	}

	CCC::CCC(const CCC && other) : CNODE(other) {

		this->deflen_count = other.deflen_count;
		this->ctxt = other.ctxt;
		this->on_GPU = other.on_GPU;
	}

	CCC::~CCC() {

		if (this->ctxt != 0) {

			if (this->on_GPU) {

				CUDA_interface::VRAM_delete(this->ctxt);
				GPUValues::gpu_current_vram_deflen_usage -= this->deflen_count;
			}
				
			else
				delete[] ctxt;
		}
		else
			std::cout << "CCC ctxt pointer should never be null (check the rest of the code)";
	}

#else

	CCC::CCC(Context * context, uint64_t * ctxt, uint64_t deflen_cnt) : CNODE(context) {

		if (deflen_cnt > OPValues::max_ccc_deflen_size) {

			std::cout << "ERROR creating CCC node: deflen " << deflen_cnt
				<< " exceeds limit " << OPValues::max_ccc_deflen_size << "\n";

			throw std::invalid_argument("ERROR creating CCC node: deflen exceeds limit");
		}
		else {

			this->deflen_count = deflen_cnt;
			this->ctxt = ctxt;
		}

	}

	CCC::CCC(const CCC & other) : CNODE(other) {

		if (other.ctxt != 0 && other.deflen_count > 0) {

			uint64_t u64_length = this->deflen_count * this->context->getDefaultN();
			this->ctxt = new uint64_t[u64_length];

			if (u64_length < MTValues::cpy_m_threshold)
				for (uint64_t i = 0; i < u64_length; i++)
					this->ctxt[i] = other.ctxt[i];
			else
				Helper::u64_multithread_cpy(other.ctxt, this->ctxt, u64_length);
		}
		else
			this->ctxt = 0;
	}

	CCC::CCC(const CCC && other) : CNODE(other) {

		this->deflen_count = other.deflen_count;
		this->ctxt = other.ctxt;
	}

	CCC::~CCC() {

		if (this->ctxt != 0)
			delete[] ctxt;
		else
			std::cout << "CCC ctxt pointer should never be null (check the rest of the code)";
	}

#endif

	void CCC::chunk_decrypt(Args * raw_args) {

		DecArgs * args = (DecArgs *)raw_args;

		uint64_t * to_decrypt = args->to_decrypt;
		uint64_t * sk_mask = args->sk_mask;
		uint64_t snd_deflen_pos = args->snd_deflen_pos;

		uint64_t default_len = args->default_len;

		uint64_t * decrypted = &(args->decrypted);

#ifdef __AVX512F__

		for (uint64_t i = args->fst_deflen_pos; i < snd_deflen_pos; i++) {

			uint64_t * current_chunk = to_decrypt + i * default_len;
			uint64_t current_decrypted = 0x01;

			uint64_t u = 0;

			for (; u + 8 <= default_len; u += 8) {

				__m512i avx_aux = _mm512_loadu_si512((const void *)(current_chunk + u));
				__m512i avx_mask = _mm512_loadu_si512((const void *)(sk_mask + u));

				avx_aux = _mm512_and_si512(avx_aux, avx_mask);
				avx_aux = _mm512_xor_si512(avx_aux, avx_mask);

				__mmask8 is_zero_mask = _mm512_test_epi64_mask(avx_aux, avx_aux);
				current_decrypted &= (is_zero_mask == 0);
			}

			for (u; u < default_len; u++)
				current_decrypted &= ((current_chunk[u] & sk_mask[u]) ^ sk_mask[u]) == (uint64_t)0;

			*decrypted ^= current_decrypted;
		}

#elif __AVX2__

		for (uint64_t i = args->fst_deflen_pos; i < snd_deflen_pos; i++) {

			uint64_t * current_chunk = to_decrypt + i * default_len;
			uint64_t current_decrypted = 0x01;

			uint64_t u = 0;

			for (; u + 4 <= default_len; u += 4) {

				__m256i avx_aux = _mm256_loadu_si256((const __m256i *)(current_chunk + u));
				__m256i avx_mask = _mm256_loadu_si256((const __m256i *)(sk_mask + u));

				avx_aux = _mm256_and_si256(avx_aux, avx_mask);
				avx_aux = _mm256_xor_si256(avx_aux, avx_mask);

				current_decrypted &= _mm256_testz_si256(avx_aux, avx_aux);
			}

			for (; u < default_len; u++)
				current_decrypted &= ((current_chunk[u] & sk_mask[u]) ^ sk_mask[u]) == (uint64_t)0;

			*decrypted ^= current_decrypted;
		}

#else

		for (uint64_t i = args->fst_deflen_pos; i < snd_deflen_pos; i++) {

			uint64_t * current_chunk = to_decrypt + i * default_len;
			uint64_t current_decrypted = 0x01;

			for (uint64_t u = 0; u < default_len; u++)
				current_decrypted &= ((current_chunk[u] & sk_mask[u]) ^ sk_mask[u]) == (uint64_t)0;

			*decrypted ^= current_decrypted;
		}

#endif

		{
			std::lock_guard <std::mutex> lock(args->done_mutex);

			args->task_is_done = true;
			args->done.notify_all();
		}
	}

	void CCC::chunk_add(Args * raw_args) {

		AddArgs * args = (AddArgs *)raw_args;

		uint64_t * result = args->result;
		uint64_t * fst_chunk = args->fst_chunk;
		uint64_t * snd_chunk = args->snd_chunk;
		uint64_t fst_len = args->fst_len;

		uint64_t res_snd_deflen_pos = args->res_snd_deflen_pos;

		for (uint64_t i = args->res_fst_deflen_pos; i < res_snd_deflen_pos; i++)

			if (i < fst_len)
				result[i] = fst_chunk[i];
			else
				result[i] = snd_chunk[i - fst_len];

		{
			std::lock_guard <std::mutex> lock(args->done_mutex);

			args->task_is_done = true;
			args->done.notify_all();
		}
	}

	void CCC::chunk_multiply(Args * raw_args) {

		MulArgs * args = (MulArgs *)raw_args;

		uint64_t * result = args->result;
		uint64_t * fst_chunk = args->fst_chunk;
		uint64_t * snd_chunk = args->snd_chunk;
		uint64_t snd_chlen = args->snd_chlen;
		uint64_t default_len = args->default_len;

		uint64_t res_snd_deflen_pos = args->res_snd_deflen_pos;
		uint64_t res_fst_deflen_pos = args->res_fst_deflen_pos;

		for (uint64_t i = args->res_fst_deflen_pos; i < res_snd_deflen_pos; i++) {

			uint64_t fst_ch_i = (i / snd_chlen) * default_len;
			uint64_t snd_ch_j = (i % snd_chlen) * default_len;

#ifdef __AVX512F__

			uint64_t k = 0;
			for (; k + 8 <= default_len; k += 8) {

				__m512i avx_fst_chunk = _mm512_loadu_si512((const void *)(fst_chunk + fst_ch_i + k));
				__m512i avx_snd_chunk = _mm512_loadu_si512((const void *)(snd_chunk + snd_ch_j + k));
				__m512i avx_result = _mm512_and_si512(avx_fst_chunk, avx_snd_chunk);

				_mm512_storeu_si512((void *)(result + i * default_len + k), avx_result);
			}

			for (; k < default_len; k++)
				result[i * default_len + k] = fst_chunk[fst_ch_i + k] & snd_chunk[snd_ch_j + k];

#elif __AVX2__

			uint64_t k = 0;
			for (; k + 4 <= default_len; k += 4) {

				__m256i avx_fst_chunk = _mm256_loadu_si256((const __m256i *)(fst_chunk + fst_ch_i + k));
				__m256i avx_snd_chunk = _mm256_loadu_si256((const __m256i *)(snd_chunk + snd_ch_j + k));
				__m256i avx_result = _mm256_and_si256(avx_fst_chunk, avx_snd_chunk);

				_mm256_storeu_si256((__m256i *)(result + i * default_len + k), avx_result);
			}

			for (; k < default_len; k++)
				result[i * default_len + k] = fst_chunk[fst_ch_i + k] & snd_chunk[snd_ch_j + k];

#else	

			for (uint64_t k = 0; k < default_len; k++)
				result[i * default_len + k] = fst_chunk[fst_ch_i + k] & snd_chunk[snd_ch_j + k];

#endif
		}

		{
			std::lock_guard <std::mutex> lock(args->done_mutex);

			args->task_is_done = true;
			args->done.notify_all();
		}
	}

	void CCC::chunk_permute(Args * raw_args) {

		PermArgs * args = (PermArgs *)raw_args;

		PermInversion * perm_invs = args->perm_invs;
		uint64_t inv_cnt = args->inv_cnt;
		uint64_t * ctxt = args->ctxt;
		uint64_t * res = args->res;
		uint64_t default_len = args->default_len;

		uint64_t snd_deflen_pos = args->snd_deflen_pos;

		for (uint64_t i = args->fst_deflen_pos; i < snd_deflen_pos; i++) {

			uint64_t * current_chunk = ctxt + i * default_len;
			uint64_t * current_chunk_res = res + i * default_len;

			for (uint64_t k = 0; k < inv_cnt; k++) {

				uint64_t fst_u64_ch = perm_invs[k].fst_u64_ch;
				uint64_t snd_u64_ch = perm_invs[k].snd_u64_ch;
				uint64_t fst_u64_r = perm_invs[k].fst_u64_r;
				uint64_t snd_u64_r = perm_invs[k].snd_u64_r;

				unsigned char val_i = (current_chunk[fst_u64_ch] >> fst_u64_r) & 0x01;
				unsigned char val_j = (current_chunk[snd_u64_ch] >> snd_u64_r) & 0x01;

				if (val_i)
					current_chunk_res[snd_u64_ch] |= (uint64_t)1 << snd_u64_r;
				else
					current_chunk_res[snd_u64_ch] &= ~((uint64_t)1 << snd_u64_r);

				if (val_j)
					current_chunk_res[fst_u64_ch] |= (uint64_t)1 << fst_u64_r;
				else
					current_chunk_res[fst_u64_ch] &= ~((uint64_t)1 << fst_u64_r);
			}
		}

		{
			std::lock_guard <std::mutex> lock(args->done_mutex);

			args->task_is_done = true;
			args->done.notify_all();
		}
	}

#if CERTFHE_USE_CUDA

	CCC * CCC::CPU_add(CCC * fst, CCC * snd) {

		uint64_t deflen_to_u64 = fst->context->getDefaultN();

		uint64_t fst_u64_cnt = fst->deflen_count * deflen_to_u64;
		uint64_t snd_u64_cnt = snd->deflen_count * deflen_to_u64;
		uint64_t res_u64_cnt = fst_u64_cnt + snd_u64_cnt;

		uint64_t * fst_c = fst->ctxt;
		uint64_t * snd_c = snd->ctxt;

		uint64_t * res = new uint64_t[res_u64_cnt];

		if (fst->deflen_count + snd->deflen_count < MTValues::add_m_threshold) {

			for (uint64_t i = 0; i < fst_u64_cnt; i++)
				res[i] = fst_c[i];

			for (uint64_t i = 0; i < snd_u64_cnt; i++)
				res[i + fst_u64_cnt] = snd_c[i];
		}
		else {

			Threadpool <Args *> * threadpool = Library::getThreadpool();
			uint64_t thread_count = threadpool->get_threadcount();

			AddArgs * args = new AddArgs[thread_count];

			uint64_t r = res_u64_cnt % thread_count;
			uint64_t q = res_u64_cnt / thread_count;

			uint64_t prevchnk = 0;

			for (uint64_t thr = 0; thr < thread_count; thr++) {

				args[thr].fst_chunk = fst_c;
				args[thr].snd_chunk = snd_c;

				args[thr].result = res;

				args[thr].res_fst_deflen_pos = prevchnk;
				args[thr].res_snd_deflen_pos = prevchnk + q;

				if (r > 0) {

					args[thr].res_snd_deflen_pos += 1;
					r -= 1;
				}
				prevchnk = args[thr].res_snd_deflen_pos;

				args[thr].fst_len = fst_u64_cnt;

				threadpool->add_task(&chunk_add, args + thr);
			}

			for (uint64_t thr = 0; thr < thread_count; thr++) {

				std::unique_lock <std::mutex> lock(args[thr].done_mutex);

				args[thr].done.wait(lock, [thr, args] {
					return args[thr].task_is_done;
				});
			}

			delete[] args;
		}

		return new CCC(fst->context, res, res_u64_cnt / deflen_to_u64, false);
	}

	CCC * CCC::CPU_multiply(CCC * fst, CCC * snd) {

		uint64_t deflen_to_u64 = fst->context->getDefaultN();
		uint64_t * fst_c = fst->ctxt;
		uint64_t * snd_c = snd->ctxt;

		if (fst->deflen_count == 1 && snd->deflen_count == 1) {

			uint64_t * res = new uint64_t[deflen_to_u64];

			for (uint64_t i = 0; i < deflen_to_u64; i++)
				res[i] = fst_c[i] & snd_c[i];

			return new CCC(fst->context, res, 1, false);
		}

		uint64_t res_u64_cnt = (fst->deflen_count * snd->deflen_count) * deflen_to_u64;
		uint64_t fst_deflen_cnt = fst->deflen_count;
		uint64_t snd_deflen_cnt = snd->deflen_count;
		uint64_t res_deflen_cnt = fst_deflen_cnt * snd_deflen_cnt;

		uint64_t * res;
		CCC * mul_result;

		res = new uint64_t[res_u64_cnt];

		mul_result = new CCC(fst->context, res, fst->deflen_count * snd->deflen_count, false);

		if (res_deflen_cnt < MTValues::mul_m_threshold) {

			for (uint64_t i = 0; i < res_deflen_cnt; i++) {

				uint64_t fst_ch_i = (i / snd_deflen_cnt) * deflen_to_u64;
				uint64_t snd_ch_j = (i % snd_deflen_cnt) * deflen_to_u64;

#ifdef __AVX512F__

				uint64_t k = 0;
				for (; k + 8 <= deflen_to_u64; k += 8) {

					__m512i avx_fst_c = _mm512_loadu_si512((const void *)(fst_c + fst_ch_i + k));
					__m512i avx_snd_c = _mm512_loadu_si512((const void *)(snd_c + snd_ch_j + k));
					__m512i avx_res = _mm512_and_si512(avx_fst_c, avx_snd_c);

					_mm512_storeu_si512((void *)(res + i * deflen_to_u64 + k), avx_res);
				}

				for (; k < deflen_to_u64; k++)
					res[i * deflen_to_u64 + k] = fst_c[fst_ch_i + k] & fst_c[snd_ch_j + k];

#elif __AVX2__

				uint64_t k = 0;
				for (; k + 4 <= deflen_to_u64; k += 4) {

					__m256i avx_fst_c = _mm256_loadu_si256((const __m256i *)(fst_c + fst_ch_i + k));
					__m256i avx_snd_c = _mm256_loadu_si256((const __m256i *)(snd_c + snd_ch_j + k));
					__m256i avx_res = _mm256_and_si256(avx_fst_c, avx_snd_c);

					_mm256_storeu_si256((__m256i *)(res + i * deflen_to_u64 + k), avx_res);
				}

				for (; k < deflen_to_u64; k++)
					res[i * deflen_to_u64 + k] = fst_c[fst_ch_i + k] & snd_c[snd_ch_j + k];

#else

				for (uint64_t k = 0; k < deflen_to_u64; k++)
					res[i * deflen_to_u64 + k] = fst_c[fst_ch_i + k] & snd_c[snd_ch_j + k];

#endif
			}
		}
		else {

			Threadpool <Args *> * threadpool = Library::getThreadpool();
			uint64_t thread_count = threadpool->get_threadcount();

			uint64_t q;
			uint64_t r;

			uint64_t worker_cnt;

			if (thread_count >= res_deflen_cnt) {

				q = 1;
				r = 0;

				worker_cnt = res_deflen_cnt;
			}
			else {

				q = res_deflen_cnt / thread_count;
				r = res_deflen_cnt % thread_count;

				worker_cnt = thread_count;
			}

			MulArgs * args = new MulArgs[worker_cnt];

			uint64_t prevchnk = 0;

			for (uint64_t thr = 0; thr < worker_cnt; thr++) {

				args[thr].fst_chunk = fst_c;
				args[thr].snd_chunk = snd_c;

				args[thr].result = res;

				args[thr].res_fst_deflen_pos = prevchnk;
				args[thr].res_snd_deflen_pos = prevchnk + q;

				if (r > 0) {

					args[thr].res_snd_deflen_pos += 1;
					r -= 1;
				}
				prevchnk = args[thr].res_snd_deflen_pos;

				args[thr].snd_chlen = snd_deflen_cnt;

				args[thr].default_len = deflen_to_u64;

				threadpool->add_task(&chunk_multiply, args + thr);
			}

			for (uint64_t thr = 0; thr < worker_cnt; thr++) {

				std::unique_lock <std::mutex> lock(args[thr].done_mutex);

				args[thr].done.wait(lock, [thr, args] {
					return args[thr].task_is_done;
				});
			}

			delete[] args;
		}

		return mul_result;
	}

	CCC * CCC::add(CCC * fst, CCC * snd) {

		if (!fst->on_GPU && !snd->on_GPU) {

			if (fst->deflen_count + snd->deflen_count < GPUValues::gpu_deflen_threshold ||
				fst->deflen_count + snd->deflen_count + GPUValues::gpu_current_vram_deflen_usage >= GPUValues::gpu_max_vram_deflen_usage)

				return CCC::CPU_add(fst, snd);

			else {

				uint64_t deflen_to_u64 = fst->context->getDefaultN();

				uint64_t fst_u64_cnt = fst->deflen_count * deflen_to_u64;
				uint64_t snd_u64_cnt = snd->deflen_count * deflen_to_u64;
				uint64_t res_u64_cnt = fst_u64_cnt + snd_u64_cnt;

				uint64_t * res = CUDA_interface::RAM_RAM_VRAM_chiphertext_addition(deflen_to_u64, fst->deflen_count, snd->deflen_count, fst->ctxt, snd->ctxt);

				GPUValues::gpu_current_vram_deflen_usage += fst->deflen_count + snd->deflen_count;

				return new CCC(fst->context, res, res_u64_cnt / deflen_to_u64, true);
			}
				
		}
		else if (fst->on_GPU ^ snd->on_GPU) {

			if (fst->on_GPU)
				std::swap(fst, snd);

			uint64_t deflen_to_u64 = fst->context->getDefaultN();

			if (fst->deflen_count + snd->deflen_count + GPUValues::gpu_current_vram_deflen_usage >= GPUValues::gpu_max_vram_deflen_usage) {

				uint64_t * ram_snd_ctxt = (uint64_t *)CUDA_interface::VRAM_TO_RAM_copy(snd->ctxt, snd->deflen_count * deflen_to_u64 * sizeof(uint64_t), 0);

				CCC ram_snd(snd->context, ram_snd_ctxt, snd->deflen_count, false);

				return CCC::CPU_add(fst, &ram_snd);
			}
			else {

				uint64_t fst_u64_cnt = fst->deflen_count * deflen_to_u64;
				uint64_t snd_u64_cnt = snd->deflen_count * deflen_to_u64;
				uint64_t res_u64_cnt = fst_u64_cnt + snd_u64_cnt;

				uint64_t * res = CUDA_interface::RAM_VRAM_VRAM_chiphertext_addition(deflen_to_u64, fst->deflen_count, snd->deflen_count, fst->ctxt, snd->ctxt);

				GPUValues::gpu_current_vram_deflen_usage += fst->deflen_count + snd->deflen_count;

				return new CCC(fst->context, res, res_u64_cnt / deflen_to_u64, true);
			}
		}
		else if (fst->on_GPU && snd->on_GPU) {

			uint64_t deflen_to_u64 = fst->context->getDefaultN();

			if (fst->deflen_count + snd->deflen_count + GPUValues::gpu_current_vram_deflen_usage >= GPUValues::gpu_max_vram_deflen_usage) {

				uint64_t * ram_fst_ctxt = (uint64_t *)CUDA_interface::VRAM_TO_RAM_copy(fst->ctxt, fst->deflen_count * deflen_to_u64 * sizeof(uint64_t), 0);
				uint64_t * ram_snd_ctxt = (uint64_t *)CUDA_interface::VRAM_TO_RAM_copy(snd->ctxt, snd->deflen_count * deflen_to_u64 * sizeof(uint64_t), 0);

				CCC ram_fst(fst->context, ram_fst_ctxt, fst->deflen_count, false);
				CCC ram_snd(snd->context, ram_snd_ctxt, snd->deflen_count, false);

				return CCC::CPU_add(&ram_fst, &ram_snd);
			}
			else {

				uint64_t fst_u64_cnt = fst->deflen_count * deflen_to_u64;
				uint64_t snd_u64_cnt = snd->deflen_count * deflen_to_u64;
				uint64_t res_u64_cnt = fst_u64_cnt + snd_u64_cnt;

				uint64_t * res = CUDA_interface::VRAM_VRAM_VRAM_chiphertext_addition(deflen_to_u64, fst->deflen_count, snd->deflen_count, fst->ctxt, snd->ctxt);

				GPUValues::gpu_current_vram_deflen_usage += fst->deflen_count + snd->deflen_count;

				return new CCC(fst->context, res, res_u64_cnt / deflen_to_u64, true);
			}
		}
	}

	CCC * CCC::multiply(CCC * fst, CCC * snd) {

		if (!fst->on_GPU && !snd->on_GPU) {

			if (fst->deflen_count * snd->deflen_count < GPUValues::gpu_deflen_threshold ||
				fst->deflen_count * snd->deflen_count + GPUValues::gpu_current_vram_deflen_usage >= GPUValues::gpu_max_vram_deflen_usage)

				return CCC::CPU_multiply(fst, snd);

			else {

				uint64_t deflen_to_u64 = fst->context->getDefaultN();

				uint64_t * res = CUDA_interface::RAM_RAM_VRAM_chiphertext_multiply(deflen_to_u64, fst->deflen_count, snd->deflen_count, fst->ctxt, snd->ctxt);

				GPUValues::gpu_current_vram_deflen_usage += fst->deflen_count * snd->deflen_count;

				return new CCC(fst->context, res, fst->deflen_count * snd->deflen_count, true);
			}

		}
		else if (fst->on_GPU ^ snd->on_GPU) {

			if (fst->on_GPU)
				std::swap(fst, snd);

			uint64_t deflen_to_u64 = fst->context->getDefaultN();

			if (fst->deflen_count * snd->deflen_count + GPUValues::gpu_current_vram_deflen_usage >= GPUValues::gpu_max_vram_deflen_usage) {

				uint64_t * ram_snd_ctxt = (uint64_t *)CUDA_interface::VRAM_TO_RAM_copy(snd->ctxt, snd->deflen_count * deflen_to_u64 * sizeof(uint64_t), 0);

				CCC ram_snd(snd->context, ram_snd_ctxt, snd->deflen_count, false);

				return CCC::CPU_multiply(fst, &ram_snd);
			}
			else {

				uint64_t * res = CUDA_interface::RAM_VRAM_VRAM_chiphertext_multiply(deflen_to_u64, fst->deflen_count, snd->deflen_count, fst->ctxt, snd->ctxt);

				GPUValues::gpu_current_vram_deflen_usage += fst->deflen_count * snd->deflen_count;

				return new CCC(fst->context, res, fst->deflen_count * snd->deflen_count, true);
			}
		}
		else if (fst->on_GPU && snd->on_GPU) {

			uint64_t deflen_to_u64 = fst->context->getDefaultN();

			if (fst->deflen_count * snd->deflen_count + GPUValues::gpu_current_vram_deflen_usage >= GPUValues::gpu_max_vram_deflen_usage) {

				uint64_t * ram_fst_ctxt = (uint64_t *)CUDA_interface::VRAM_TO_RAM_copy(fst->ctxt, fst->deflen_count * deflen_to_u64 * sizeof(uint64_t), 0);
				uint64_t * ram_snd_ctxt = (uint64_t *)CUDA_interface::VRAM_TO_RAM_copy(snd->ctxt, snd->deflen_count * deflen_to_u64 * sizeof(uint64_t), 0);

				CCC ram_fst(fst->context, ram_fst_ctxt, fst->deflen_count, false);
				CCC ram_snd(snd->context, ram_snd_ctxt, snd->deflen_count, false);

				return CCC::CPU_multiply(&ram_fst, &ram_snd);
			}
			else {

				uint64_t * res = CUDA_interface::VRAM_VRAM_VRAM_chiphertext_multiply(deflen_to_u64, fst->deflen_count, snd->deflen_count, fst->ctxt, snd->ctxt);

				GPUValues::gpu_current_vram_deflen_usage += fst->deflen_count * snd->deflen_count;

				return new CCC(fst->context, res, fst->deflen_count * snd->deflen_count, true);
			}
		}

		return 0;
	}

	uint64_t CCC::decrypt(const SecretKey & sk) {

		if (OPValues::decryption_cache) {

			auto cache_entry = CNODE::decryption_cached_values.find(this);

			if (cache_entry != CNODE::decryption_cached_values.end())
				return (uint64_t)cache_entry->second;
		}

		uint64_t dec = 0;

		uint64_t deflen_cnt = this->deflen_count;
		uint64_t deflen_to_u64 = this->context->getDefaultN();

		uint64_t * sk_mask = sk.getMaskKey();
		uint64_t * ctxt = this->ctxt;

		if (this->on_GPU) {

			dec = CUDA_interface::VRAM_ciphertext_decryption(deflen_to_u64, deflen_cnt, ctxt, sk.getVramMaskKey());
		}
		else if (deflen_cnt < MTValues::dec_m_threshold) {

#ifdef __AVX2__

			for (uint64_t i = 0; i < deflen_cnt; i++) {

				uint64_t * current_chunk = ctxt + i * deflen_to_u64;
				uint64_t current_decrypted = 0x01;

				uint64_t u = 0;

				for (; u + 4 <= deflen_to_u64; u += 4) {

					__m256i avx_aux = _mm256_loadu_si256((const __m256i *)(current_chunk + u));
					__m256i avx_mask = _mm256_loadu_si256((const __m256i *)(sk_mask + u));

					avx_aux = _mm256_and_si256(avx_aux, avx_mask);
					avx_aux = _mm256_xor_si256(avx_aux, avx_mask);

					current_decrypted &= _mm256_testz_si256(avx_aux, avx_aux);
				}

				for (; u < deflen_to_u64; u++)
					current_decrypted &= ((current_chunk[u] & sk_mask[u]) ^ sk_mask[u]) == (uint64_t)0;

				dec ^= current_decrypted;
			}

#else

			for (uint64_t i = 0; i < deflen_cnt; i++) {

				uint64_t * current_chunk = ctxt + i * deflen_to_u64;
				uint64_t current_decrypted = 0x01;

				for (uint64_t u = 0; u < deflen_to_u64; u++)
					current_decrypted &= (((current_chunk[u] & sk_mask[u]) ^ sk_mask[u]) == (uint64_t)0);

				dec ^= current_decrypted;
			}

#endif
		}
		else {

			Threadpool <Args *> * threadpool = Library::getThreadpool();
			uint64_t thread_count = threadpool->get_threadcount();

			uint64_t q;
			uint64_t r;

			uint64_t worker_cnt;

			if (thread_count >= deflen_cnt) {

				q = 1;
				r = 0;

				worker_cnt = deflen_cnt;
			}
			else {

				q = deflen_cnt / thread_count;
				r = deflen_cnt % thread_count;

				worker_cnt = thread_count;
			}

			DecArgs * args = new DecArgs[worker_cnt];

			uint64_t prevchnk = 0;

			for (uint64_t thr = 0; thr < worker_cnt; thr++) {

				args[thr].to_decrypt = ctxt;
				args[thr].sk_mask = sk_mask;

				args[thr].default_len = deflen_to_u64;
				args[thr].d = this->context->getD();

				args[thr].fst_deflen_pos = prevchnk;
				args[thr].snd_deflen_pos = prevchnk + q;

				if (r > 0) {

					args[thr].snd_deflen_pos += 1;
					r -= 1;
				}
				prevchnk = args[thr].snd_deflen_pos;

				args[thr].decrypted = 0;

				threadpool->add_task(&chunk_decrypt, args + thr);
			}

			for (uint64_t thr = 0; thr < worker_cnt; thr++) {

				std::unique_lock <std::mutex> lock(args[thr].done_mutex);

				args[thr].done.wait(lock, [thr, args] {
					return args[thr].task_is_done;
				});

				dec ^= args[thr].decrypted;
			}

			delete[] args;
		}

		if (OPValues::decryption_cache)
			CNODE::decryption_cached_values[this] = (unsigned char)dec;

		return dec;
	}

	CNODE * CCC::permute(const Permutation & perm, bool force_deep_copy) {

		PermInversion * invs = perm.getInversions();
		uint64_t inv_cnt = perm.getInversionsCnt();

		uint64_t deflen_cnt = this->deflen_count;
		uint64_t deflen_to_u64 = this->context->getDefaultN();

		uint64_t len = deflen_to_u64 * deflen_cnt;

		CCC * to_permute;
		if (this->downstream_reference_count == 1 && !force_deep_copy) {

			to_permute = this;
			this->downstream_reference_count += 1;
		}
		else
			to_permute = new CCC(*this);

		if (to_permute->on_GPU) {

			CUDA_interface::VRAM_ciphertext_permutation(deflen_to_u64, deflen_cnt, to_permute->ctxt, perm.getVramInversions(), inv_cnt);
		}
		else {

			if (deflen_cnt < MTValues::perm_m_threshold) {

				for (uint64_t i = 0; i < deflen_cnt; i++) {

					uint64_t * current_chunk = to_permute->ctxt + i * deflen_to_u64;

					for (uint64_t k = 0; k < inv_cnt; k++) {

						uint64_t fst_u64_ch = invs[k].fst_u64_ch;
						uint64_t snd_u64_ch = invs[k].snd_u64_ch;
						uint64_t fst_u64_r = invs[k].fst_u64_r;
						uint64_t snd_u64_r = invs[k].snd_u64_r;

#if CERTFHE_MSVC_COMPILER_MACRO

						//unsigned char val_i = _bittest64((const __int64 *)current_chunk + fst_u64_ch, fst_u64_r);
						//unsigned char val_j = _bittest64((const __int64 *)current_chunk + snd_u64_ch, snd_u64_r);

						unsigned char val_i = (current_chunk[fst_u64_ch] >> fst_u64_r) & 0x01;
						unsigned char val_j = (current_chunk[snd_u64_ch] >> snd_u64_r) & 0x01;

#else

						unsigned char val_i = (current_chunk[fst_u64_ch] >> fst_u64_r) & 0x01;
						unsigned char val_j = (current_chunk[snd_u64_ch] >> snd_u64_r) & 0x01;

#endif

						if (val_i)
							current_chunk[snd_u64_ch] |= (uint64_t)1 << snd_u64_r;
						else
							current_chunk[snd_u64_ch] &= ~((uint64_t)1 << snd_u64_r);

						if (val_j)
							current_chunk[fst_u64_ch] |= (uint64_t)1 << fst_u64_r;
						else
							current_chunk[fst_u64_ch] &= ~((uint64_t)1 << fst_u64_r);
					}
				}
			}
			else {

				Threadpool <Args *> * threadpool = Library::getThreadpool();
				uint64_t thread_count = threadpool->get_threadcount();

				uint64_t q;
				uint64_t r;

				uint64_t worker_cnt;

				if (thread_count >= deflen_cnt) {

					q = 1;
					r = 0;

					worker_cnt = deflen_cnt;
				}
				else {

					q = deflen_cnt / thread_count;
					r = deflen_cnt % thread_count;

					worker_cnt = thread_count;
				}

				PermArgs * args = new PermArgs[worker_cnt];

				uint64_t prevchnk = 0;

				for (uint64_t thr = 0; thr < worker_cnt; thr++) {

					args[thr].perm_invs = invs;
					args[thr].inv_cnt = inv_cnt;

					args[thr].ctxt = to_permute->ctxt;
					args[thr].res = to_permute->ctxt;

					args[thr].fst_deflen_pos = prevchnk;
					args[thr].snd_deflen_pos = prevchnk + q;

					if (r > 0) {

						args[thr].snd_deflen_pos += 1;
						r -= 1;
					}
					prevchnk = args[thr].snd_deflen_pos;

					args[thr].default_len = deflen_to_u64;

					threadpool->add_task(&chunk_permute, args + thr);
				}

				for (uint64_t thr = 0; thr < worker_cnt; thr++) {

					std::unique_lock <std::mutex> lock(args[thr].done_mutex);

					args[thr].done.wait(lock, [thr, args] {
						return args[thr].task_is_done;
					});
				}

				delete[] args;
			}
		}

		return to_permute;
	}

#else

	CCC * CCC::add(CCC * fst, CCC * snd) {

		uint64_t deflen_to_u64 = fst->context->getDefaultN();

		uint64_t fst_u64_cnt = fst->deflen_count * deflen_to_u64;
		uint64_t snd_u64_cnt = snd->deflen_count * deflen_to_u64;
		uint64_t res_u64_cnt = fst_u64_cnt + snd_u64_cnt;

		uint64_t * fst_c = fst->ctxt;
		uint64_t * snd_c = snd->ctxt;

		uint64_t * res = new uint64_t[res_u64_cnt];

		if (fst->deflen_count + snd->deflen_count < MTValues::add_m_threshold) {

			for (uint64_t i = 0; i < fst_u64_cnt; i++)
				res[i] = fst_c[i];

			for (uint64_t i = 0; i < snd_u64_cnt; i++)
				res[i + fst_u64_cnt] = snd_c[i];
		}
		else {

			Threadpool <Args *> * threadpool = Library::getThreadpool();
			uint64_t thread_count = threadpool->get_threadcount();

			AddArgs * args = new AddArgs[thread_count];

			uint64_t r = res_u64_cnt % thread_count;
			uint64_t q = res_u64_cnt / thread_count;

			uint64_t prevchnk = 0;

			for (uint64_t thr = 0; thr < thread_count; thr++) {

				args[thr].fst_chunk = fst_c;
				args[thr].snd_chunk = snd_c;

				args[thr].result = res;

				args[thr].res_fst_deflen_pos = prevchnk;
				args[thr].res_snd_deflen_pos = prevchnk + q;

				if (r > 0) {

					args[thr].res_snd_deflen_pos += 1;
					r -= 1;
				}
				prevchnk = args[thr].res_snd_deflen_pos;

				args[thr].fst_len = fst_u64_cnt;

				threadpool->add_task(&chunk_add, args + thr);
			}

			for (uint64_t thr = 0; thr < thread_count; thr++) {

				std::unique_lock <std::mutex> lock(args[thr].done_mutex);

				args[thr].done.wait(lock, [thr, args] {
					return args[thr].task_is_done;
				});
			}

			delete[] args;
		}

		return new CCC(fst->context, res, res_u64_cnt / deflen_to_u64);
	}

	CCC * CCC::multiply(CCC * fst, CCC * snd) {

		uint64_t deflen_to_u64 = fst->context->getDefaultN();
		uint64_t * fst_c = fst->ctxt;
		uint64_t * snd_c = snd->ctxt;

		if (fst->deflen_count == 1 && snd->deflen_count == 1) {

			uint64_t * res = new uint64_t[deflen_to_u64];

			for (uint64_t i = 0; i < deflen_to_u64; i++)
				res[i] = fst_c[i] & snd_c[i];

			return new CCC(fst->context, res, 1);
		}

		uint64_t res_u64_cnt = (fst->deflen_count * snd->deflen_count) * deflen_to_u64;
		uint64_t fst_deflen_cnt = fst->deflen_count;
		uint64_t snd_deflen_cnt = snd->deflen_count;
		uint64_t res_deflen_cnt = fst_deflen_cnt * snd_deflen_cnt;

		uint64_t * res;
		CCC * mul_result;

		res = new uint64_t[res_u64_cnt];

		mul_result = new CCC(fst->context, res, fst->deflen_count * snd->deflen_count);

		if (res_deflen_cnt < MTValues::mul_m_threshold) {

			for (uint64_t i = 0; i < res_deflen_cnt; i++) {

				uint64_t fst_ch_i = (i / snd_deflen_cnt) * deflen_to_u64;
				uint64_t snd_ch_j = (i % snd_deflen_cnt) * deflen_to_u64;

#ifdef __AVX512F__

				uint64_t k = 0;
				for (; k + 8 <= deflen_to_u64; k += 8) {

					__m512i avx_fst_c = _mm512_loadu_si512((const void *)(fst_c + fst_ch_i + k));
					__m512i avx_snd_c = _mm512_loadu_si512((const void *)(snd_c + snd_ch_j + k));
					__m512i avx_res = _mm512_and_si512(avx_fst_c, avx_snd_c);

					_mm512_storeu_si512((void *)(res + i * deflen_to_u64 + k), avx_res);
				}

				for (; k < deflen_to_u64; k++)
					res[i * deflen_to_u64 + k] = fst_c[fst_ch_i + k] & fst_c[snd_ch_j + k];

#elif __AVX2__

				uint64_t k = 0;
				for (; k + 4 <= deflen_to_u64; k += 4) {

					__m256i avx_fst_c = _mm256_loadu_si256((const __m256i *)(fst_c + fst_ch_i + k));
					__m256i avx_snd_c = _mm256_loadu_si256((const __m256i *)(snd_c + snd_ch_j + k));
					__m256i avx_res = _mm256_and_si256(avx_fst_c, avx_snd_c);

					_mm256_storeu_si256((__m256i *)(res + i * deflen_to_u64 + k), avx_res);
				}

				for (; k < deflen_to_u64; k++)
					res[i * deflen_to_u64 + k] = fst_c[fst_ch_i + k] & snd_c[snd_ch_j + k];

#else

				for (uint64_t k = 0; k < deflen_to_u64; k++)
					res[i * deflen_to_u64 + k] = fst_c[fst_ch_i + k] & snd_c[snd_ch_j + k];

#endif
			}
		}
		else {

			Threadpool <Args *> * threadpool = Library::getThreadpool();
			uint64_t thread_count = threadpool->get_threadcount();

			uint64_t q;
			uint64_t r;

			uint64_t worker_cnt;

			if (thread_count >= res_deflen_cnt) {

				q = 1;
				r = 0;

				worker_cnt = res_deflen_cnt;
			}
			else {

				q = res_deflen_cnt / thread_count;
				r = res_deflen_cnt % thread_count;

				worker_cnt = thread_count;
			}

			MulArgs * args = new MulArgs[worker_cnt];

			uint64_t prevchnk = 0;

			for (uint64_t thr = 0; thr < worker_cnt; thr++) {

				args[thr].fst_chunk = fst_c;
				args[thr].snd_chunk = snd_c;

				args[thr].result = res;

				args[thr].res_fst_deflen_pos = prevchnk;
				args[thr].res_snd_deflen_pos = prevchnk + q;

				if (r > 0) {

					args[thr].res_snd_deflen_pos += 1;
					r -= 1;
				}
				prevchnk = args[thr].res_snd_deflen_pos;

				args[thr].snd_chlen = snd_deflen_cnt;

				args[thr].default_len = deflen_to_u64;

				threadpool->add_task(&chunk_multiply, args + thr);
			}

			for (uint64_t thr = 0; thr < worker_cnt; thr++) {

				std::unique_lock <std::mutex> lock(args[thr].done_mutex);

				args[thr].done.wait(lock, [thr, args] {
					return args[thr].task_is_done;
				});
			}

			delete[] args;
		}

		return mul_result;
	}

	uint64_t CCC::decrypt(const SecretKey & sk) {

		if (OPValues::decryption_cache) {

			auto cache_entry = CNODE::decryption_cached_values.find(this);

			if (cache_entry != CNODE::decryption_cached_values.end())
				return (uint64_t)cache_entry->second;
		}

		uint64_t dec = 0;

		uint64_t deflen_cnt = this->deflen_count;
		uint64_t deflen_to_u64 = this->context->getDefaultN();

		uint64_t * sk_mask = sk.getMaskKey();
		uint64_t * ctxt = this->ctxt;

		if (deflen_cnt < MTValues::dec_m_threshold) {

#ifdef __AVX2__

			for (uint64_t i = 0; i < deflen_cnt; i++) {

				uint64_t * current_chunk = ctxt + i * deflen_to_u64;
				uint64_t current_decrypted = 0x01;

				uint64_t u = 0;

				for (; u + 4 <= deflen_to_u64; u += 4) {

					__m256i avx_aux = _mm256_loadu_si256((const __m256i *)(current_chunk + u));
					__m256i avx_mask = _mm256_loadu_si256((const __m256i *)(sk_mask + u));

					avx_aux = _mm256_and_si256(avx_aux, avx_mask);
					avx_aux = _mm256_xor_si256(avx_aux, avx_mask);

					current_decrypted &= _mm256_testz_si256(avx_aux, avx_aux);
				}

				for (; u < deflen_to_u64; u++)
					current_decrypted &= ((current_chunk[u] & sk_mask[u]) ^ sk_mask[u]) == (uint64_t)0;

				dec ^= current_decrypted;
			}

#else

			for (uint64_t i = 0; i < deflen_cnt; i++) {

				uint64_t * current_chunk = ctxt + i * deflen_to_u64;
				uint64_t current_decrypted = 0x01;

				for (uint64_t u = 0; u < deflen_to_u64; u++)
					current_decrypted &= (((current_chunk[u] & sk_mask[u]) ^ sk_mask[u]) == (uint64_t)0);

				dec ^= current_decrypted;
			}

#endif
		}
		else {

			Threadpool <Args *> * threadpool = Library::getThreadpool();
			uint64_t thread_count = threadpool->get_threadcount();

			uint64_t q;
			uint64_t r;

			uint64_t worker_cnt;

			if (thread_count >= deflen_cnt) {

				q = 1;
				r = 0;

				worker_cnt = deflen_cnt;
			}
			else {

				q = deflen_cnt / thread_count;
				r = deflen_cnt % thread_count;

				worker_cnt = thread_count;
			}

			DecArgs * args = new DecArgs[worker_cnt];

			uint64_t prevchnk = 0;

			for (uint64_t thr = 0; thr < worker_cnt; thr++) {

				args[thr].to_decrypt = ctxt;
				args[thr].sk_mask = sk_mask;

				args[thr].default_len = deflen_to_u64;
				args[thr].d = this->context->getD();

				args[thr].fst_deflen_pos = prevchnk;
				args[thr].snd_deflen_pos = prevchnk + q;

				if (r > 0) {

					args[thr].snd_deflen_pos += 1;
					r -= 1;
				}
				prevchnk = args[thr].snd_deflen_pos;

				args[thr].decrypted = 0;

				threadpool->add_task(&chunk_decrypt, args + thr);
			}

			for (uint64_t thr = 0; thr < worker_cnt; thr++) {

				std::unique_lock <std::mutex> lock(args[thr].done_mutex);

				args[thr].done.wait(lock, [thr, args] {
					return args[thr].task_is_done;
				});

				dec ^= args[thr].decrypted;
			}

			delete[] args;
		}

		if (OPValues::decryption_cache)
			CNODE::decryption_cached_values[this] = (unsigned char)dec;

		return dec;
	}

	CNODE * CCC::permute(const Permutation & perm, bool force_deep_copy) {

		PermInversion * invs = perm.getInversions();
		uint64_t inv_cnt = perm.getInversionsCnt();

		uint64_t deflen_cnt = this->deflen_count;
		uint64_t deflen_to_u64 = this->context->getDefaultN();

		uint64_t len = deflen_to_u64 * deflen_cnt;

		CCC * to_permute;
		if (this->downstream_reference_count == 1 && !force_deep_copy) {

			to_permute = this;
			this->downstream_reference_count += 1;
		}
		else
			to_permute = new CCC(*this);

		if (deflen_cnt < MTValues::perm_m_threshold) {

			for (uint64_t i = 0; i < deflen_cnt; i++) {

				uint64_t * current_chunk = to_permute->ctxt + i * deflen_to_u64;

				for (uint64_t k = 0; k < inv_cnt; k++) {

					uint64_t fst_u64_ch = invs[k].fst_u64_ch;
					uint64_t snd_u64_ch = invs[k].snd_u64_ch;
					uint64_t fst_u64_r = invs[k].fst_u64_r;
					uint64_t snd_u64_r = invs[k].snd_u64_r;

#if CERTFHE_MSVC_COMPILER_MACRO

					//unsigned char val_i = _bittest64((const __int64 *)current_chunk + fst_u64_ch, fst_u64_r);
					//unsigned char val_j = _bittest64((const __int64 *)current_chunk + snd_u64_ch, snd_u64_r);

					unsigned char val_i = (current_chunk[fst_u64_ch] >> fst_u64_r) & 0x01;
					unsigned char val_j = (current_chunk[snd_u64_ch] >> snd_u64_r) & 0x01;

#else

					unsigned char val_i = (current_chunk[fst_u64_ch] >> fst_u64_r) & 0x01;
					unsigned char val_j = (current_chunk[snd_u64_ch] >> snd_u64_r) & 0x01;

#endif

					if (val_i)
						current_chunk[snd_u64_ch] |= (uint64_t)1 << snd_u64_r;
					else
						current_chunk[snd_u64_ch] &= ~((uint64_t)1 << snd_u64_r);

					if (val_j)
						current_chunk[fst_u64_ch] |= (uint64_t)1 << fst_u64_r;
					else
						current_chunk[fst_u64_ch] &= ~((uint64_t)1 << fst_u64_r);
				}
			}
		}
		else {

			Threadpool <Args *> * threadpool = Library::getThreadpool();
			uint64_t thread_count = threadpool->get_threadcount();

			uint64_t q;
			uint64_t r;

			uint64_t worker_cnt;

			if (thread_count >= deflen_cnt) {

				q = 1;
				r = 0;

				worker_cnt = deflen_cnt;
			}
			else {

				q = deflen_cnt / thread_count;
				r = deflen_cnt % thread_count;

				worker_cnt = thread_count;
			}

			PermArgs * args = new PermArgs[worker_cnt];

			uint64_t prevchnk = 0;

			for (uint64_t thr = 0; thr < worker_cnt; thr++) {

				args[thr].perm_invs = invs;
				args[thr].inv_cnt = inv_cnt;

				args[thr].ctxt = to_permute->ctxt;
				args[thr].res = to_permute->ctxt;

				args[thr].fst_deflen_pos = prevchnk;
				args[thr].snd_deflen_pos = prevchnk + q;

				if (r > 0) {

					args[thr].snd_deflen_pos += 1;
					r -= 1;
				}
				prevchnk = args[thr].snd_deflen_pos;

				args[thr].default_len = deflen_to_u64;

				threadpool->add_task(&chunk_permute, args + thr);
			}

			for (uint64_t thr = 0; thr < worker_cnt; thr++) {

				std::unique_lock <std::mutex> lock(args[thr].done_mutex);

				args[thr].done.wait(lock, [thr, args] {
					return args[thr].task_is_done;
				});
			}

			delete[] args;
		}

		return to_permute;
	}

#endif

	std::ostream & operator << (std::ostream & out, const CCC & ccc) {

		out << "CCC\n" << static_cast <const CNODE &>(ccc);

		return out;
	}
}


