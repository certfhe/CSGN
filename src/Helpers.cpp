#include "Helpers.h"

namespace certFHE{

#pragma region Library class

	Threadpool <Args *> * Library::threadpool = 0;

	void Library::initializeLibrary(bool initPools) {

		//Introducing local time as seed for further pseudo random generator calls
		srand((unsigned int)time(0));

		if (initPools == true)
			Library::threadpool = Threadpool <Args *> ::make_threadpool();
		else
			Library::threadpool = 0;
	}

	Threadpool <Args *> * Library::getThreadpool() {

		if(Library::threadpool == 0)
			Library::threadpool = Threadpool <Args *> ::make_threadpool();

		return Library::threadpool;
	}

#pragma endregion 

#pragma region Helper class

	bool Helper::exists(const uint64_t * v, const uint64_t len, const uint64_t value) {

		for (uint64_t i = 0; i < len; i++)
			if (v[i] == value)
				return true;

		return false;
	}

	void Helper::u64_chunk_cpy(Args * raw_args) {

		U64CpyArgs * args = (U64CpyArgs *)raw_args;

		const uint64_t * src = args->src;
		uint64_t * dest = args->dest;
		uint64_t snd_u64_pos = args->snd_u64_pos;

		for (uint64_t i = args->fst_u64_pos; i < snd_u64_pos; i++)
			dest[i] = src[i];
		
		{
			std::lock_guard <std::mutex> lock(args->done_mutex);

			args->task_is_done = true;
			args->done.notify_all(); 
		}
	}

	void Helper::u64_multithread_cpy(const uint64_t * src, uint64_t * dest, uint64_t to_cpy_len) {

		Threadpool <Args *> * threadpool = Library::getThreadpool();
		uint64_t thread_count = threadpool->get_threadcount();

		uint64_t q;
		uint64_t r;

		uint64_t worker_cnt;

		// trying to split workload as even as possible

		if (thread_count >= to_cpy_len) {

			q = 1;
			r = 0;

			worker_cnt = to_cpy_len;
		}
		else {

			q = to_cpy_len / thread_count;
			r = to_cpy_len % thread_count;

			worker_cnt = thread_count;
		}

		U64CpyArgs * args = new U64CpyArgs[worker_cnt];

		uint64_t prevchnk = 0;

		for (uint64_t thr = 0; thr < worker_cnt; thr++) {

			args[thr].src = src;
			args[thr].dest = dest;

			args[thr].fst_u64_pos = prevchnk;
			args[thr].snd_u64_pos = prevchnk + q;

			if (r > 0) {

				args[thr].snd_u64_pos += 1;
				r -= 1;
			}
			prevchnk = args[thr].snd_u64_pos;

			threadpool->add_task(&u64_chunk_cpy, args + thr);
		}

		for (uint64_t thr = 0; thr < worker_cnt; thr++) {

			std::unique_lock <std::mutex> lock(args[thr].done_mutex);

			args[thr].done.wait(lock, [thr, args] {
				return args[thr].task_is_done;
			});
		}

		delete[] args;
	}

#pragma endregion

}