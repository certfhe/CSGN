#ifndef THREADPOOL_H
#define THREADPOOL_H

#include "utils.h"

namespace certFHE {

	/**
	 * Template singleton class that implements a threadpool
	 * (Currently) used only with T = Args * (defined in ArgClasses.h)
	**/
	template <typename T>
	class Threadpool {

		std::unordered_set <std::thread::id> * closed;
		bool all_closed;

		static Threadpool <T> * threadpool;
		static bool initialized;

		int thread_count;

		std::vector <std::thread *> * threads;
		std::queue <std::function <void(T)>> tasks;
		std::queue <T> tasks_args;

		std::mutex tasks_mutex;
		std::condition_variable tasks_condition;

		static std::mutex threadpool_manipulation_mutex;

		void wait_for_tasks();

		Threadpool();

		~Threadpool();

	public:

		/**
		 * Explicitly set the threadcount
		 * (threads will be closed / created depending on the situation)
		**/
		void set_threadcount(const int new_threadcount);

		/**
		 * Getter for thread_count value
		**/
		int get_threadcount();

		/**
		 * Creating the threadpool
		**/
		static Threadpool <T> * make_threadpool();

		/**
		 * Schedules given tasks in FIFO order
		**/
		void add_task(std::function <void(T)> to_execute, T to_execute_args);

		/**
		 * Closes the threadpool
		**/
		void close();
	};

	template <typename T>
	Threadpool <T> * Threadpool <T>::threadpool = 0;

	template <typename T>
	bool Threadpool <T>::initialized = 0;

	template <typename T>
	std::mutex Threadpool <T>::threadpool_manipulation_mutex;


	template <typename T>
	void Threadpool <T>::set_threadcount(int new_threadcount) {
		
		std::lock_guard <std::mutex> lock_fst(Threadpool <T>::threadpool_manipulation_mutex);

		if (Threadpool <T>::initialized) {

			{
				std::lock_guard <std::mutex> lock_snd(this->tasks_mutex);

				/**
				 * For creating new threads
				**/
				for (int i = this->thread_count; i < new_threadcount; i++) {

					this->threads->push_back(new std::thread(&Threadpool<T>::wait_for_tasks, this));
				}

				/**
				 * For removing excess threads
				**/
				for (int i = new_threadcount; i < this->thread_count; i++) {

					this->closed->insert(this->threads->at(i)->get_id());
				}

			}

			this->tasks_condition.notify_all();

			for (int i = new_threadcount; i < this->thread_count; i++)
				this->threads->at(i)->join();
		}
		
		this->thread_count = new_threadcount;
	}

	template <typename T>
	int Threadpool <T>::get_threadcount() { return this->thread_count; }

	template <typename T>
	Threadpool <T>::Threadpool(){

		this->thread_count = std::thread::hardware_concurrency() != 0 ? std::thread::hardware_concurrency() : 12;

		threads = new std::vector <std::thread *>(this->thread_count);
		closed = new std::unordered_set <std::thread::id>();

		all_closed = false;
	}

	template <typename T>
	Threadpool<T> * Threadpool <T>::make_threadpool() {

		std::lock_guard <std::mutex> lock(Threadpool <T>::threadpool_manipulation_mutex);

		if (!Threadpool <T>::initialized) {

			Threadpool * created = new Threadpool();
			Threadpool <T>::threadpool = created;

			Threadpool <T>::initialized = true;

			for (int i = 0; i < created->thread_count; i++) 
				created->threads->at(i) = new std::thread(&Threadpool<T>::wait_for_tasks, created);	
		}

		return threadpool;
	}

	template <typename T>
	void Threadpool <T>::wait_for_tasks() {

		while (true) {

			std::function <void(T)> to_execute;
			T to_execute_args;

			{
				std::unique_lock <std::mutex> tasks_lock(this->tasks_mutex);

				this->tasks_condition.wait(tasks_lock,
					[this] {
					return
						!(this->tasks.empty()) ||
						(this->tasks.empty() && 
						(this->all_closed || this->closed->find(std::this_thread::get_id()) != this->closed->end()));
				});

				if (this->tasks.empty() && 
					(this->all_closed || this->closed->find(std::this_thread::get_id()) != this->closed->end()))
					return;

				to_execute = this->tasks.front();
				this->tasks.pop();

				to_execute_args = this->tasks_args.front();
				this->tasks_args.pop();
			}

			to_execute(to_execute_args);
		}
	}

	template <typename T>
	void Threadpool <T>::add_task(std::function <void(T)> to_execute, T to_execute_args) {

		{
			std::lock_guard <std::mutex> tasks_lock(this->tasks_mutex);

			if (this->all_closed == true)
				throw std::runtime_error("Threadpool already closed!");

			this->tasks.push(to_execute);
			this->tasks_args.push(to_execute_args);
		}

		this->tasks_condition.notify_one();
	}

	template <typename T>
	void Threadpool <T>::close() {

		std::lock_guard <std::mutex> lock_fst(Threadpool <T>::threadpool_manipulation_mutex);

		{
			std::lock_guard <std::mutex> lock_snd(this->tasks_mutex);

			if (this->all_closed == true)
				return;

			this->all_closed = true;
		}

		this->tasks_condition.notify_all();

		for (int i = 0; i < this->thread_count; i++)
			this->threads->at(i)->join();

		Threadpool <T>::initialized = false;
		delete this;
	}

	template <typename T>
	Threadpool <T>::~Threadpool() {

		delete[] closed;
		delete[] threads;
	}
}

#endif


