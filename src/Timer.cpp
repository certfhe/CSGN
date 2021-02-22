#include "Timer.h"

using namespace certFHE;
using namespace std;

#pragma region Constructors and destructor

Timer::Timer(string pname) : name(pname)
{
    this->chronometer = std::chrono::duration<double>(0);
}

Timer::~Timer() {

}

#pragma endregion

#pragma region Public methods

void Timer::start(){
    this->start_fingerprint = std::chrono::high_resolution_clock::now();
}

double Timer::stop(){
    this->stop_fingerprint = std::chrono::high_resolution_clock::now();
    chronometer = stop_fingerprint - start_fingerprint;
    return chronometer.count()*1000;
}

void Timer::print(){
    cout<<this->name<<" : "<<chronometer.count()*1000<< " ms "<<endl;fflush(stdout);
}

void Timer::reset(){
    this->stop_fingerprint = std::chrono::high_resolution_clock::now();
    this->start_fingerprint = stop_fingerprint;
}

double Timer::stopAndPrint(){
    this->stop();
    this->print();
    return chronometer.count()*1000;
}

double Timer::getValue(){
    return chronometer.count()*1000;
}

#pragma endregion