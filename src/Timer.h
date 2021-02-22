#ifndef TIMER_H
#define TIMER_H

#include "utils.h"

using namespace std;

namespace certFHE
{
  /**
   * Basic timer to measure operations
  **/
  class Timer{

    private:

      string name;

      std::chrono::duration<double> chronometer;

      std::chrono::high_resolution_clock::time_point  start_fingerprint = std::chrono::high_resolution_clock::now();
      std::chrono::high_resolution_clock::time_point  stop_fingerprint =std::chrono::high_resolution_clock::now();
      
    public:

      /**
       * Default/Simple constructor
       * @param[in] name: Name of the timer
      **/
      Timer(string name = "Default timer");

      /**
       * Destructor
      **/
      virtual ~Timer();
      
      /** 
       * Start the stopwatch
      **/
      void start();

      /**
       * Stop the timer
      **/

      /**
       * Stop and returm the timer
       * @return value: the measured time in miliseconds
      **/
      double stop();

      /**
       * Reset the stopwatch
      **/
      void reset();

      /**
       * Stop the timer, print & returned the measure time, in miliseconds
       * @return value: measured time in miliseconds
      **/
      double stopAndPrint();

      /**
       * Print the measured time, in miliseconds. Timer should be stopped before calling the function.
      **/
      void print();

      /**
       * Return the current measured time, in miliseconds. Timer should be stopped before calling the function.
       * @return value :measured time in miliseconds
      **/
      double getValue();
      
  };

} 


#endif