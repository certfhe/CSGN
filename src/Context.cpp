#include "Context.h"

using namespace certFHE;
using namespace std;

namespace certFHE {

#pragma region Constructors and destructor
  
Context::Context(const Context& context)
{
	this->N = context.getN();
	this->D = context.getD();
	this->S = context.getS();
	this->defaultLen = context.getDefaultN();
}



Context::Context(const uint64_t pN,const uint64_t pD) : N(pN),D(pD)
{
    this->S = N/(2*D);

    uint64_t div = this->N / (sizeof(uint64_t)*8);
	uint64_t rem = this->N % (sizeof(uint64_t)*8);
    this->defaultLen = div;
	if ( rem != 0)
		this->defaultLen++;	
}

Context::~Context()
{

}

#pragma endregion

#pragma region Operators

ostream& operator<<(ostream &out, const Context &c)
{
	out<<"N= "<<c.getN()<<endl;
	out<<"D= "<<c.getD()<<endl;
	out<<"S= "<<c.getS();	
	out<<endl;
	return out;
}

Context& Context::operator=(const Context& context) 
{
	this->D = context.D;
	this->N = context.N;	
	this->S = context.S;
	this->defaultLen = context.defaultLen;
	return *this;
}

#pragma endregion

#pragma region Getters and Setters

uint64_t Context::getN() const
{
	return this->N;
}

uint64_t Context::getD() const
{
	return this->D;
}

uint64_t Context::getS() const
{
	return this->S;
}
uint64_t Context::getDefaultN() const
{
	return this->defaultLen;
}

void Context::setN(uint64_t n)
{	
	this->N = n;
	this->S = n / (2*this->D);
}

void Context::setD(uint64_t d)
{
	this->D= d;
	this->S = this->N / (2*this->D);
}

#pragma endregion

}