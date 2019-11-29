#ifndef __SR25519_H__
#define __SR25519_H__

#include "merlin.h"

void sign011_s(uint8_t* public_key, uint8_t* secret_key, uint8_t* message, unsigned int message_size, uint8_t* result);

#endif