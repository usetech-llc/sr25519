#ifndef __MERLIN__
#define __MERLIN__
#include "../strobe-code/strobe.h"

typedef strobe_s* transcript_strobe;

transcript_strobe init_transcript(strobe_t* strobe, unsigned char* label);

void append_message(transcript_strobe strobe, 
	uint8_t* label, 
	unsigned int label_length, 
	uint8_t* message, 
	unsigned int message_length);

void meta_ad(transcript_strobe strobe,
	uint8_t* data,
	unsigned int length,
	bool more);

void ad(transcript_strobe strobe,
	uint8_t* data,
	unsigned int length,
	bool more);

uint8_t* prf(transcript_strobe strobe,
	unsigned int expected_output,
	bool more);

void key(transcript_strobe strobe,
	uint8_t* data,
	size_t len,
	bool more);

uint8_t* operate(transcript_strobe strobe,
	bool meta,
	bool more,
	control_word_t flags,
	uint8_t* data,
	unsigned int length);

#endif