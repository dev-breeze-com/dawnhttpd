/*
cdecode.h - c header for a base64 decoding algorithm
This is part of the libbase64 project, and has been placed in the public domain.
For details, see http://sourceforge.net/projects/libbase64
*/

#ifndef BASE64_CDECODE_H
#define BASE64_CDECODE_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum { step_a=1, step_b, step_c, step_d } base64_decodestep;

typedef struct {
	base64_decodestep step;
	char plainchar;
} base64_decodestate;

extern void base64_init_decodestate(base64_decodestate* state_in);

extern int base64_decode_value(char value_in);

extern int base64_decode_block(const char* code_in, const int length_in,
	char* plaintext_out, base64_decodestate* state_in);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* BASE64_CDECODE_H */
