#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "curve25519_i64.h"

typedef unsigned char BYTE;

static BYTE *S_get_key_buffer(SV *var, const char *name, bool null, bool writable)
{
	STRLEN len;
	dTHX;
	if (!SvOK(var) && null) {
		return NULL;
	}
	if (!SvOK(var)) {
		croak("%s cannot be undefined", name);
	}
	if (writable) {
		SV_CHECK_THINKFIRST(var);
	}
	BYTE* buff = (BYTE*) SvPV(var, len);
	if (len != 32) {
		croak("%s requires 32 bytes", name);
	}

	return buff;
}

MODULE = HEAT::Crypto	PACKAGE = HEAT::Crypto

PROTOTYPES: DISABLED

void _clamp(key)
	CODE:
	BYTE *key = S_get_key_buffer(ST(0), "key", false, true);
	clamp25519(key);

void _core(p, s, k, g)
	CODE:
	BYTE *p = S_get_key_buffer(ST(0), "p", false, true);
	BYTE *s = S_get_key_buffer(ST(1), "s", true, true);
	BYTE *k = S_get_key_buffer(ST(2), "k", false, false);
	BYTE *g = S_get_key_buffer(ST(3), "g", true, false);
	core25519(p, s, k, g);

int _sign(v, h, x, s)
	CODE:
	BYTE *v = S_get_key_buffer(ST(0), "v", false, true);
	BYTE *h = S_get_key_buffer(ST(1), "h", false, false);
	BYTE *x = S_get_key_buffer(ST(2), "x", false, false);
	BYTE *s = S_get_key_buffer(ST(3), "s", false, false);
	RETVAL = sign25519(v, h, x, s);
	OUTPUT:
	RETVAL

void _verify(y, v, h, p)
	CODE:
	BYTE *y = S_get_key_buffer(ST(0), "y", false, true);
	BYTE *v = S_get_key_buffer(ST(1), "v", false, false);
	BYTE *h = S_get_key_buffer(ST(2), "h", false, false);
	BYTE *p = S_get_key_buffer(ST(3), "p", false, false);
	verify25519(y, v, h, p);
