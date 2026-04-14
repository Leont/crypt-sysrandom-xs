#if __STDC_VERSION__ >= 199901L
#define PERL_WANT_VARARGS
#endif
#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#define NO_XSLOCKS
#include "XSUB.h"
#include "ppport.h"

#ifndef custom_op_register
#define custom_op_register(pp_addr, xop) Perl_custom_op_register(aTHX_ pp_addr, xop)
#endif

#include <sys/types.h>
#include <errno.h>

#if defined(HAVE_SYS_RANDOM_GETRANDOM) || defined(HAVE_SYS_RANDOM_ARC4RANDOM)
#include <sys/random.h>

#elif defined(HAVE_SYSCALL_GETRANDOM)
#include <sys/syscall.h>
#include <unistd.h>
#define getrandom(data, length, flags) syscall(SYS_getrandom, data, length, flags)

#elif defined(HAVE_UNISTD_ARC4RANDOM)
#include <unistd.h>

#elif defined(HAVE_STDLIB_ARC4RANDOM)
#include <stdlib.h>

#elif defined(HAVE_BCRYPT_GENRANDOM)
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <winternl.h>
#include <ntstatus.h>
#include <bcrypt.h>

#elif defined(HAVE_RDRAND32) || defined(HAVE_RDRAND64)
#include <immintrin.h>

#else
#error "No suitable implementation found"
#endif

static const char error_string[] = "Could not read random bytes";

SV* S_random_bytes(pTHX_ long wanted) {
	if (wanted < 0)
		croak("Invalid length %ld", wanted);

	SV* RETVAL = newSVpv("", 0);
	char* data = SvGROW(RETVAL, (size_t)wanted + 1);
#if defined(HAVE_BCRYPT_GENRANDOM)
	NTSTATUS status = BCryptGenRandom(NULL, data, wanted, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (!NT_SUCCESS(status)) {
		SvREFCNT_dec(RETVAL);
		croak(error_string);
	}
#elif defined(HAVE_SYS_RANDOM_ARC4RANDOM) || defined(HAVE_UNISTD_ARC4RANDOM) || defined(HAVE_STDLIB_ARC4RANDOM)
	arc4random_buf(data, wanted);
#elif defined(HAVE_RDRAND64)
	if (wanted % 8)
		data = SvGROW(RETVAL, wanted + (8 - (wanted % 8)) + 1);
	int i;
	for (i = 0; i < wanted; i += 8)
		_rdrand64_step((unsigned long long*)(data + i));
#elif defined(HAVE_RDRAND32)
	if (wanted % 4)
		data = SvGROW(RETVAL, wanted + (4 - (wanted % 4)) + 1);
	int i;
	for (i = 0; i < wanted; i += 4)
		_rdrand32_step((unsigned*)(data + i));
#else
	size_t received = 0;
	while (received < (size_t)wanted) {
		int result = getrandom(data + received, wanted - received, 0);
		if (result == -1 && errno == EINTR) {
			dXCPT;

			XCPT_TRY_START {
				PERL_ASYNC_CHECK();
			} XCPT_TRY_END;

			XCPT_CATCH {
				SvREFCNT_dec(RETVAL);
				XCPT_RETHROW;
			}
		} else if (result == -1 || result == 0) {
			SvREFCNT_dec(RETVAL);
			croak(error_string);
		} else {
			received += result;
		}
	}
#endif
	SvCUR_set(RETVAL, wanted);
	data[wanted] = '\0';

	return RETVAL;
}
#define random_bytes(length) S_random_bytes(aTHX_ length)

#if PERL_VERSION >= 22

static OP* pp_random_bytes(pTHX) {
	dSP;
	IV arg = POPi;
	SV* result = random_bytes(arg);
	mPUSHs(result);
	RETURN;
}

static const XOP random_bytes_xop = {
	.xop_flags = XOPf_xop_name | XOPf_xop_desc | XOPf_xop_class,
	.xop_name  = "random_bytes",
	.xop_desc  = "random_bytes retrieval",
	.xop_class = OA_UNOP,
};

static OP* random_bytes_call_checker(pTHX_ OP *entersubop, GV *namegv, SV *ckobj) {
	OP* pushop = cLISTOPx(entersubop)->op_first;
	if (!pushop)
		return entersubop;

	if (pushop->op_type == OP_NULL && cLISTOPx(pushop)->op_first)
		pushop = cLISTOPx(pushop)->op_first;

	OP* argop = OpSIBLING(pushop);
	if (!argop)
		return entersubop;

	if (argop->op_type != OP_CONST && argop->op_type != OP_PADSV && argop->op_type != OP_GVSV)
		return entersubop;

	OP* nextop = OpSIBLING(argop);
	if (!nextop || nextop->op_type != OP_NULL)
		return entersubop;

	if (OpSIBLING(nextop))
		return entersubop;

	OpMORESIB_set(pushop, nextop);
	OpLASTSIB_set(argop, NULL);
	OP* newop = newUNOP(OP_CUSTOM, 0, argop);
	newop->op_ppaddr = pp_random_bytes;
	op_free(entersubop);
	return newop;
}

#endif

MODULE = Crypt::SysRandom::XS				PACKAGE = Crypt::SysRandom::XS

PROTOTYPES: DISABLE

SV* random_bytes(long wanted)

BOOT:
#if PERL_VERSION >= 22
{
	custom_op_register(pp_random_bytes, &random_bytes_xop);
	CV* random_bytes_cv = get_cv("Crypt::SysRandom::XS::random_bytes", 0);
	cv_set_call_checker(random_bytes_cv, random_bytes_call_checker, (SV*)random_bytes_cv);
}
#endif
