#include "yasl/yasl.h"
#include "yasl/yasl_aux.h"

#include "tommath.h"

#define BIGINT_VERSION "v0.2.0"

static const char *BIGINT_NAME = "bigint";

static mp_int *init_bigint(struct YASL_State *S) {
	mp_int *value = malloc(sizeof(mp_int));
	int result = mp_init(value);
	if (result != MP_OKAY) {
		YASL_print_err(S, "Error creating bigint: %s", mp_error_to_string(result));
		YASL_throw_err(S, YASL_ERROR);
	}

	return value;
}

static void free_bigint(struct YASL_State *S, mp_int *value) {
    (void)S;
    mp_clear(value);
}

static void YASL_pushbigint(struct YASL_State *S, mp_int *value) {
	YASL_pushuserdata(S, value, BIGINT_NAME, (void (*)(struct YASL_State *, void *))mp_clear);
	YASL_loadmt(S, BIGINT_NAME);
	YASL_setmt(S);
}

int YASL_bigint_bigint(struct YASL_State *S) {
	if (YASL_isnuserdata(S, BIGINT_NAME, 0)) {
		return 1;
	}

	if (YASL_isnint(S, 0)) {
		yasl_int n = YASL_peeknint(S, 0);
		mp_int *value = init_bigint(S);
		if (n < 0) {
			mp_set_i64(value, -n);
			int result = mp_neg(value, value);
			if (result) {
				YASL_print_err(S, "Error creating bigint: %s", mp_error_to_string(result));
				YASL_throw_err(S, YASL_ERROR);
			}
		} else {
			mp_set_i64(value, n);
		}

		YASL_pushbigint(S, value);
		return 1;
	}

	if (!YASL_isnstr(S, 0)) {
		YASLX_print_err_bad_arg_type(S, "bigint.bigint", 0, BIGINT_NAME, YASL_peekntypename(S, 0));
		YASL_throw_err(S, YASL_TYPE_ERROR);
	}

	const char *str = YASL_popcstr(S);

	mp_int *value = init_bigint(S);

	int result = mp_read_radix(value, str, 10);
	if (result) {
		YASL_print_err(S, "Error creating bigint: %s", mp_error_to_string(result));
		YASL_throw_err(S, YASL_VALUE_ERROR);
	}

	YASL_pushbigint(S, value);

	return 1;
}

int YASL_bigint_tostr(struct YASL_State *S) {
	mp_int *v = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.tostr", 0);

	int size;
	int result = mp_radix_size(v, 10, &size);
	(void) result;

	char *buffer = malloc(size);

	mp_toradix(v, buffer, 10);

	YASL_pushzstr(S, buffer);

	free(buffer);

	return 1;
}

int YASL_bigint_iszero(struct YASL_State *S) {
	mp_int *n = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.iszero", 0);

	YASL_pushbool(S, mp_iszero(n));

	return 1;
}

int YASL_bigint_iseven(struct YASL_State *S) {
	mp_int *n = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.iseven", 0);

	YASL_pushbool(S, mp_iseven(n));

	return 1;
}

int YASL_bigint_isodd(struct YASL_State *S) {
	mp_int *n = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.isodd", 0);

	YASL_pushbool(S, mp_isodd(n));

	return 1;
}

const uint32_t MAX_UINT32 = 0xFFFFFFFF;
static int YASL_bigint_log_n(struct YASL_State *S) {
	mp_int *a = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.log_n", 0);
	yasl_int n = YASLX_checknint(S, "bigint.log_n", 1);

	if (n <= 1) {
		YASL_print_err(S, "Invalid logarithm base given: %li", n);
		YASL_throw_err(S, YASL_VALUE_ERROR);
	}
	if (n > MAX_UINT32) {
		YASL_print_err(S, "Logarithm base was not smaller than 2^32: %li", n);
		YASL_throw_err(S, YASL_VALUE_ERROR);
	}

	uint32_t value;
	int result = mp_log_u32(a, (uint32_t)n, &value);
	if (result) {
		YASL_print_err(S, "Error performing operation: %s", mp_error_to_string(result));
		YASL_throw_err(S, YASL_ERROR);
	}

	YASL_pushint(S, value);

	return 1;
}

int YASL_bigint_isprime(struct YASL_State *S) {
	mp_int *n = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.isprime", 0);

	const int bitsize = mp_count_bits(n);

	int value;
	int result = mp_prime_is_prime(n, mp_prime_rabin_miller_trials(bitsize), &value);
	if (result) {
		YASL_print_err(S, "Error performing operation: %s", mp_error_to_string(result));
		YASL_throw_err(S, YASL_ERROR);
	}

	YASL_pushbool(S, value);

	return 1;
}

static int YASL_bigint_kronecker(struct YASL_State *S) {
	mp_int *a = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.kronecker", 0);
	mp_int *n = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.kronecker", 1);

	int value;
	int result = mp_kronecker(a, n, &value);
	if (result) {
		YASL_print_err(S, "Error performing operation: %s", mp_error_to_string(result));
		YASL_throw_err(S, YASL_ERROR);
	}

	YASL_pushint(S, value);

	return 1;
}

static int YASL_bigint_gcd(struct YASL_State *S) {
	mp_int *a = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.gcd", 0);
	mp_int *b = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.gcd", 1);

	mp_int *value = init_bigint(S);

	int result = mp_gcd(a, b, value);
	if (result) {
		YASL_print_err(S, "Error performing operation: %s", mp_error_to_string(result));
		YASL_throw_err(S, YASL_ERROR);
	}

	YASL_pushbigint(S, value);

	return 1;
}

static int YASL_bigint_lcm(struct YASL_State *S) {
	mp_int *a = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.lcm", 0);
	mp_int *b = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.lcm", 1);

	mp_int *value = init_bigint(S);

	int result = mp_lcm(a, b, value);
	if (result) {
		YASL_print_err(S, "Error performing operation: %s", mp_error_to_string(result));
		YASL_throw_err(S, YASL_ERROR);
	}

	YASL_pushbigint(S, value);

	return 1;
}

static int YASL_bigint_powmod(struct YASL_State *S) {
	mp_int *a = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.powmod", 0);
	mp_int *b = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.powmod", 1);
	mp_int *n = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.powmod", 2);

	mp_int *value = init_bigint(S);

	int result = mp_exptmod(a, b, n, value);
	if (result) {
		YASL_print_err(S, "Error performing operation: %s", mp_error_to_string(result));
		YASL_throw_err(S, YASL_ERROR);
	}

	YASL_pushbigint(S, value);

	return 1;
}

static int YASL_bigint___neg(struct YASL_State *S) {
	mp_int *expr = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.__neg", 0);

	mp_int *value = init_bigint(S);
	int result = mp_neg(expr, value);
	if (result) {
		YASL_print_err(S, "Error performing arithmetic: %s", mp_error_to_string(result));
		YASL_throw_err(S, YASL_ERROR);
	}

	YASL_pushbigint(S, value);

	return 1;
}

static int YASL_bigint___pos(struct YASL_State *S) {
	mp_int *expr = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.__pos", 0);
	(void) expr;

	return 1;
}

#define mp_eq(result) (result == MP_EQ)
#define mp_lt(result) (result == MP_LT)
#define mp_le(result) (mp_eq(result) || mp_lt(result))
#define mp_gt(result) (result == MP_GT)
#define mp_ge(result) (mp_eq(result) || mp_gt(result))

#define DEFINE_COMP(name) \
static int YASL_bigint___##name(struct YASL_State *S) {\
	mp_int *left = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.__" #name, 0);\
	mp_int *right = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.__" #name, 1);\
	\
	int result = mp_cmp(left, right);\
	\
	YASL_pushbool(S, mp_##name(result));\
	\
	return 1;\
}

DEFINE_COMP(eq)
DEFINE_COMP(lt)
DEFINE_COMP(le)
DEFINE_COMP(gt)
DEFINE_COMP(ge)

#define DEFINE_ARITH(op, name) \
static int YASL_bigint___##name(struct YASL_State *S) {\
	mp_int *left = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.__" #name, 0);\
	mp_int *right = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.__" #name, 1);\
	\
	mp_int *value = init_bigint(S);\
	\
	int result = mp_##op(left, right, value);\
	if (result) {\
		YASL_print_err(S, "Error performing arithmetic: %s", mp_error_to_string(result));\
		YASL_throw_err(S, YASL_ERROR);\
	}\
	\
	YASL_pushbigint(S, value);\
	\
	return 1;\
}

DEFINE_ARITH(add, add)
DEFINE_ARITH(sub, sub)
DEFINE_ARITH(mul, mul)
DEFINE_ARITH(or, bor)
DEFINE_ARITH(xor, bxor)
DEFINE_ARITH(and, band)
#undef DEFINE_ARITH

static int YASL_bigint___idiv(struct YASL_State *S) {
	mp_int *left = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.__idiv", 0);
	mp_int *right = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.__idiv", 1);

	if (!mp_cmp_d(right, 0)) {
		YASL_print_err(S, "DivisionByZeroError");
		YASL_throw_err(S, YASL_DIVIDE_BY_ZERO_ERROR);
	}

	mp_int *value = init_bigint(S);

	int result = mp_div(left, right, value, NULL);
	if (result) {
		YASL_print_err(S, "Error performing arithmetic: %s", mp_error_to_string(result));
		YASL_throw_err(S, YASL_ERROR);
	}

	YASL_pushbigint(S, value);

	return 1;
}

static int YASL_bigint___mod(struct YASL_State *S) {
	mp_int *left = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.__idiv", 0);
	mp_int *right = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.__idiv", 1);

	if (!mp_cmp_d(right, 0)) {
		YASL_print_err(S, "DivisionByZeroError");
		YASL_throw_err(S, YASL_DIVIDE_BY_ZERO_ERROR);
	}

	mp_int *value = init_bigint(S);

	int result = mp_div(left, right, NULL, value);
	if (result) {
		YASL_print_err(S, "Error performing arithmetic: %s", mp_error_to_string(result));
		YASL_throw_err(S, YASL_ERROR);
	}

	YASL_pushbigint(S, value);

	return 1;
}

static int YASL_bigint___pow(struct YASL_State *S) {
	mp_int *base = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.__pow", 0);
	yasl_int exponent = YASLX_checknint(S, "bigint.__pow", 1);

	if (exponent < 0) {
		YASL_print_err(S, "Invalid exponent given: %li", exponent);
		YASL_throw_err(S, YASL_VALUE_ERROR);
	}
	if (exponent > MAX_UINT32) {
		YASL_print_err(S, "Exponent was not smaller than 2^32: %li", exponent);
		YASL_throw_err(S, YASL_VALUE_ERROR);
	}

	mp_int *value = init_bigint(S);

	int result = mp_expt_u32(base, (uint32_t)exponent, value);
	if (result) {
		YASL_print_err(S, "Error performing arithmetic: %s", mp_error_to_string(result));
		YASL_throw_err(S, YASL_ERROR);
	}

	YASL_pushbigint(S, value);

	return 1;
}

static int YASL_bigint___bshl(struct YASL_State *S) {
	mp_int *left = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.__bshl", 0);
	yasl_int right = YASLX_checknint(S, "bigint.__bshl", 1);

	mp_int *value = init_bigint(S);

	int result = mp_mul_2d(left, right, value);
	if (result) {
		YASL_print_err(S, "Error performing arithmetic: %s", mp_error_to_string(result));
		YASL_throw_err(S, YASL_ERROR);
	}

	YASL_pushbigint(S, value);

	return 1;
}

static int YASL_bigint___bshr(struct YASL_State *S) {
	mp_int *left = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.__bshr", 0);
	yasl_int right = YASLX_checknint(S, "bigint.__bshr", 1);

	mp_int *value = init_bigint(S);

	int result = mp_div_2d(left, right, value, NULL);
	if (result) {
		YASL_print_err(S, "Error performing arithmetic: %s", mp_error_to_string(result));
		YASL_throw_err(S, YASL_ERROR);
	}

	YASL_pushbigint(S, value);

	return 1;
}

int YASL_load_dyn_lib(struct YASL_State *S) {
	YASL_pushtable(S);
	YASL_registermt(S, BIGINT_NAME);

	YASL_loadmt(S, BIGINT_NAME);

	YASL_pushlit(S, "tostr");
	YASL_pushcfunction(S, YASL_bigint_tostr, 1);
	YASL_tableset(S);

	YASL_pushlit(S, "iszero");
	YASL_pushcfunction(S, YASL_bigint_iszero, 1);
	YASL_tableset(S);

	YASL_pushlit(S, "iseven");
	YASL_pushcfunction(S, YASL_bigint_iseven, 1);
	YASL_tableset(S);

	YASL_pushlit(S, "isodd");
	YASL_pushcfunction(S, YASL_bigint_isodd, 1);
	YASL_tableset(S);

	YASL_pushlit(S, "isprime");
	YASL_pushcfunction(S, YASL_bigint_isprime, 1);
	YASL_tableset(S);

	YASL_pushlit(S, "log_n");
	YASL_pushcfunction(S, YASL_bigint_log_n, 2);
	YASL_tableset(S);

	YASL_pushlit(S, "__neg");
	YASL_pushcfunction(S, YASL_bigint___neg, 1);
	YASL_tableset(S);

	YASL_pushlit(S, "__pos");
	YASL_pushcfunction(S, YASL_bigint___pos, 1);
	YASL_tableset(S);

	YASL_pushlit(S, "__add");
	YASL_pushcfunction(S, YASL_bigint___add, 2);
	YASL_tableset(S);

	YASL_pushlit(S, "__sub");
	YASL_pushcfunction(S, YASL_bigint___sub, 2);
	YASL_tableset(S);

	YASL_pushlit(S, "__idiv");
	YASL_pushcfunction(S, YASL_bigint___idiv, 2);
	YASL_tableset(S);

	YASL_pushlit(S, "__mod");
	YASL_pushcfunction(S, YASL_bigint___mod, 2);
	YASL_tableset(S);

	YASL_pushlit(S, "__mul");
	YASL_pushcfunction(S, YASL_bigint___mul, 2);
	YASL_tableset(S);

	YASL_pushlit(S, "__pow");
	YASL_pushcfunction(S, YASL_bigint___pow, 2);
	YASL_tableset(S);

	YASL_pushlit(S, "__band");
	YASL_pushcfunction(S, YASL_bigint___band, 2);
	YASL_tableset(S);

	YASL_pushlit(S, "__bor");
	YASL_pushcfunction(S, YASL_bigint___bor, 2);
	YASL_tableset(S);

	YASL_pushlit(S, "__bxor");
	YASL_pushcfunction(S, YASL_bigint___bxor, 2);
	YASL_tableset(S);

	YASL_pushlit(S, "__bshl");
	YASL_pushcfunction(S, YASL_bigint___bshl, 2);
	YASL_tableset(S);

	YASL_pushlit(S, "__bshr");
	YASL_pushcfunction(S, YASL_bigint___bshr, 2);
	YASL_tableset(S);

	YASL_pushlit(S, "__lt");
	YASL_pushcfunction(S, YASL_bigint___lt, 2);
	YASL_tableset(S);

	YASL_pushlit(S, "__le");
	YASL_pushcfunction(S, YASL_bigint___le, 2);
	YASL_tableset(S);

	YASL_pushlit(S, "__gt");
	YASL_pushcfunction(S, YASL_bigint___gt, 2);
	YASL_tableset(S);

	YASL_pushlit(S, "__ge");
	YASL_pushcfunction(S, YASL_bigint___ge, 2);
	YASL_tableset(S);

	YASL_pushlit(S, "__eq");
	YASL_pushcfunction(S, YASL_bigint___eq, 2);
	YASL_tableset(S);

	YASL_pushtable(S);

	YASL_pushtable(S);
	YASL_pushlit(S, "__call");
	YASL_pushcfunction(S, YASL_bigint_bigint, 1);
	YASL_tableset(S);
	YASL_setmt(S);

	// libTomMath utilities exposed
	YASL_pushlit(S, "kronecker");
	YASL_pushcfunction(S, YASL_bigint_kronecker, 2);
	YASL_tableset(S);

	YASL_pushlit(S, "gcd");
	YASL_pushcfunction(S, YASL_bigint_gcd, 2);
	YASL_tableset(S);

	YASL_pushlit(S, "lcm");
	YASL_pushcfunction(S, YASL_bigint_lcm, 2);
	YASL_tableset(S);

	YASL_pushlit(S, "pow");
	YASL_pushcfunction(S, YASL_bigint___pow, 2);
	YASL_tableset(S);

	YASL_pushlit(S, "powmod");
	YASL_pushcfunction(S, YASL_bigint_powmod, 3);
	YASL_tableset(S);

	YASL_pushlit(S, "log_n");
	YASL_pushcfunction(S, YASL_bigint_log_n, 2);
	YASL_tableset(S);

	YASL_pushlit(S, "__VERSION__");\
	YASL_pushlit(S, BIGINT_VERSION);
	YASL_tableset(S);

	return 1;
}
