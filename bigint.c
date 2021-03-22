#include "yasl/yasl.h"
#include "yasl/yasl_aux.h"

#include "tommath.h"

static const char *BIGINT_NAME = "bigint";

int YASL_bigint_bigint(struct YASL_State *S) {
	if (!YASL_isnstr(S, 0)) {
		YASLX_print_err_bad_arg_type(S, "bigint.bigint", 0, BIGINT_NAME, YASL_peekntypename(S, 0));
		YASL_throw_err(S, YASL_TYPE_ERROR);
	}
	const char *str = YASL_popcstr(S);

	mp_int *value = malloc(sizeof(mp_int));
	int result = mp_init(value);
	if (result != MP_OKAY) {
		YASL_print_err(S, "Error creating bigint: %s", mp_error_to_string(result));
		YASL_throw_err(S, YASL_ERROR);
	}

	result = mp_read_radix(value, str, 10);
	if (result) {
		YASL_print_err(S, "Error creating bigint: %s", mp_error_to_string(result));
		YASL_throw_err(S, YASL_VALUE_ERROR);
	}

	YASL_pushuserdata(S, value, BIGINT_NAME, mp_clear);
	YASL_loadmt(S, BIGINT_NAME);
	YASL_setmt(S);

	return 1;
}

int YASL_bigint_tostr(struct YASL_State *S) {
	mp_int *v = YASLX_checknuserdata(S, BIGINT_NAME, "bigint.tostr", 0);

	int size;
	int result = mp_radix_size(v, 10, &size);

	char *buffer = malloc(size);

	mp_toradix(v, buffer, 10);

	YASL_pushlstr(S, buffer, size);

	free(buffer);

	return 1;
}

int YASL_load_dyn_lib(struct YASL_State *S) {
	YASL_pushtable(S);
	YASL_registermt(S, BIGINT_NAME);

	YASL_loadmt(S, BIGINT_NAME);
	YASL_pushlit(S, "tostr");
	YASL_pushcfunction(S, YASL_bigint_tostr, 1);
	YASL_tableset(S);
	YASL_pop(S);

	YASL_pushtable(S);

	YASL_pushlit(S, "bigint");
	YASL_pushcfunction(S, YASL_bigint_bigint, 1);
	YASL_tableset(S);

	return 1;
}
