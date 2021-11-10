#include <string.h>
#include "erl_nif.h"
#include "psa/crypto.h"

typedef struct
{
    psa_status_t val;
    char* str;
} psa_status_str_t;

/* https://gcc.gnu.org/onlinedocs/cpp/Stringizing.html
There is no way to convert a macro argument into a character constant. */
static psa_status_str_t psa_status_str[] =
{
    {PSA_SUCCESS, "PSA_SUCCESS"},
    {PSA_ERROR_BAD_STATE, "PSA_ERROR_BAD_STATE"},
    {PSA_ERROR_INVALID_ARGUMENT, "PSA_ERROR_INVALID_ARGUMENT"},
    {PSA_ERROR_INSUFFICIENT_MEMORY, "PSA_ERROR_INSUFFICIENT_MEMORY"},
    {PSA_ERROR_DOES_NOT_EXIST, "PSA_ERROR_DOES_NOT_EXIST"},
    {PSA_ERROR_INVALID_HANDLE, "PSA_ERROR_INVALID_HANDLE"},
    {PSA_ERROR_ALREADY_EXISTS, "PSA_ERROR_ALREADY_EXISTS"},
    {PSA_ERROR_NOT_PERMITTED, "PSA_ERROR_NOT_PERMITTED"}
};

typedef struct
{
    psa_key_type_t val;
    char* str;
} psa_key_type_str_t;

static psa_key_type_str_t psa_key_type_str[] =
{
    {PSA_KEY_TYPE_NONE, "PSA_KEY_TYPE_NONE"},
    {PSA_KEY_TYPE_AES, "PSA_KEY_TYPE_AES"}
};

typedef struct
{
    psa_algorithm_t val;
    char* str;
} psa_algorithm_str_t;

static psa_algorithm_str_t psa_algorithm_str[] =
{
    //{PSA_ALG_NONE, "PSA_ALG_NONE"}, Not defined in MbedTLS 3.0.0.
    {PSA_ALG_CBC_NO_PADDING, "PSA_ALG_CBC_NO_PADDING"}
};

typedef struct
{
    psa_key_usage_t val;
    char* str;
} psa_key_usage_str_t;

static psa_key_usage_str_t psa_key_usage_str[] =
{
    {PSA_KEY_USAGE_EXPORT, "PSA_KEY_USAGE_EXPORT"},
    {PSA_KEY_USAGE_COPY, "PSA_KEY_USAGE_COPY"},
    //{PSA_KEY_USAGE_CACHE, "PSA_KEY_USAGE_CACHE"}, Not defined in MbedTLS 3.0.0.
    {PSA_KEY_USAGE_ENCRYPT, "PSA_KEY_USAGE_ENCRYPT"},
    {PSA_KEY_USAGE_DECRYPT, "PSA_KEY_USAGE_DECRYPT"}
};

static ERL_NIF_TERM psa_error_atom(ErlNifEnv* env, psa_status_t status)
{
    int size = sizeof(psa_status_str)/sizeof(psa_status_str[0]);
    for (int i=0; i<size; i++)
    {
        if (psa_status_str[i].val == status)
        {
            return enif_make_atom(env, psa_status_str[i].str);
        }
    }
    return enif_make_int(env, status);
}

static ERL_NIF_TERM psa_error_tuple(ErlNifEnv* env, psa_status_t status)
{
    return enif_make_tuple2(env, enif_make_atom(env, "error"), psa_error_atom(env, status));
}

static ERL_NIF_TERM psa_crypto_init_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    psa_status_t status;
    status = psa_crypto_init();
    return (status == PSA_SUCCESS ? enif_make_atom(env, "ok"): psa_error_tuple(env, status));
}

static ERL_NIF_TERM psa_key_attributes_init_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    psa_key_attributes_t* key_attr = malloc(sizeof(psa_key_attributes_t));
    *key_attr = psa_key_attributes_init();
    enif_make_uint64(env, (ErlNifUInt64)key_attr);
}

static ERL_NIF_TERM psa_generate_random_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifUInt64 output_size;
    ErlNifBinary output;
    psa_status_t status;

    if (!enif_get_uint64(env, argv[0], &output_size)) return enif_make_badarg(env);
    if (!enif_alloc_binary(output_size, &output)) return enif_make_atom(env, "no_mem");
    status = psa_generate_random(output.data, output_size);
    return (status == PSA_SUCCESS ? enif_make_binary(env, &output): psa_error_tuple(env, status));
}

static ERL_NIF_TERM psa_reset_key_attributes_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifUInt64 attr_ptr;

    if (!enif_get_uint64(env, argv[0], &attr_ptr)) return enif_make_badarg(env);
    psa_reset_key_attributes((psa_key_attributes_t*)attr_ptr);
    return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM psa_set_key_id_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifUInt64 attr_ptr, id;

    if (!enif_get_uint64(env, argv[0], &attr_ptr)) return enif_make_badarg(env);
    if (!enif_get_uint64(env, argv[1], &id)) return enif_make_badarg(env);
    psa_set_key_id((psa_key_attributes_t*)attr_ptr, (psa_key_id_t)id);
    return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM psa_get_key_id_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifUInt64 attr_ptr;
    psa_key_id_t id;

    if (!enif_get_uint64(env, argv[0], &attr_ptr)) return enif_make_badarg(env);
    id = psa_get_key_id((psa_key_attributes_t*)attr_ptr);
    return enif_make_int(env, id);
}

static ERL_NIF_TERM psa_set_key_bits_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifUInt64 attr_ptr, bits;

    if (!enif_get_uint64(env, argv[0], &attr_ptr)) return enif_make_badarg(env);
    if (!enif_get_uint64(env, argv[1], &bits)) return enif_make_badarg(env);
    psa_set_key_bits((psa_key_attributes_t*)attr_ptr, (size_t)bits);
    return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM psa_get_key_bits_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifUInt64 attr_ptr;
    size_t bits;

    if (!enif_get_uint64(env, argv[0], &attr_ptr)) return enif_make_badarg(env);
    bits = psa_get_key_bits((psa_key_attributes_t*)attr_ptr);
    return enif_make_int(env, bits);
}

static ERL_NIF_TERM psa_set_key_usage_flags_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifUInt64 attr_ptr, usage_flags;

    if (!enif_get_uint64(env, argv[0], &attr_ptr)) return enif_make_badarg(env);
    if (!enif_get_uint64(env, argv[1], &usage_flags)) return enif_make_badarg(env);

    psa_set_key_usage_flags((psa_key_attributes_t*)attr_ptr, (psa_key_usage_t)usage_flags);
    return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM psa_get_key_usage_flags_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    return enif_make_atom(env, ":not_implemented");
}

static ERL_NIF_TERM psa_set_key_algorithm_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifUInt64 attr_ptr, algorithm;

    if (!enif_get_uint64(env, argv[0], &attr_ptr)) return enif_make_badarg(env);
    if (!enif_get_uint64(env, argv[1], &algorithm)) return enif_make_badarg(env);
    psa_set_key_algorithm((psa_key_attributes_t*)attr_ptr, (psa_algorithm_t)algorithm);
    return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM psa_get_key_algorithm_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    return enif_make_atom(env, ":not_implemented");
}

static ERL_NIF_TERM psa_set_key_type_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifUInt64 attr_ptr, type;

    if (!enif_get_uint64(env, argv[0], &attr_ptr)) return enif_make_badarg(env);
    if (!enif_get_uint64(env, argv[1], &type)) return enif_make_badarg(env);
    psa_set_key_type((psa_key_attributes_t*)attr_ptr, (psa_key_type_t)type);
    return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM psa_get_key_type_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    return enif_make_atom(env, ":not_implemented");
}

static ERL_NIF_TERM psa_get_key_attributes_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    psa_status_t status;
    ErlNifUInt64 key;
    ErlNifUInt64 attr_ptr;

    if (!enif_get_uint64(env, argv[0], &key)) return enif_make_badarg(env);
    if (!enif_get_uint64(env, argv[1], &attr_ptr)) return enif_make_badarg(env);

    status = psa_get_key_attributes((psa_key_id_t)key, (psa_key_attributes_t*)attr_ptr);
    return (status == PSA_SUCCESS ? enif_make_atom(env, "ok"): psa_error_tuple(env, status));
}


static ERL_NIF_TERM psa_generate_key_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    psa_status_t status;
    ErlNifUInt64 attr_ptr;
    psa_key_id_t key;

    if (!enif_get_uint64(env, argv[0], &attr_ptr)) return enif_make_badarg(env);
    status = psa_generate_key((psa_key_attributes_t*)attr_ptr, &key);
    return (status == PSA_SUCCESS ? enif_make_int(env, key): psa_error_tuple(env, status));
}

static ERL_NIF_TERM psa_import_key_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    psa_status_t status;
    ErlNifUInt64 attr_ptr;
    ErlNifBinary data;
    psa_key_id_t key;

    if (!enif_get_uint64(env, argv[0], &attr_ptr)) return enif_make_badarg(env);
    if (!enif_inspect_binary(env, argv[1], &data)) return enif_make_badarg(env);
    status = psa_import_key((psa_key_attributes_t*)attr_ptr, data.data, data.size, &key);
    return (status == PSA_SUCCESS ? enif_make_int(env, key): psa_error_tuple(env, status));
}

static ERL_NIF_TERM psa_copy_key_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    psa_status_t status;
    ErlNifUInt64 attr_ptr, source_key;
    psa_key_id_t key;

    if (!enif_get_uint64(env, argv[0], &source_key)) return enif_make_badarg(env);
    if (!enif_get_uint64(env, argv[1], &attr_ptr)) return enif_make_badarg(env);
    status = psa_copy_key((psa_key_id_t)source_key, (psa_key_attributes_t*)attr_ptr, &key);
    return (status == PSA_SUCCESS ? enif_make_int(env, key): psa_error_tuple(env, status));
}
/* ----- PSA values converters ----- */
static ERL_NIF_TERM val_psa_key_type_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    char atom_buf[30]; // should fit all psa_key_type_t names

    if (!enif_get_atom(env, argv[0], atom_buf, sizeof(atom_buf), ERL_NIF_LATIN1)) return enif_make_badarg(env);

    int size = sizeof(psa_key_type_str)/sizeof(psa_key_type_str[0]);
    for (int i=0; i<size; i++)
    {
        if (strcmp(psa_key_type_str[i].str, atom_buf) == 0)
        {
            return enif_make_int(env, psa_key_type_str[i].val);
        }
    }
    return enif_make_atom(env, "not_found");
}

static ERL_NIF_TERM val_psa_key_usage_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    char atom_buf[30]; // should fit all psa_key_usage_t names

    if (!enif_get_atom(env, argv[0], atom_buf, sizeof(atom_buf), ERL_NIF_LATIN1)) return enif_make_badarg(env);

    int size = sizeof(psa_key_usage_str)/sizeof(psa_key_usage_str[0]);
    for (int i=0; i<size; i++)
    {
        if (strcmp(psa_key_usage_str[i].str, atom_buf) == 0)
        {
            return enif_make_int(env, psa_key_usage_str[i].val);
        }
    }
    return enif_make_atom(env, "not_found");
}

static ERL_NIF_TERM val_psa_algorithm_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    char atom_buf[30]; // should fit all psa_algorithm_t names

    if (!enif_get_atom(env, argv[0], atom_buf, sizeof(atom_buf), ERL_NIF_LATIN1)) return enif_make_badarg(env);

    int size = sizeof(psa_algorithm_str)/sizeof(psa_algorithm_str[0]);
    for (int i=0; i<size; i++)
    {
        if (strcmp(psa_algorithm_str[i].str, atom_buf) == 0)
        {
            return enif_make_int(env, psa_algorithm_str[i].val);
        }
    }
    return enif_make_atom(env, "not_found");
}


/* ----- Other MbedTLS functions ----- */
static ERL_NIF_TERM mbedtls_psa_crypto_free_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    mbedtls_psa_crypto_free();
    return enif_make_atom(env, "ok");
}

/* ----- Aux. functions start ----- */
static ERL_NIF_TERM free_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifUInt64 ptr;

    if (!enif_get_uint64(env, argv[0], &ptr)) return enif_make_badarg(env);
    free((void*)ptr);
    return enif_make_atom(env, "ok");
}
/* ----- Aux. functions end ----- */

static ErlNifFunc nif_funcs[] =
{
    {"psa_crypto_init", 0, psa_crypto_init_nif},
    {"psa_key_attributes_init", 0, psa_key_attributes_init_nif},
    {"psa_generate_random", 1, psa_generate_random_nif},
    {"psa_reset_key_attributes", 1, psa_reset_key_attributes_nif},
    {"psa_set_key_id", 2, psa_set_key_id_nif},
    {"psa_get_key_id", 1, psa_get_key_id_nif},
    {"psa_set_key_bits", 2, psa_set_key_bits_nif},
    {"psa_get_key_bits", 1, psa_get_key_bits_nif},
    {"psa_set_key_usage_flags", 2, psa_set_key_usage_flags_nif},
    {"psa_get_key_usage_flags", 1, psa_set_key_usage_flags_nif},
    {"psa_set_key_algorithm", 2, psa_set_key_algorithm_nif},
    {"psa_get_key_algorithm", 1, psa_get_key_algorithm_nif},
    {"psa_set_key_type", 2, psa_set_key_type_nif},
    {"psa_get_key_type", 1, psa_get_key_type_nif},
    {"psa_get_key_attributes", 2, psa_get_key_attributes_nif},
    {"psa_generate_key", 1, psa_generate_key_nif},
    {"psa_import_key", 2, psa_import_key_nif},
    {"psa_copy_key", 2, psa_copy_key_nif},
    {"val_psa_key_type", 1, val_psa_key_type_nif},
    {"val_psa_key_usage", 1, val_psa_key_usage_nif},
    {"val_psa_algorithm", 1, val_psa_algorithm_nif},
    {"mbedtls_psa_crypto_free", 0, mbedtls_psa_crypto_free_nif},
    {"free", 1, free_nif}
};

ERL_NIF_INIT(Elixir.MbedTLS, nif_funcs, NULL, NULL, NULL, NULL)
