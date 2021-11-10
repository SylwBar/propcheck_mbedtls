MBEDTLS_PATH=mbedtls
ERL_INCLUDE_PATH=$(shell erl -eval 'io:format("~s~n", [lists:concat([code:root_dir(), "/erts-", erlang:system_info(version), "/include"])])' -s init stop -noshell)
UNAME := $(shell uname)

ifeq ($(UNAME), Linux)
	CC := gcc
	CFLAGS := -shared -fpic
endif

all: priv/mbedtls.so

priv/mbedtls.so: c_src/mbedtls_nif.c
	mkdir -p priv
	$(CC) $(CFLAGS) -std=c99 -O3 -I$(ERL_INCLUDE_PATH) -I$(MBEDTLS_PATH)/include c_src/mbedtls*.c $(MBEDTLS_PATH)/library/libmbedcrypto.a -o priv/mbedtls.so

clean:
	rm -rf priv/mbedtls.so
