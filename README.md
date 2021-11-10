# propcheck_mbedtls
Property based testing for PSA cryptography API

## Compiling MbedTLS

    $ git submodule init
    $ git submodule update
    $ cd mbedtls
    $ SHARED=1 CFLAGS=-DPSA_ITS_STORAGE_PREFIX=\\\"/tmp/\\\" make lib
    $ cd ..

## Compiling Propcheck MbedTLS

    $ mix deps.get
    $ mix compile

## Executing tests

    $ iex -S mix
    
    iex()> PCMbedTLS.start
    ....................................................................................................
    OK: Passed 100 test(s).
    
    12.15% {PSASetKeyType, :exec, 2}
    11.75% {PSASetKeyId, :exec, 2}
    11.04% {PSAResetKeyAttributes, :exec, 1}
    10.74% {PSASetKeyUsageFlags, :exec, 2}
    10.34% {PSASetKeyBits, :exec, 2}
     9.54% {PSASetKeyAlgorithm, :exec, 2}
     8.63% {PSACryptoInit, :exec, 0}
     8.13% {PSAGenerateRandom.Fail, :exec, 1}
     5.22% {PSAGenerateRandom.Success, :exec, 1}
     5.12% {PowerCycle, :exec, 1}
     3.82% {PSAKeyAttributesInit, :exec, 0}
     2.71% {PSAGetKeyId, :exec, 1}
     0.40% {PSAGenerateKey.Persistent.PSA_ERROR_ALREADY_EXISTS, :exec, 1}
     0.20% {PSAGenerateKey.Persistent.Success, :exec, 1}
     0.20% {PSAGetKeyAttributes, :exec, 1}
    true

## Verbose output
Edit lib/pc_mbedtls.ex: set @trace to true and recompile.

    iex()> recompile
    iex()> PCMbedTLS.start

Example test:

    .--------- Test ---------
    psa_set_key_bits(128) => ok
    psa_reset_key_attributes() => ok
    psa_set_key_bits(128) => ok
    psa_crypto_init() => ok
    psa_set_key_bits(128) => ok
    psa_set_key_usage_flags([encrypt: true, decrypt: true, copy: false]) => ok
    psa_reset_key_attributes() => ok
    psa_set_key_bits(128) => ok
    power cycle => ok
    psa_generate_random(48) => {:error, :PSA_ERROR_BAD_STATE}
    psa_crypto_init() => ok
    psa_generate_random(33) => binary:33
    psa_generate_random(3) => binary:3
    psa_key_attributes_init() => 0x7F7A3423AE50
    psa_reset_key_attributes() => ok
    psa_set_key_usage_flags([encrypt: true, decrypt: true, copy: false]) => ok
    psa_set_key_usage_flags([encrypt: true, decrypt: true, copy: true]) => ok
    power cycle => ok
    psa_key_attributes_init() => 0x7F7A3423AE50
    psa_set_key_type(PSA_KEY_TYPE_AES) => ok
    psa_set_key_type(PSA_KEY_TYPE_AES) => ok
    psa_set_key_bits(128) => ok
    psa_crypto_init() => ok
    psa_set_key_usage_flags([encrypt: true, decrypt: true, copy: false]) => ok
    psa_reset_key_attributes() => ok
    power cycle => ok
    psa_key_attributes_init() => 0x7F7A3423AE50
    psa_set_key_bits(128) => ok
    psa_crypto_init() => ok
    psa_set_key_bits(128) => ok
    psa_set_key_type(PSA_KEY_TYPE_AES) => ok
    psa_set_key_algorithm(PSA_ALG_CBC_NO_PADDING) => ok



