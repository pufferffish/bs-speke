#include "monocypher.h"
#include <string.h>

#define GENERATOR_MOD  "generator_mod"
#define SECRET_KEY_MOD "secret_key_mod"

typedef struct {
  char* server_id;
  char* username;
  char* password;

  uint8_t salt_mask[32];
  uint8_t ephemeral_key[32];
  uint8_t blinded_salt[32];

  uint8_t generator[32];
  uint8_t secret_key[32];
  uint8_t public_key[32];
} bs_speke_ctx;

void map_to_prime_order_point(uint8_t point[32], const uint8_t buffer[32]) {
  #define CLAMP "clamping constant"
  uint8_t clamp[32];
  crypto_blake2b(clamp, 32, CLAMP, strlen(CLAMP));
  crypto_elligator_map(point, buffer);
  // multiply by a clamped scalar to clear the cofactor
  crypto_x25519(point, clamp, point);
  #undef CLAMP
}

size_t bs_speke_size() {
  return sizeof(bs_speke_ctx);
}

void bs_speke_init(bs_speke_ctx* ctx, char* server_id, char* username, char* password, uint8_t entropy[64]) {
  ctx->server_id = server_id;
  ctx->username = username;
  ctx->password = password;
  memcpy(ctx->salt_mask, &entropy[0], 32);
  memcpy(ctx->ephemeral_key, &entropy[32], 32);
}

void bs_speke_get_salt(const bs_speke_ctx* ctx, uint8_t blinded_salt[32]) {
  uint8_t salt[32];
  uint8_t point[32];
  // hash password and server ID into salt
  crypto_blake2b_ctx blake2b;
  crypto_blake2b_init(&blake2b, 32);
  crypto_blake2b_update(&blake2b, ctx->server_id, strlen(ctx->server_id));
  crypto_blake2b_update(&blake2b, ctx->password, strlen(ctx->password));
  crypto_blake2b_final(&blake2b, salt);
  // convert salt to point
  map_to_prime_order_point(point, salt);
  // multiply salt by 1/r
  crypto_x25519_inverse(blinded_salt, ctx->salt_mask, point);
}

#define ARGON_BLOCKS 100000

int bs_speke_derive_secret(bs_speke_ctx* ctx, const uint8_t blinded_salt[32], uint8_t work_area[ARGON_BLOCKS*1024]) {
  // multiply salt by r to unmask it
  uint8_t salt[32];
  crypto_x25519(salt, ctx->salt_mask, blinded_salt);
  // check if we are trapped in a small subgroup
  uint8_t zeros[32];
  memset(zeros, 0, 32);
  if (crypto_verify32(zeros, salt) == 0) {
    return -1;
  }
  // mix server ID into salt
  uint8_t kdf_salt[64];
  crypto_blake2b_keyed(kdf_salt, 64, salt, 32, ctx->server_id, strlen(ctx->server_id));
  // perform KDF to derive secret
  crypto_argon2_config config = {
    .algorithm = CRYPTO_ARGON2_D,
    .nb_blocks = ARGON_BLOCKS,
    .nb_passes = 4,
    .nb_lanes  = 1
  };
  crypto_argon2_extras extras = {0};
  crypto_argon2_inputs inputs = {
    .pass = ctx->password,
    .pass_size = strlen(ctx->password),
    .salt = kdf_salt,
    .salt_size = 64,
  };

  uint8_t secret[64];
  crypto_argon2(secret, 64, work_area, config, inputs, extras);

  // derive generator and secret key
  uint8_t generator[32];
  crypto_blake2b_keyed(generator, 32, secret, 64, GENERATOR_MOD, strlen(GENERATOR_MOD));
  crypto_blake2b_keyed(ctx->secret_key, 32, secret, 64, SECRET_KEY_MOD, strlen(SECRET_KEY_MOD));
  map_to_prime_order_point(ctx->generator, generator);
  crypto_x25519(ctx->public_key, ctx->secret_key, ctx->generator);
  if (crypto_verify32(zeros, ctx->public_key) == 0) {
    return -1;
  }
  return 0;
}

int bs_speke_register(bs_speke_ctx *ctx, uint8_t generator[32], uint8_t public_key[32]) {
  uint8_t zeros[32];
  memset(zeros, 0, 32);
  if (crypto_verify32(zeros, ctx->generator) == 0) {
    return -1;
  }
  if (crypto_verify32(zeros, ctx->public_key) == 0) {
    return -1;
  }

  memcpy(generator, ctx->generator, 32);
  memcpy(public_key, ctx->public_key, 32);
  return 0;
}

int bs_speke_login_key_exchange(bs_speke_ctx* ctx, uint8_t ephemeral_client_pk[32], uint8_t shared_key_material[64], const uint8_t ephemeral_server_pk[32]) {
  uint8_t secret[64];
  uint8_t zeros[32];
  memset(zeros, 0, 32);
  crypto_x25519(secret, ctx->ephemeral_key, ephemeral_server_pk);
  if (crypto_verify32(zeros, secret) == 0) {
    return -1;
  }
  crypto_x25519(&secret[32], ctx->secret_key, ephemeral_server_pk);
  if (crypto_verify32(zeros, &secret[32]) == 0) {
    return -1;
  }
  crypto_x25519(ephemeral_client_pk, ctx->ephemeral_key, ctx->generator);
  if (crypto_verify32(zeros, ephemeral_client_pk) == 0) {
    return -1;
  }

  crypto_blake2b_ctx blake2b;
  crypto_blake2b_keyed_init(&blake2b, 64, secret, 64);
  crypto_blake2b_update(&blake2b, ephemeral_client_pk, 32); // A
  crypto_blake2b_update(&blake2b, ctx->public_key, 32); // V
  crypto_blake2b_update(&blake2b, ctx->server_id, strlen(ctx->server_id)+1);
  crypto_blake2b_update(&blake2b, ctx->username, strlen(ctx->username)+1);
  crypto_blake2b_final(&blake2b, shared_key_material);
  return 0;
}