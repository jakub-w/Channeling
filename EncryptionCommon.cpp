// Copyright (C) 2020 by Jakub Wojciech

// This file is part of Channeling

// Lelo Remote Music Player is free software: you can redistribute it
// and/or modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.

// Lelo Remote Music Player is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the implied warranty
// of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Lelo Remote Music Player. If not, see
// <https://www.gnu.org/licenses/>.

#include "EncryptionCommon.h"

namespace Channeling {
EcScalar make_secret(std::string_view password) {
  static_assert(sizeof(decltype(password)::value_type) == sizeof(byte));

  // std::array<byte, crypto_core_ristretto255_NONREDUCEDSCALARBYTES> hash;
  std::array<byte, crypto_core_ristretto255_HASHBYTES> hash;
  std::array<byte, crypto_core_ristretto255_SCALARBYTES> result;

  // H(p)
  crypto_generichash(hash.data(), hash.size(),
                     reinterpret_cast<const byte*>(password.data()),
                     password.length(),
                     nullptr, 0);

  // mod L
  // crypto_core_ristretto255_scalar_reduce(result.data(), hash.data());
  crypto_core_ristretto255_from_hash(result.data(), hash.data());

  // // s = H(p)^2
  // crypto_core_ristretto255_scalar_mul(result.data(),
  //                                     result.data(), result.data());

  sodium_memzero(hash.data(), hash.size());
  return result;
}

EcScalar make_zkp_challenge(const EcPoint& V,
                            const EcPoint& pubkey,
                            std::string_view user_id,
                            const EcPoint& generator) {
  static_assert(sizeof(decltype(user_id)::value_type) == sizeof(byte));

  // challenge: H(gen || V || pubkey || user_id)
  std::array<byte, crypto_core_ristretto255_HASHBYTES> hash;
  crypto_generichash_state state;
  // TODO: Probably use some kind of a key for hashing, it can be just a
  //       static salt.
  crypto_generichash_init(&state, nullptr, 0, hash.size());

  crypto_generichash_update(&state, generator.data(), generator.size());
  crypto_generichash_update(&state, V.data(), V.size());
  crypto_generichash_update(&state, pubkey.data(), pubkey.size());
  crypto_generichash_update(&state,
                            reinterpret_cast<const byte*>(user_id.data()),
                            user_id.size());
  crypto_generichash_final(&state, hash.data(), hash.size());

  EcScalar c;
  crypto_core_ristretto255_from_hash(c.data(), hash.data());

  return c;
}

struct zkp make_zkp(std::string_view user_id,
                           const EcScalar& privkey,
                           const EcPoint& pubkey,
                           const EcPoint& generator) {
  static_assert(sizeof(decltype(user_id)::value_type) == sizeof(byte));

  zkp zkp;
  zkp.user_id = user_id;

  // random number
  EcScalar v; // FIXME: depending on this number the test fails or passes
  crypto_core_ristretto255_scalar_random(v.data());

  // V = G x [v]
  if (crypto_scalarmult_ristretto255(zkp.V.data(), v.data(), generator.data())
      != 0) {
    return {};
  }
  // crypto_scalarmult_ristretto255_base(zkp.V.data(), v.data());

  // challenge: H(gen || V || pubkey || user_id)
  EcScalar c = make_zkp_challenge(zkp.V, pubkey, user_id, generator);

  // challenge response (r)
  // privkey * c
  crypto_core_ristretto255_scalar_mul(zkp.r.data(), privkey.data(), c.data());
  // TODO: Check if it's ok to make the input and output the same
  // v - (privkey * c)
  crypto_core_ristretto255_scalar_sub(zkp.r.data(), v.data(), zkp.r.data());

  return zkp;
  // TODO: Check the return values of libsodium functions.
}

bool check_zkp(const struct zkp& zkp,
               const EcPoint& pubkey,
               std::string_view expected_id,
               std::string_view this_user_id,
               const EcPoint& generator) {
  if (not crypto_core_ristretto255_is_valid_point(pubkey.data())) {
    return false;
  }
  // TODO: Check if verify checks if pubkey x [h] isn't the point at infinity.
  //       h is a cofactor of the subgroup over E(Fp) of prime order n.
  //       Does *_is_valid_point() already do it?
  if (not crypto_core_ristretto255_is_valid_point(zkp.V.data())) {
    return false;
  }
  if (not crypto_core_ristretto255_is_valid_point(generator.data())) {
    return false;
  }
  if (not std::any_of(zkp.r.begin(), zkp.r.end(),
                      [](byte b){ return b != 0; })) {
    return false;
  }
  if (zkp.user_id == this_user_id) {
    return false;
  }
  if (zkp.user_id != expected_id) {
    return false;
  }

  EcPoint V, temp;
  EcScalar c = make_zkp_challenge(zkp.V, pubkey, zkp.user_id, generator);

  // G x [r]
  // crypto_scalarmult_ristretto255_base(V.data(), zkp.r.data());
  if (crypto_scalarmult_ristretto255(V.data(), zkp.r.data(), generator.data())
      != 0) {
    return false;
  }
  // pubkey x [c]
  if (crypto_scalarmult_ristretto255(temp.data(), c.data(), pubkey.data())
      != 0) {
    return false;
  }
  // V = G x [r] + pubkey x [c]
  crypto_core_ristretto255_add(V.data(), V.data(), temp.data());

  return V == zkp.V;
}

std::tuple<EcScalar, EcPoint, zkp>
generate_keypair(std::string_view id, const EcPoint& generator) {
  assert(crypto_core_ristretto255_is_valid_point(generator.data()));
  assert(id.size() > 0);

  // FIXME: If id length is 0, it loops forever.

  EcScalar privkey;
  crypto_core_ristretto255_scalar_random(privkey.data());
  EcPoint pubkey;
  if (crypto_scalarmult_ristretto255(pubkey.data(), privkey.data(),
                                     generator.data())
      != 0) {
    return generate_keypair(id, generator);
  }
  zkp zkp = make_zkp(id, privkey, pubkey, generator);
  if (zkp.user_id.empty()) return generate_keypair(id, generator);

  return std::make_tuple(std::move(privkey),
                         std::move(pubkey),
                         std::move(zkp));
}

HmacHash make_key_confirmation(const HmacKey& key,
                               std::string_view peer1_id,
                               const EcPoint& peer1_pubkey1,
                               const EcPoint& peer1_pubkey2,
                               std::string_view peer2_id,
                               const EcPoint& peer2_pubkey1,
                               const EcPoint& peer2_pubkey2) {
  // HMAC(key, "KC_1_U" || peer1_id || peer2_id ||
  //      peer1_pubkey1 || peer1_pubkey2 || peer2_pubkey1 || peer2_pubkey2)
  crypto_auth_hmacsha512_state state;
  crypto_auth_hmacsha512_init(&state, key.data(), key.size());

  crypto_auth_hmacsha512_update(
      &state,
      reinterpret_cast<const byte*>(peer1_id.data()),
      peer1_id.size());

  crypto_auth_hmacsha512_update(
      &state,
      reinterpret_cast<const byte*>(peer2_id.data()),
      peer2_id.size());

  crypto_auth_hmacsha512_update(
      &state,
      peer1_pubkey1.data(),
      peer1_pubkey1.size());

  crypto_auth_hmacsha512_update(
      &state,
      peer1_pubkey2.data(),
      peer1_pubkey2.size());

  crypto_auth_hmacsha512_update(
      &state,
      peer2_pubkey1.data(),
      peer2_pubkey1.size());

  crypto_auth_hmacsha512_update(
      &state,
      peer2_pubkey2.data(),
      peer2_pubkey2.size());

  HmacHash hash;
  crypto_auth_hmacsha512_final(&state, hash.data());

  return hash;
}
}
