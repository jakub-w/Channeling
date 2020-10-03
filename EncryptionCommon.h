#ifndef ENCRYPTIONCOMMON_H
#define ENCRYPTIONCOMMON_H

#include <algorithm>
#include <array>
#include <cassert>
#include <string>

#include <sodium.h>
#include <msgpack.hpp>

using byte = unsigned char;
using EcPoint = std::array<byte, crypto_core_ristretto255_BYTES>;
using EcScalar = std::array<byte, crypto_core_ristretto255_SCALARBYTES>;
using HmacHash = std::array<byte, crypto_auth_hmacsha512_BYTES>;
// FIXME: Make it a new class that will zero out the array's memory for
//        security reasons. Just a wrapper for std::array.
using HmacKey = std::array<byte, crypto_auth_hmacsha512_KEYBYTES>;

static const auto
NA_SS_ABYTES = crypto_secretstream_xchacha20poly1305_ABYTES;
static const auto
NA_SS_KEYBYTES = crypto_secretstream_xchacha20poly1305_KEYBYTES;
static const auto
NA_SS_HEADERBYTES = crypto_secretstream_xchacha20poly1305_HEADERBYTES;

// Asserts to ensure that libsodium isn't incompatible.
static_assert(crypto_core_ristretto255_SCALARBYTES ==
              crypto_core_ristretto255_BYTES);
static_assert(crypto_core_ristretto255_NONREDUCEDSCALARBYTES >=
              crypto_generichash_BYTES &&
              crypto_core_ristretto255_NONREDUCEDSCALARBYTES <=
              crypto_generichash_BYTES_MAX);

template<std::size_t N>
class safe_array {
  std::array<unsigned char, N> data_;

 public:
  typedef typename decltype(data_)::value_type value_type;
  typedef typename decltype(data_)::size_type size_type;
  typedef typename decltype(data_)::difference_type difference_type;
  typedef typename decltype(data_)::reference reference;
  typedef typename decltype(data_)::const_reference const_reference;
  typedef typename decltype(data_)::pointer pointer;
  typedef typename decltype(data_)::const_pointer const_pointer;
  typedef typename decltype(data_)::iterator iterator;
  typedef typename decltype(data_)::const_iterator const_iterator;
  typedef typename decltype(data_)::reverse_iterator reverse_iterator;
  typedef typename decltype(data_)::const_reverse_iterator
      const_reverse_iterator;

  // TODO: Make a normal constructor. Or test if implicitly created one is
  //       valid.

  safe_array(const safe_array& other) = delete;
  safe_array(safe_array&& other) : data_{std::move(other.data_)} {
    sodium_memzero(other.data_.data(), other.data_.size());
  }

  safe_array& operator=(const safe_array& other) = delete;
  safe_array& operator=(safe_array&& other) {
    std::move(other.data_.begin(), other.data_.end(), data_.begin());
    sodium_memzero(other.data_.data(), other.data_.size());

    return *this;
  }

  ~safe_array() {
    sodium_memzero(data_.data(), data_.size());
  }

  inline constexpr reference at(size_type pos) {
    return data_.at(pos);
  }
  inline constexpr const_reference at(size_type pos) const {
    return data_.at(pos);
  }

  inline constexpr reference operator[](size_type pos) {
    return data_[pos];
  }
  inline constexpr const_reference operator[](size_type pos) const {
    return data_[pos];
  }

  inline constexpr reference front() { return data_.front(); }
  inline constexpr const_reference front() const { return data_.front(); }

  inline constexpr reference back() { return data_.back(); }
  inline constexpr const_reference back() const { return data_.back(); }

  inline constexpr pointer data() noexcept {
    return data_.data();
  }
  inline constexpr const_pointer data() const noexcept {
    return data_.data();
  }

  inline constexpr iterator begin() noexcept {
    return data_.begin();
  }
  inline constexpr const_iterator begin() const noexcept {
    return data_.begin();
  }
  inline constexpr const_iterator cbegin() const noexcept {
    return data_.cbegin();
  }

  inline constexpr iterator end() noexcept {
    return data_.end();
  }
  inline constexpr const_iterator end() const noexcept {
    return data_.end();
  }
  inline constexpr const_iterator cend() const noexcept {
    return data_.cend();
  }

  inline constexpr reverse_iterator rbegin() noexcept {
    return data_.rbegin();
  }
  inline constexpr const_reverse_iterator rbegin() const noexcept {
    return data_.rbegin();
  }
  inline constexpr const_reverse_iterator crbegin() const noexcept {
    return data_.crbegin();
  }

  inline constexpr reverse_iterator rend() noexcept {
    return data_.rend();
  }
  inline constexpr const_reverse_iterator rend() const noexcept {
    return data_.rend();
  }
  inline constexpr const_reverse_iterator crend() const noexcept {
    return data_.crend();
  }

  inline constexpr bool empty() const noexcept {
    return data_.empty();
  }

  inline constexpr size_type size() const noexcept {
    return data_.size();
  }

  inline constexpr size_type max_size() const noexcept {
    return data_.max_size();
  }

  inline constexpr void fill(const_reference value) {
    return data_.fill(value);
  }

  inline constexpr void swap(safe_array& other) noexcept {
    return data_.swap(other.data_);
  }

};

struct zkp {
  std::string user_id;
  // V = G x [v], where v is a random number
  EcPoint V;
  // r = v - privkey * c, where c = H(gen || V || pubkey || user_id)
  EcScalar r;

  MSGPACK_DEFINE(user_id, V, r);
};

// TODO: Make it more sophisticated? Use crypto_pwhash() perhaps?
static EcScalar make_secret(std::string_view password) {
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

const static EcPoint basepoint =
    []{
      EcScalar identity = {1};
      EcPoint result;
      crypto_scalarmult_ristretto255_base(result.data(), identity.data());

      assert(std::any_of(result.begin(), result.end(),
                         [](byte b){ return b != 0; })
             && "Base point of ristretto255 seems to be 0");

      return result;
    }();

static EcScalar make_zkp_challenge(const EcPoint& V,
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

/// If it fails, it returns an empty struct.
static struct zkp make_zkp(std::string_view user_id,
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

/// \param pubkey Public key used in generating \e zkp.
/// \param expected_id Id of the user that made \e zkp.
/// \param this_user_id Id of the user that checks \e zkp.
/// \param generator Generator used to make \e zkp.
static bool check_zkp(const struct zkp& zkp,
                      const EcPoint& pubkey,
                      std::string_view expected_id,
                      std::string_view this_user_id,
                      const EcPoint& generator = basepoint) {
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

/// Generate a tuple with private key, public key and the zero knowledge proof
/// for them.
/// If
static std::tuple<EcScalar, EcPoint, zkp>
generate_keypair(std::string_view id, const EcPoint& generator = basepoint) {
  // TODO: Check if the privkeys are not 0.
  //       Probably done by libsodium already.
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

static HmacHash make_key_confirmation(const HmacKey& key,
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

// FIXME: Make the result type safe in crypto way (i.e. zeroing out memory).
template <size_t N>
static std::array<byte, N> make_key_confirmation_key(
    const EcPoint& key_material) {
  static_assert(crypto_kdf_KEYBYTES == sizeof(decltype(key_material)));

  const char context[crypto_kdf_CONTEXTBYTES] = "KC_KEY_";
  const uint64_t subkey_id = 1;

  std::array<byte, N> key;
  // BLAKE2B(key=key_material, message={},
  //         salt=subkey_id || {0},
  //         personal=context || {0})
  crypto_kdf_derive_from_key(
      key.data(), N, subkey_id, context, key_material.data());

  return key;
}

namespace {
template<class T>
static void derive_keys_internal(const EcPoint& key_material,
                                 uint64_t i, T& key) {
  const char context[crypto_kdf_CONTEXTBYTES] = "KC_KEY_";

  crypto_kdf_derive_from_key(
      key.data(), key.size(), i, context, key_material.data());
}

template<class T, class ...Ts>
static void derive_keys_internal(const EcPoint& key_material,
                                 uint64_t i, T& key, Ts&... rest) {
  const char context[crypto_kdf_CONTEXTBYTES] = "JW_KGEN";

  crypto_kdf_derive_from_key(
      key.data(), key.size(), i, context, key_material.data());

  if (sizeof...(rest)) {
    derive_keys_internal(key_material, i + 1, rest...);
  }
}
}

template<class ...Ts>
static void derive_keys(const EcPoint& key_material, Ts&... args) {
  static_assert(crypto_kdf_KEYBYTES == sizeof(decltype(key_material)));

  derive_keys_internal(key_material, 1, args...);
}

#endif /* ENCRYPTIONCOMMON_H */
