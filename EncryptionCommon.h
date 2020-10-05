#ifndef ENCRYPTIONCOMMON_H
#define ENCRYPTIONCOMMON_H

#include <algorithm>
#include <array>
#include <cassert>
#include <sodium/crypto_core_ristretto255.h>
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
EcScalar make_secret(std::string_view password);

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

EcScalar make_zkp_challenge(const EcPoint& V,
                            const EcPoint& pubkey,
                            std::string_view user_id,
                            const EcPoint& generator);

/// If it fails, it returns an empty struct.
struct zkp make_zkp(std::string_view user_id,
                    const EcScalar& privkey,
                    const EcPoint& pubkey,
                    const EcPoint& generator);

/// \param pubkey Public key used in generating \e zkp.
/// \param expected_id Id of the user that made \e zkp.
/// \param this_user_id Id of the user that checks \e zkp.
/// \param generator Generator used to make \e zkp.
bool check_zkp(const struct zkp& zkp,
               const EcPoint& pubkey,
               std::string_view expected_id,
               std::string_view this_user_id,
               const EcPoint& generator = basepoint);

/// Generate a tuple with private key, public key and the zero knowledge proof
/// for them.
std::tuple<EcScalar, EcPoint, zkp>
generate_keypair(std::string_view id, const EcPoint& generator = basepoint);

HmacHash make_key_confirmation(const HmacKey& key,
                               std::string_view peer1_id,
                               const EcPoint& peer1_pubkey1,
                               const EcPoint& peer1_pubkey2,
                               std::string_view peer2_id,
                               const EcPoint& peer2_pubkey1,
                               const EcPoint& peer2_pubkey2);

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
