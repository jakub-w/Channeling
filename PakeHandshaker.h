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

#ifndef PAKEHANDSHAKER_H
#define PAKEHANDSHAKER_H

#include "Handshaker.h"

#include <algorithm>
#include <variant>

#include <zmq.hpp>

#include "EncryptionCommon.h"
#include "Logging.h"
#include "ProtocolCommon.h"
#include "Util.h"

// Uses J-PAKE algorithm
class PakeHandshaker : public Handshaker<PakeHandshaker> {
  // FIXME: Use a class based on std::array, but that zeroes its memory on
  //        move.
  using EncryptionKey = std::array<byte, NA_SS_KEYBYTES>;
  using NextResult = std::variant<PartialMessage,
                                  EncKeys,
                                  std::pair<PartialMessage, EncKeys>>;

  class Requester {
    struct loc_keys_generated {};
    struct all_received {
      std::string peer_id;
      EcPoint peer_pubkey1, peer_pubkey2;
      HmacKey kc_key;
      EncryptionKey enc_key, dec_key;
    };
    struct finished {};

    using State = std::variant<loc_keys_generated,
                               all_received,
                               finished>;
    State state_ = loc_keys_generated{};

   public:
    // id is the external socket id
    Requester(const std::string& id, const EcScalar& secret,
              // EcScalar&& privkey1, EcScalar&& privkey2,
              EcScalar&& privkey2,
              EcPoint&& pubkey1, EcPoint&& pubkey2)
        : id_{id},
          secret_{secret},
          // privkey1_{privkey1}, privkey2_{privkey2},
          privkey2_{privkey2},
          pubkey1_{pubkey1}, pubkey2_{pubkey2} {}

    NextResult Next(const char* data, std::size_t size) {
      return std::visit(
          overload{
            [&, data, size](loc_keys_generated&) -> NextResult {
              auto new_state = all_received{};
              std::size_t offset = 0;

              auto peer_pubkey1 = Unpack<EcPoint>(data, size, offset);
              auto peer_pubkey2 = Unpack<EcPoint>(data, size, offset);
              auto peer_pubkey3 = Unpack<EcPoint>(data, size, offset);
              auto peer_zkp1 = Unpack<zkp>(data, size, offset);
              auto peer_zkp2 = Unpack<zkp>(data, size, offset);
              auto peer_zkp3 = Unpack<zkp>(data, size, offset);

              if (not (peer_pubkey1 and peer_pubkey2 and peer_pubkey3 and
                       peer_zkp1 and peer_zkp2 and peer_zkp3)) {
                return pack_message_type(MessageType::BAD_MESSAGE);
              }

              new_state.peer_id = peer_zkp1.value().user_id;

              if (not (check_zkp(peer_zkp1.value(), peer_pubkey1.value(),
                                 new_state.peer_id, id_) and
                       check_zkp(peer_zkp2.value(), peer_pubkey2.value(),
                                 new_state.peer_id, id_))) {
                // TODO: Report denied request
                return pack_message_type(MessageType::DENY);
              }

              // Last zkp has a different generator.
              // G1 = pubkey1 + pubkey2 + peer_pubkey1
              EcPoint peer_zkp_gen;
              crypto_core_ristretto255_add(peer_zkp_gen.data(),
                                           pubkey1_.data(),
                                           pubkey2_.data());
              crypto_core_ristretto255_add(peer_zkp_gen.data(),
                                           peer_zkp_gen.data(),
                                           peer_pubkey1.value().data());
              if (not crypto_core_ristretto255_is_valid_point(
                      peer_zkp_gen.data())) {
                // TODO: Report denied request
                return pack_message_type(MessageType::DENY);
              }

              if (not check_zkp(peer_zkp3.value(), peer_pubkey3.value(),
                                new_state.peer_id, id_,
                                peer_zkp_gen)) {
                // TODO: Report denied request
                return pack_message_type(MessageType::DENY);
              }

              // Send pubkey3 and ZKP for it.
              // G2 = pubkey1 + peer_pubkey1 + peer_pubkey2
              EcPoint zkp_gen;
              crypto_core_ristretto255_add(zkp_gen.data(), pubkey1_.data(),
                                           peer_pubkey1.value().data());
              crypto_core_ristretto255_add(zkp_gen.data(), zkp_gen.data(),
                                           peer_pubkey2.value().data());
              // privkey3 = privkey2 * secret_
              EcScalar privkey3;
              crypto_core_ristretto255_scalar_mul(
                  privkey3.data(), privkey2_.data(), secret_.data());
              // pubkey3 = G2 * privkey3
              EcPoint pubkey3;
              if (-1 == crypto_scalarmult_ristretto255(
                      pubkey3.data(), privkey3.data(), zkp_gen.data())) {
                // TODO: This is a protocol error. Maybe don't just deny but
                //       rather tell the peer to drop the session and restart.
                return pack_message_type(MessageType::DENY);
              }

              const auto zkp3 = make_zkp(id_, privkey3, pubkey3, zkp_gen);

              // Compute the session key material
              // K = (peer_pubkey3 - (peer_pubkey2 x [privkey2 * secret_]))
              //         x [privkey2]
              auto key_material = make_key_material(
                  peer_pubkey3.value(), peer_pubkey2.value(),
                  privkey2_, secret_);
              if (not key_material) {
                // NOTE: This means that one of the scalar multiplications of
                //       a point in make_key_material() returned the zero
                //       element.
                // TODO: Report denied request
                return pack_message_type(MessageType::DENY);
              }

              // Key confirmation
              // Generate a signing key: k' = KDF(K || 1 || "JW_KGEN")
              // Generate encryption keys: EK = KDF(K || 2 || "JW_KGEN")
              //                           DK = KDF(K || 3 || "JW_KGEN")

              // The order of args is important! Note that dec_key and enc_key
              // are in an inverted order to the one in peer's version of the
              // algorithm.
              derive_keys(key_material.value(), new_state.kc_key,
                          new_state.enc_key, new_state.dec_key);

              const auto kc =
              make_key_confirmation(new_state.kc_key,
                                    id_, pubkey1_, pubkey2_,
                                    new_state.peer_id,
                                    peer_pubkey1.value(),
                                    peer_pubkey2.value());

              std::stringstream buffer;
              msgpack::pack(buffer, MessageType::AUTH);
              msgpack::pack(buffer, pubkey3);
              msgpack::pack(buffer, zkp3);
              msgpack::pack(buffer, kc);

              new_state.peer_pubkey1 = std::move(peer_pubkey1.value());
              new_state.peer_pubkey2 = std::move(peer_pubkey2.value());

              state_ = std::move(new_state);

              return buffer.str();
            },
            [&, data, size](all_received& context) -> NextResult {
              // TODO: Receive key confirmation data from peer.
              std::size_t offset = 0;

              const auto peer_kc = Unpack<HmacHash>(data, size, offset);

              const auto expected_peer_kc =
              make_key_confirmation(context.kc_key,
                                    context.peer_id,
                                    context.peer_pubkey1,
                                    context.peer_pubkey2,
                                    id_, pubkey1_, pubkey2_);
              if (peer_kc != expected_peer_kc) {
                // TODO: Report denied request
                return pack_message_type(MessageType::DENY);
              }

              auto result = EncKeys{
                std::move(context.enc_key), std::move(context.dec_key)};

              state_ = finished{};

              return result;
            },
            [](finished&) -> NextResult {
              return pack_message_type(MessageType::BAD_MESSAGE);
            }
          },
          state_);
    }

   private:
    const std::string id_;
    const EcScalar& secret_;

    EcScalar privkey2_;
    // EcScalar privkey1_, privkey2_;
    EcPoint pubkey1_, pubkey2_;
  };

  class Responder {
    struct start {};
    struct first_keys_received {};
    struct finished {};

    using State = std::variant<start,
                               first_keys_received,
                               finished>;
    State state_ = start{};

   public:
    Responder(const std::string& id, const EcScalar& secret)
        : id_{id},
          secret_{secret} {}

    NextResult Next(const char* data, std::size_t size) {
      return std::visit(
          overload{
            [&, data, size](start&) -> NextResult {
              // id_ = server_id_;

              std::size_t offset = 0;

              {
                auto peer_pubkey1 = Unpack<EcPoint>(data, size, offset);
                auto peer_pubkey2 = Unpack<EcPoint>(data, size, offset);
                auto peer_zkp1 = Unpack<zkp>(data, size, offset);
                auto peer_zkp2 = Unpack<zkp>(data, size, offset);

                if (not (peer_pubkey1 and peer_pubkey2 and
                         peer_zkp1 and peer_zkp2)) {
                  return pack_message_type(MessageType::BAD_MESSAGE);
                }

                peer_id_ = peer_zkp1.value().user_id;

                // TODO: These id_ references were client_id's, which were
                //       obtained from zmq's received message as a first frame
                if (not (check_zkp(peer_zkp1.value(), peer_pubkey1.value(),
                                   peer_id_, id_) and
                         check_zkp(peer_zkp2.value(), peer_pubkey2.value(),
                                   peer_id_, id_))) {
                  return pack_message_type(MessageType::DENY);
                }

                peer_pubkey1_ = std::move(peer_pubkey1.value());
                peer_pubkey2_ = std::move(peer_pubkey2.value());
              }

              // Generate new key-pairs and zkp's for them
              auto [privkey1, pubkey1, zkp1] = generate_keypair(id_);
              auto [privkey2, pubkey2, zkp2] = generate_keypair(id_);

              // Generate the last key-pair. This one is special:
              // G1 = peer_pubkey1 + peer_pubkey2 + pubkey1
              EcPoint zkp_gen;
              crypto_core_ristretto255_add(
                  zkp_gen.data(), peer_pubkey1_.data(), peer_pubkey2_.data());
              crypto_core_ristretto255_add(
                  zkp_gen.data(), zkp_gen.data(), pubkey1.data());
              // privkey3 = privkey2 * secret_
              EcScalar privkey3;
              crypto_core_ristretto255_scalar_mul(
                  privkey3.data(), privkey2.data(), secret_.data());
              // pubkey3 = G1 * privkey3
              EcPoint pubkey3;
              if (crypto_scalarmult_ristretto255(
                      pubkey3.data(), privkey3.data(), zkp_gen.data())
                  != 0) {
                return pack_message_type(MessageType::DENY);
              }

              const auto zkp3 =
              make_zkp(id_, privkey3, pubkey3, zkp_gen);

              privkey1_ = std::move(privkey1);
              pubkey1_ = std::move(pubkey1);
              privkey2_ = std::move(privkey2);
              pubkey2_ = std::move(pubkey2);
              privkey3_ = std::move(privkey3);
              pubkey3_ = std::move(pubkey3);

              std::stringstream buffer;
              // Build the message and send
              msgpack::pack(buffer, MessageType::AUTH);
              msgpack::pack(buffer, pubkey1_);
              msgpack::pack(buffer, pubkey2_);
              msgpack::pack(buffer, pubkey3_);
              msgpack::pack(buffer, zkp1);
              msgpack::pack(buffer, zkp2);
              msgpack::pack(buffer, zkp3);

              state_ = first_keys_received{};

              return buffer.str();
            },
            [&, data, size](first_keys_received&) -> NextResult {
              std::size_t offset = 0;

              auto peer_pubkey3 = Unpack<EcPoint>(data, size, offset);
              auto peer_zkp3 = Unpack<zkp>(data, size, offset);
              auto peer_kc = Unpack<HmacHash>(data, size, offset);

              if (not (peer_pubkey3 and peer_zkp3 and peer_kc)) {
                return pack_message_type(MessageType::BAD_MESSAGE);
              }

              // Verify
              // G2 = peer_pubkey1 + pubkey1 + pubkey2
              EcPoint peer_zkp_gen;
              crypto_core_ristretto255_add(peer_zkp_gen.data(),
                                           peer_pubkey1_.data(),
                                           pubkey1_.data());
              crypto_core_ristretto255_add(peer_zkp_gen.data(),
                                           peer_zkp_gen.data(),
                                           pubkey2_.data());
              if (not
                  (crypto_core_ristretto255_is_valid_point(
                      peer_zkp_gen.data()) and
                   check_zkp(
                       peer_zkp3.value(), peer_pubkey3.value(),
                       peer_id_, id_, peer_zkp_gen))) {
                return pack_message_type(MessageType::DENY);
              }

              // Compute the session key material
              // K = (peer_pubkey3 - (peer_pubkey2 x [privkey2 * secret_]))
              //         x [privkey2]
              auto key_material = make_key_material(
                  peer_pubkey3.value(), peer_pubkey2_,
                  privkey2_, secret_);
              if (not key_material) {
                // NOTE: This means that one of the scalar multiplications of
                //       a point in make_key_material() returned the zero
                //       element.
                // TODO: Report denied request
                return pack_message_type(MessageType::DENY);
              }

              // Key confirmation
              // Generate a signing key: k' = KDF(K || 1 || "JW_KGEN")
              HmacKey kc_key;
              // Generate an encryption keys: EK = KDF(K || 3 || "JW_KGEN")
              //                              DK = KDF(K || 2 || "JW_KGEN")

              CryptoKey enc_key, dec_key;
              // The order of args is important! Note that dec_key and enc_key
              // are in inverted order to the one in connect().
              derive_keys(key_material.value(), kc_key, dec_key, enc_key);

              // Verify the received key confirmation data.
              const auto expected_peer_kc =
              make_key_confirmation(
                  kc_key,
                  peer_id_, peer_pubkey1_, peer_pubkey2_,
                  id_, pubkey1_, pubkey2_);
              if (peer_kc != expected_peer_kc) {
                return pack_message_type(MessageType::DENY);
              }

              // Generate the key confirmation data
              const auto kc =
              make_key_confirmation(
                  kc_key,
                  id_, pubkey1_, pubkey2_,
                  peer_id_, peer_pubkey1_, peer_pubkey2_);

              std::stringstream buffer;

              // Build the message and send
              msgpack::pack(buffer, MessageType::AUTH);
              msgpack::pack(buffer, kc);

              state_ = finished{};

              return std::pair{
                buffer.str(),
                EncKeys{std::move(enc_key), std::move(dec_key)}};
            },
            [](finished&) -> NextResult {
              return pack_message_type(MessageType::BAD_MESSAGE);
            }
          },
          state_);
    }

    private:
    const std::string id_;
    const EcScalar& secret_;

    EcScalar privkey1_, privkey2_, privkey3_;
    EcPoint pubkey1_, pubkey2_, pubkey3_;
    EcPoint peer_pubkey1_, peer_pubkey2_;
    std::string peer_id_;
  };

 public:
  enum class Step {
    UNKNOWN = -1,
    NONE = 0,
    PKZKP_2,  // pubkey 1 and 2 with corresponding zkp's
    PKZKP_3,  // pubkey 1, 2 and 3 with corresponding zkp's
    PKZKP_KC, // pubkey 3 with the zkp and key confirmation
    KC        // key confirmation
  };

  // id will be used when the handshaker is on the server side.
  PakeHandshaker(std::shared_ptr<zmq::context_t> context,
                 std::string_view password)
      : ctx_{std::move(context)},
        socket_{*ctx_, ZMQ_PAIR},
        secret_{make_secret(password)},
        server_id_(5, ' ') {
    randombytes_buf(server_id_.data(), server_id_.length());
  }

  PakeHandshaker(const PakeHandshaker&) = delete;
  PakeHandshaker operator=(const PakeHandshaker&) = delete;

  ~PakeHandshaker() {
    Stop();
  }

  // id is the external socket id
  zmq::message_t GetAuthRequest(const std::string& id) {
    auto [privkey1, pubkey1, zkp1] = generate_keypair(id);
    auto [privkey2, pubkey2, zkp2] = generate_keypair(id);

    std::stringstream buffer;
    msgpack::pack(buffer, MessageType::AUTH);
    msgpack::pack(buffer, pubkey1);
    msgpack::pack(buffer, pubkey2);
    msgpack::pack(buffer, zkp1);
    msgpack::pack(buffer, zkp2);

    std::string buffer_str = buffer.str();

    auto context = contexts.find(id);
    if (contexts.end() == context) {
      context = contexts.emplace(id, Requester(id, secret_,
                                                   // std::move(privkey1),
                                                   std::move(privkey2),
                                                   std::move(pubkey1),
                                                   std::move(pubkey2)))
                .first;
    }

    return zmq::message_t{buffer_str.data(), buffer_str.size()};
  }

 private:
  void worker() {
    LOG_DEBUG("PAKE handshaker starting...");
    try {
      socket_.bind(address_);
    } catch (const zmq::error_t& e) {
      LOG_ERROR("Couldn't bind the handshaker: {}", e.what());
      return;
    }

    std::array<zmq::pollitem_t, 1> items = {{
        {socket_, 0, ZMQ_POLLIN, 0}
      }};

    while (listening) {
      try {
        zmq::poll(items.data(), items.size(), std::chrono::milliseconds(500));
      } catch (const zmq::error_t& e) {
        if (EINTR != e.num()) {
          LOG_ERROR("Handshaker poll error: {}", e.what());
        }
        break;
      }

      if (items[0].revents & ZMQ_POLLIN) {
        std::size_t offset = 0;
        std::stringstream buffer;

        zmq::multipart_t message(socket_);

        if (3 != message.size()) {
          LOG_ERROR("Handshaker received an unexpectedly structured "
                    "message. Frames: {}. Discarding", message.size());
          LOG_TRACE("Contents: {}", message.str());
          continue;
        }

        auto client_id = std::string{message[0].data<char>(),
          message[0].size()};

        const char* data = message[2].data<char>();
        const size_t data_size = message[2].size();

        const auto type = Unpack<MessageType>(data, data_size, offset)
                    .value_or(MessageType::BAD_MESSAGE);

        LOG_DEBUG(
            "Handshaker received a message. Type: {}, client id: {}",
            MessageTypeName(type), client_id);
        LOG_TRACE("Contents: ", message.str());

        if (client_id.empty() or
            MessageType::AUTH != type) {
          msgpack::pack(buffer, type);
          auto buffer_str = buffer.str();
          message[2].rebuild(buffer_str.data(), buffer_str.size());
          message.send(socket_);
          continue;
        }

        auto it = contexts.find(client_id);
        if (contexts.end() == it) {
          it = contexts.emplace(client_id, Responder(server_id_, secret_))
               .first;
        }
        AuthContext& context = it->second;

        auto result = std::visit([=](auto& ctx) {
          return ctx.Next(data + offset, data_size - offset);
        },
          context);

        std::visit(overload{
            [&](PartialMessage& msg) {
              // Just send the message

              msgpack::pack(buffer, HandshakerMessageType::MESSAGE);
              buffer << msg;
              const auto buffer_str = buffer.str();

              message[2].rebuild(buffer_str.data(), buffer_str.size());

              LOG_DEBUG("Handshaker sending MESSAGE message");
            },
            [&](EncKeys& keys) {
              // Send just the keys on the socket

              contexts.erase(client_id);
              msgpack::pack(buffer, HandshakerMessageType::KEYS);
              msgpack::pack(buffer, keys);
              const auto buffer_str = buffer.str();
              message[2].rebuild(buffer_str.data(), buffer_str.size());

              LOG_DEBUG("Handshaker sending KEYS message");
            },
            [&](std::pair<PartialMessage, EncKeys>& pair) {
              // Send the message and the keys

              const auto& msg = pair.first;
              const auto& keys = pair.second;
              assert(not msg.empty()
                     and not keys.get<0>().empty()
                     and not keys.get<1>().empty());

              msgpack::pack(buffer, HandshakerMessageType::KEYS_AND_MESSAGE);
              msgpack::pack(buffer, keys);
              buffer << msg;
              const auto buffer_str = buffer.str();
              message[2].rebuild(buffer_str.data(), buffer_str.size());

              LOG_DEBUG("Handshaker sending KEYS_AND_MESSAGE message");
            }},
          result);

        LOG_TRACE("Contents: {}", message.str());
        message.send(socket_);
      }
    }

    LOG_DEBUG("Handshaker stopped");
  }

  static std::optional<EcPoint> make_key_material(
      const EcPoint& peer_pubkey3,
      const EcPoint& peer_pubkey2,
      const EcScalar& privkey2,
      const EcScalar& secret) {
    // K = (peer_pubkey3 - (peer_pubkey2 x [privkey2 * secret_])) x [privkey2]
    EcPoint key_material;
    EcScalar temp_scalar;
    // temp_scalar = [privkey2 * secret]
    crypto_core_ristretto255_scalar_mul(
        temp_scalar.data(), privkey2.data(), secret.data());
    // key_material = peer_pubkey2 x temp_scalar
    if (-1 == crypto_scalarmult_ristretto255(
            key_material.data(), temp_scalar.data(), peer_pubkey2.data())) {
      return {};
    }
    // key_material = peer_pubkey3 - key_material
    crypto_core_ristretto255_sub(
        key_material.data(),
        peer_pubkey3.data(), key_material.data());
    // key_material = key_material x [privkey2]
    if (-1 == crypto_scalarmult_ristretto255(
            key_material.data(), privkey2.data(), key_material.data())) {
      return {};
    }

    return key_material;
  }


  static size_t auth_number;

  std::shared_ptr<zmq::context_t> ctx_;
  zmq::socket_t socket_;

  // std::atomic_bool listening = false;
  // std::thread thread_;

  EcScalar secret_;
  std::string server_id_;

  using AuthContext = std::variant<Requester, Responder>;
  std::unordered_map<std::string, AuthContext> contexts;

  friend class Handshaker;
};
size_t PakeHandshaker::auth_number = 0;
MSGPACK_ADD_ENUM(PakeHandshaker::Step);

#endif /* PAKEHANDSHAKER_H */

// This Handshaker should pass a step id in its message so there's no
// ambiguity on how to process the received data.

// Client doesn't know what's his id. It should be therefore generated before
// connecting to the server and set with GetAuthRequest().
// Client will also require the id of the server. This will be sent in a zkp.
//
// The server should have a constant id. It could be generated for every
// Handshaker object.
//
// To be unambiguous the context should contain both the local id and the
// peer id.

// Make a dual-class variant for the context. One for the server-side
// handshakes and one for the client ones.
// Alternatively use single context but without shortened, 3-stage protocol.
