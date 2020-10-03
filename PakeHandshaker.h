#ifndef PAKEHANDSHAKER_H
#define PAKEHANDSHAKER_H

#include "Handshaker.h"

#include "EncryptionCommon.h"
#include "ProtocolCommon.h"
#include <variant>
#include <zmq.hpp>

// Uses J-PAKE algorithm
class PakeHandshaker : public Handshaker<PakeHandshaker> {
  // FIXME: Use a class based on std::array, but that zeroes its memory on
  //        move.
  using EncryptionKey = std::array<byte, NA_SS_KEYBYTES>;
  using EncKeys = msgpack::type::tuple<CryptoKey, CryptoKey>;

  template<class... Ts> struct overload : Ts... { using Ts::operator()...; };
  template<class... Ts> overload(Ts...) -> overload<Ts...>;

  class Requester {
    struct loc_keys_generated {};
    struct all_received {
      std::string peer_id;
      EcPoint peer_pubkey1, peer_pubkey2;
      HmacKey kc_key;
      EncryptionKey enc_key, dec_key;
    };
    struct finished {};

    std::variant<loc_keys_generated, all_received, finished> state_ =
        loc_keys_generated{};

   public:
    // id is the external socket id
    Requester(const std::string& id, const EcScalar& secret,
              EcScalar&& privkey1, EcScalar&& privkey2,
              EcPoint&& pubkey1, EcPoint&& pubkey2)
        : id_{id},
          secret_{secret},
          privkey1_{privkey1}, privkey2_{privkey2},
          pubkey1_{pubkey1}, pubkey2_{pubkey2} {}

    std::variant<zmq::message_t, EncKeys>
    Next(const char* data, std::size_t size) {
      return std::visit(
          overload{
            [&, size](loc_keys_generated&) ->
            std::variant<zmq::message_t, EncKeys> {
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
                return make_msg(MessageType::BAD_MESSAGE);
              }

              new_state.peer_id = peer_zkp1.value().user_id;

              if (not (check_zkp(peer_zkp1.value(), peer_pubkey1.value(),
                                 new_state.peer_id, id_) and
                       check_zkp(peer_zkp2.value(), peer_pubkey2.value(),
                                 new_state.peer_id, id_))) {
                // TODO: Report denied request
                return make_msg(MessageType::DENY);
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
                return make_msg(MessageType::DENY);
              }

              if (not check_zkp(peer_zkp3.value(), peer_pubkey3.value(),
                                new_state.peer_id, id_,
                                peer_zkp_gen)) {
                // TODO: Report denied request
                return make_msg(MessageType::DENY);
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
                return make_msg(MessageType::DENY);
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
                return make_msg(MessageType::DENY);
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
              const auto buffer_str = buffer.str();

              new_state.peer_pubkey1 = std::move(peer_pubkey1.value());
              new_state.peer_pubkey2 = std::move(peer_pubkey2.value());

              state_ = std::move(new_state);

              return zmq::message_t{buffer_str.data(), buffer_str.size()};
            },
            [&, size](all_received& context) ->
            std::variant<zmq::message_t, EncKeys> {
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
                return make_msg(MessageType::DENY);
              }

              auto result =  msgpack::type::tuple<CryptoKey, CryptoKey>{
                std::move(context.enc_key), std::move(context.dec_key)};

              state_ = finished{};

              return result;
            },
            [](finished&) ->
            std::variant<zmq::message_t, EncKeys> {
              return make_msg(MessageType::BAD_MESSAGE);
            }
          },
          state_);
    }

   private:
    const std::string id_;
    const EcScalar& secret_;

    EcScalar privkey1_, privkey2_;
    EcPoint pubkey1_, pubkey2_;
  };

  class Responder {
    struct start {};
    struct first_keys_received {};
    struct crypto_keys_generated {
      CryptoKey enc_key, dec_key;
    };
    struct finished {};

    std::variant<start, first_keys_received, crypto_keys_generated, finished>
    state_ = start{};

   public:
    Responder(const std::string& id, const EcScalar& secret,
              EcScalar&& privkey1, EcScalar&& privkey2,
              EcPoint&& pubkey1, EcPoint&& pubkey2)
        : id_{id},
          secret_{secret},
          privkey1_{privkey1}, privkey2_{privkey2},
          pubkey1_{pubkey1}, pubkey2_{pubkey2} {}

    std::variant<zmq::message_t, EncKeys>
    Next(const char* data, std::size_t size) {
      return std::visit(
          overload{
            [&, size](start&) ->
            std::variant<zmq::message_t, EncKeys> {
              // id_ = server_id_;

              std::size_t offset = 0;

              {
                auto peer_pubkey1 = Unpack<EcPoint>(data, size, offset);
                auto peer_pubkey2 = Unpack<EcPoint>(data, size, offset);
                auto peer_zkp1 = Unpack<zkp>(data, size, offset);
                auto peer_zkp2 = Unpack<zkp>(data, size, offset);

                if (not (peer_pubkey1 and peer_pubkey2 and
                         peer_zkp1 and peer_zkp2)) {
                  return make_msg(MessageType::BAD_MESSAGE);
                }

                peer_id_ = peer_zkp1.value().user_id;

                // TODO: These id_ references were client_id's, which were
                //       obtained from zmq's received message as a first frame
                if (not (check_zkp(peer_zkp1.value(), peer_pubkey1.value(),
                                   peer_id_, id_) and
                         check_zkp(peer_zkp2.value(), peer_pubkey2.value(),
                                   peer_id_, id_))) {
                  return make_msg(MessageType::DENY);
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
                return make_msg(MessageType::DENY);
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

              auto buffer_str = buffer.str();

              state_ = first_keys_received{};

              return zmq::message_t{buffer_str.data(), buffer_str.size()};
            },
            [&, size](first_keys_received&) ->
            std::variant<zmq::message_t, EncKeys> {
              std::size_t offset = 0;

              auto peer_pubkey3 = Unpack<EcPoint>(data, size, offset);
              auto peer_zkp3 = Unpack<zkp>(data, size, offset);
              auto peer_kc = Unpack<HmacHash>(data, size, offset);

              if (not (peer_pubkey3 and peer_zkp3 and peer_kc)) {
                return make_msg(MessageType::BAD_MESSAGE);
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
                return make_msg(MessageType::DENY);
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
                return make_msg(MessageType::DENY);
              }

              // Key confirmation
              // Generate a signing key: k' = KDF(K || 1 || "JW_KGEN")
              HmacKey kc_key;
              // Generate an encryption keys: EK = KDF(K || 3 || "JW_KGEN")
              //                              DK = KDF(K || 2 || "JW_KGEN")
              crypto_keys_generated new_state{};

              // The order of args is important! Note that dec_key and enc_key
              // are in inverted order to the one in connect().
              derive_keys(key_material.value(), kc_key,
                          new_state.dec_key, new_state.enc_key);

              // Verify the received key confirmation data.
              const auto expected_peer_kc =
              make_key_confirmation(
                  kc_key,
                  peer_id_, peer_pubkey1_, peer_pubkey2_,
                  id_, pubkey1_, pubkey2_);
              if (peer_kc != expected_peer_kc) {
                return make_msg(MessageType::DENY);
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

              const auto buffer_str = buffer.str();

              state_ = std::move(new_state);

              return zmq::message_t{buffer_str.data(), buffer_str.size()};
            },
            [this](crypto_keys_generated& context) ->
            std::variant<zmq::message_t, EncKeys> {
              auto result = EncKeys{std::move(context.enc_key),
                                    std::move(context.dec_key)};

              state_ = finished{};

              return result;
            },
            [](finished&) ->
            std::variant<zmq::message_t, EncKeys> {
              return make_msg(MessageType::BAD_MESSAGE);
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

  template<typename Context>
  inline auto Next(Context& ctx, const char* data, std::size_t size) {
    return ctx.Next(data, size);
  }

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
  PakeHandshaker(zmq::context_t& context,
                 std::string_view password)
      : socket_{context, ZMQ_PAIR},
        crypto_socket_{context, ZMQ_PAIR},
        secret_{make_secret(password)},
        server_id_(5, ' ') {
    randombytes_buf(server_id_.data(), server_id_.length());
  }

  PakeHandshaker(const StupidHandshaker&) = delete;
  PakeHandshaker operator=(const StupidHandshaker&) = delete;

  ~PakeHandshaker() {
    Stop();
  }

  // id is the external socket id
  zmq::message_t GetAuthRequest(const std::string& id) {
    auth_context& context = contexts[id];
    context.id = id;
    context.step = Step::PKZKP_2;

    auto [privkey1, pubkey1, zkp1] = generate_keypair(context.id);
    auto [privkey2, pubkey2, zkp2] = generate_keypair(context.id);
    context.privkey1 = std::move(privkey1);
    context.pubkey1 = std::move(pubkey1);
    context.privkey2 = std::move(privkey2);
    context.pubkey2 = std::move(pubkey2);

    std::stringstream buffer;
    msgpack::pack(buffer, Step::PKZKP_2);
    msgpack::pack(buffer, context.pubkey1);
    msgpack::pack(buffer, context.pubkey2);
    msgpack::pack(buffer, zkp1);
    msgpack::pack(buffer, zkp2);
    std::string buffer_str = buffer.str();

    return zmq::message_t{buffer_str.data(), buffer_str.size()};
  }

 private:
  void worker() {
    socket_.bind(address_);
    crypto_socket_.bind(crypto_address_);

    std::array<zmq::pollitem_t, 1> items = {{
        {socket_, 0, ZMQ_POLLIN, 0}
      }};

    while (listening) {
      zmq::poll(items.data(), items.size(), std::chrono::milliseconds(500));

      if (items[0].revents & ZMQ_POLLIN) {
        std::size_t offset = 0;
        std::stringstream buffer;

        zmq::multipart_t message(socket_);

        // FIXME: Check if the message has 3 frames

        auto client_id = std::string{message[0].data<char>(),
          message[0].size()};
        auto& context = contexts[client_id];

        const char* data = message[2].data<char>();
        const size_t data_size = message[2].size();

        auto type = Unpack<MessageType>(data, data_size, offset)
                    .value_or(MessageType::BAD_MESSAGE);

        auto step = Unpack<Step>(data, data_size, offset)
                    .value_or(Step::UNKNOWN);

        if (client_id.empty() or
            MessageType::AUTH != type or
            not check_step(context.step, step)) {
          msgpack::pack(buffer, type);
          auto buffer_str = buffer.str();
          message[2].rebuild(buffer_str.data(), buffer_str.size());
          message.send(socket_);
          continue;
        }

        bool deny = false;
        bool bad_msg = false;
        // TODO: Parse the message proper.
        switch (step) {
          case Step::UNKNOWN: case Step::NONE: {
            // This should never happen.
            deny = true;
            break;
          }
          case Step::PKZKP_2: {
            // Server: first received message
            context.id = server_id_;

            auto peer_pubkey1 = Unpack<EcPoint>(data, data_size, offset);
            auto peer_pubkey2 = Unpack<EcPoint>(data, data_size, offset);
            auto peer_zkp1 = Unpack<zkp>(data, data_size, offset);
            auto peer_zkp2 = Unpack<zkp>(data, data_size, offset);

            if (not (peer_pubkey1 and peer_pubkey2 and
                     peer_zkp1 and peer_zkp2)) {
              bad_msg = true;
              break;
            }

            context.peer_id = peer_zkp1.value().user_id;

            // Check the received data
            if (not (check_zkp(peer_zkp1.value(), peer_pubkey1.value(),
                               context.peer_id, client_id) and
                     check_zkp(peer_zkp2.value(), peer_pubkey2.value(),
                               context.peer_id, client_id))) {
              deny = true;
              break;
            }

            context.peer_pubkey1 = std::move(peer_pubkey1.value());
            context.peer_pubkey2 = std::move(peer_pubkey2.value());

            // TODO: Generate and save all 3 keypairs and zkp's. Send pubkeys
            //       and zkp's.
            // This is tricky. Server should use its id and the client the id
            // provided by the socket. How to distinguish the use-cases?
            // When GetAuthRequest() is called, we know we're the client, so
            // the context should store a socket id on the call.
            // When the server gets its first message, it knows that it's the
            // server, so we should take an id passed in the constructor.
            // Maybe we should generate an id?

            // Generate new key-pairs and zkp's for them
            auto [privkey1, pubkey1, zkp1] = generate_keypair(context.id);
            auto [privkey2, pubkey2, zkp2] = generate_keypair(context.id);

            // Generate the last key-pair. This one is special:
            // G1 = peer_pubkey1 + peer_pubkey2 + pubkey1
            EcPoint zkp_gen;
            crypto_core_ristretto255_add(
                zkp_gen.data(), peer_pubkey1.data(), peer_pubkey2.data());
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
              deny = true;
              break;
            }

            const auto zkp3 =
                make_zkp(context.id, privkey3, pubkey3, zkp_gen);

            context.privkey1 = std::move(privkey1);
            context.pubkey1 = std::move(pubkey1);
            context.privkey2 = std::move(privkey2);
            context.pubkey2 = std::move(pubkey2);
            context.privkey3 = std::move(privkey3);
            context.pubkey3 = std::move(pubkey3);

            // Build the message and send
            msgpack::pack(buffer, MessageType::AUTH);
            msgpack::pack(buffer, context.pubkey1);
            msgpack::pack(buffer, context.pubkey2);
            msgpack::pack(buffer, context.pubkey3);
            msgpack::pack(buffer, zkp1);
            msgpack::pack(buffer, zkp2);
            msgpack::pack(buffer, zkp3);

            auto buffer_str = buffer.str();
            message[2].rebuild(buffer_str.data(), buffer_str.size());
            message.send(socket_);

            // TODO: change the state
            continue;

            break;
          }
          case Step::PKZKP_3: {
            // Client: First response from the server

            // context.peer_id = peer_zkp1.value().user_id;

            // TODO: change the state
            break;
          }
          case Step::PKZKP_KC: {
            // Server: Second message from the client. Contains the third
            // pubkey and zkp for it, as well as key confirmation.

            auto peer_pubkey3 = Unpack<EcPoint>(data, data_size, offset);
            auto peer_zkp3 = Unpack<zkp>(data, data_size, offset);
            auto peer_kc = Unpack<HmacHash>(data, data_size, offset);

            if (not (peer_pubkey3 and peer_zkp3 and peer_kc)) {
              bad_msg = true;
              break;
            }

            context.peer_pubkey3 = std::move(peer_pubkey3.value());

            // Verify
            // G2 = peer_pubkey1 + pubkey1 + pubkey2
            EcPoint peer_zkp_gen;
            crypto_core_ristretto255_add(peer_zkp_gen.data(),
                                         context.peer_pubkey1.data(),
                                         context.pubkey1.data());
            crypto_core_ristretto255_add(peer_zkp_gen.data(),
                                         peer_zkp_gen.data(),
                                         context.pubkey2.data());
            if (not
                (crypto_core_ristretto255_is_valid_point(
                    peer_zkp_gen.data()) and
                 check_zkp(
                     peer_zkp3.value(), context.peer_pubkey3,
                     context.peer_id, context.id, peer_zkp_gen))) {
              deny = true;
              break;
            }

            // Compute the session key material
            // K = (peer_pubkey3 - (peer_pubkey2 x [privkey2 * secret_]))
            //         x [privkey2]
            EcPoint key_material = make_key_material(
                context.peer_pubkey3, context.peer_pubkey2,
                context.privkey2, secret_);

            // Key confirmation
            // Generate a signing key: k' = KDF(K || 1 || "JW_KGEN")
            HmacKey kc_key;
            // Generate an encryption keys: EK = KDF(K || 3 || "JW_KGEN")
            //                              DK = KDF(K || 2 || "JW_KGEN")
            EncryptionKey enc_key, dec_key;

            // The order of args is important! Note that dec_key and enc_key
            // are in inverted order to the one in connect().
            derive_keys(key_material, kc_key, dec_key, enc_key);

            // Verify the received key confirmation data.
            const auto expected_peer_kc =
                make_key_confirmation(
                    kc_key,
                    context.peer_id, context.peer_pubkey1, context.peer_pubkey2,
                    context.id, context.pubkey1, context.pubkey2);
            if (peer_kc != expected_peer_kc) {
              deny = true;
              break;
            }

            // Generate the key confirmation data
            const auto kc =
                make_key_confirmation(
                    kc_key,
                    context.id, context.pubkey1, context.pubkey2,
                    context.peer_id, context.peer_pubkey1, context.peer_pubkey2);

            // Build the message and send
            msgpack::pack(buffer, MessageType::AUTH);
            msgpack::pack(buffer, kc);

            const auto buffer_str = buffer.str();
            message[2].rebuild(buffer_str.data(), buffer_str.size());
            message.send(socket_);

            // TODO: Send the encryption keys on crypto_socket_.
            // But the response was already sent. If we send crypto stuff to
            // the server, it will write another response to the client.
            // Therefore we should wait for another request, for now saving
            // the keys in the context, I guess?

            // TODO: change the state
            break;
          }
          case Step::KC: {
            // Client: Second response from the server. Contains only the key
            // confirmation.

            // TODO: change the state
            break;
          }
        }

        if (deny) {
          msgpack::pack(buffer, MessageType::DENY);
          auto buffer_str = buffer.str();
          message[2].rebuild(buffer_str.data(), buffer_str.size());
          message.send(socket_);
          continue;
        } else if (bad_msg) {
          msgpack::pack(buffer, MessageType::BAD_MESSAGE);
          auto buffer_str = buffer.str();
          message[2].rebuild(buffer_str.data(), buffer_str.size());
          message.send(socket_);
          continue;
        }
      }
    }
    std::cout << "Handshaker stopped\n";
  }

  constexpr bool check_step(const Step current, const Step received) {
    switch (current) {
      case Step::UNKNOWN:
        return false;
        break;
      case Step::NONE:
        if (Step::PKZKP_2 == received) return true;
        return false;
        break;
      case Step::PKZKP_2:
        if (Step::PKZKP_3 == received) return true;
        return false;
        break;
      case Step::PKZKP_3:
        if (Step::PKZKP_KC == received) return true;
        return false;
        break;
      case Step::PKZKP_KC:
        if (Step::KC == received) return true;
        return false;
        break;
      case Step::KC:
        // After the key confirmation there's nothing more to do.
        return false;
        break;
    }
  }

  static zmq::message_t make_msg(MessageType type) {
    std::stringstream buffer;
    msgpack::pack(buffer, type);
    const auto buffer_str = buffer.str();
    return zmq::message_t(buffer_str.data(), buffer_str.size());
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



  struct auth_context {
    Step step = Step::UNKNOWN;

    std::string id, peer_id;

    EcScalar privkey1, privkey2, privkey3;
    EcPoint pubkey1, pubkey2, pubkey3;

    EcPoint peer_pubkey1, peer_pubkey2, peer_pubkey3;

    // #################### MEMORY ####################
    auth_context() = default;
    auth_context(const auth_context&) = delete;
    const auth_context& operator=(const auth_context&) = delete;
    auth_context(auth_context&& other) = delete;
    auth_context& operator=(auth_context&& other) = delete;

    // auth_context(auth_context&& other)
    //     : privkey1{std::move(other.privkey1)},
    //       privkey2{std::move(other.privkey2)},
    //       privkey3{std::move(other.privkey3)},
    //       pubkey1{std::move(other.pubkey1)},
    //       pubkey2{std::move(other.pubkey2)},
    //       pubkey3{std::move(other.pubkey3)},
    //       peer_pubkey1{std::move(other.peer_pubkey1)},
    //       peer_pubkey2{std::move(other.peer_pubkey2)},
    //       peer_pubkey3{std::move(other.peer_pubkey3)} {
    //   sodium_memzero(other.privkey1.data(), other.privkey1.size());
    //   sodium_memzero(other.privkey2.data(), other.privkey2.size());
    //   sodium_memzero(other.privkey3.data(), other.privkey3.size());
    // }

    // auth_context& operator=(auth_context&& other) {
    //   privkey1 = std::move(other.privkey1);
    //   privkey2 = std::move(other.privkey2);
    //   privkey3 = std::move(other.privkey3);
    //   pubkey1 = std::move(other.pubkey1);
    //   pubkey2 = std::move(other.pubkey2);
    //   pubkey3 = std::move(other.pubkey3);
    //   peer_pubkey1 = std::move(other.peer_pubkey1);
    //   peer_pubkey2 = std::move(other.peer_pubkey2);
    //   peer_pubkey3 = std::move(other.peer_pubkey3);

    //   sodium_memzero(other.privkey1.data(), other.privkey1.size());
    //   sodium_memzero(other.privkey2.data(), other.privkey2.size());
    //   sodium_memzero(other.privkey3.data(), other.privkey3.size());

    //   return *this;
    // }

    ~auth_context() {
      sodium_memzero(privkey1.data(), privkey1.size());
      sodium_memzero(privkey2.data(), privkey2.size());
      sodium_memzero(privkey3.data(), privkey3.size());
    }
  };

  static size_t auth_number;

  zmq::socket_t socket_;
  zmq::socket_t crypto_socket_;

  std::atomic_bool listening = false;
  std::thread thread_;

  EcScalar secret_;
  std::string server_id_;

  std::unordered_map<std::string, auth_context> contexts;
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
