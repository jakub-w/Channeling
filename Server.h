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

#ifndef CHANNELING_SERVER_H
#define CHANNELING_SERVER_H

#include <algorithm>
#include <functional>
#include <memory>
#include <string_view>
#include <unordered_map>
#include <variant>

#include <msgpack.hpp>

#include <spdlog/spdlog.h>

#include <zmq.h>
#include <zmq.hpp>
#include <zmq_addon.hpp>

#include "SodiumCipherStream/SodiumCipherStream.h"

#include "Handshaker.h"
#include "Logging.h"
#include "ProtocolCommon.h"
#include "ServerSFINAE.h"
#include "Util.h"

namespace Channeling {
/// \e MessageHandlerResult must be an rvalue, also it must own the data
/// stored inside of it. The data will be used by an encryption algorithm so
/// it is crucial for it to live long enough to do that. If this restriction
/// is not followed it could lead to hard to track memory errors.
/// \e MessageHandlerResult must also have size() and data() member functions.
template <class Handshaker,
          typename MessageHandler,
          typename MessageHandlerResult =
              std::result_of_t<MessageHandler(Bytes&&)>,
          std::enable_if_t<not (std::is_pointer_v<MessageHandlerResult> or
                                std::is_reference_v<MessageHandlerResult>),
                           bool> = 0,
          std::enable_if_t<has_data_and_size_v<MessageHandlerResult>,
                           bool> = 0>
class Server {
  using HandshakerMessageType = typename Handshaker::HandshakerMessageType;

  struct client_info {
    bool authenticated = false;

    std::variant<CryptoKey, crypto::SodiumEncryptionContext>
    encryption_ctx = crypto::SodiumEncryptionContext{};
    std::variant<CryptoKey, crypto::SodiumDecryptionContext>
    decryption_ctx = CryptoKey{};
  };

 public:
  Server(std::shared_ptr<Handshaker> handshaker,
         MessageHandler message_handler)
      : ctx_{get_context()},
        handshaker_{std::move(handshaker)},
        socket_{ctx_, ZMQ_ROUTER},
        handshaker_socket_{ctx_, ZMQ_PAIR},
        user_data_handler_{std::move(message_handler)} {}

  ~Server() {
    Close();
  }

  constexpr void Bind(std::string_view address) {
    LOG_INFO("Binding the server to {}", address);
    socket_.bind(address.data());
  }

  constexpr void Close() {
    handshaker_->Stop();
    run = false;
  }

  void Run() {
    if (run.exchange(true)) return;

    LOG_INFO("Server starting...");

    handshaker_->Start();
    handshaker_socket_.connect(handshaker_->GetAddress());

    std::array<zmq::pollitem_t, 3> items = {{
        {static_cast<void*>(socket_), 0, ZMQ_POLLIN, 0},
        {static_cast<void*>(handshaker_socket_), 0, ZMQ_POLLIN, 0}
      }};

    LOG_INFO("Waiting for requests...");

    while (run) {
      try {
        zmq::poll(items.data(), items.size(), std::chrono::milliseconds(500));
      } catch (const zmq::error_t& e) {
        if (EINTR != e.num()) {
          LOG_ERROR("Run() poll error: {}", e.what());
        }
        break;
      }

      // router socket (external, incoming messages)
      if (items[0].revents & ZMQ_POLLIN) {
        handle_incoming();
      }

      // handshaker socket
      if (items[1].revents & ZMQ_POLLIN)  {
        handle_handshaker();
      }
    }

    LOG_INFO("Server exiting...");
  }

 private:
  inline static void send_msg(zmq::socket_t& socket,
                              std::string_view client_id, MessageType type) {
    socket.send(zmq::buffer(client_id), zmq::send_flags::sndmore);
    socket.send(zmq::buffer(""), zmq::send_flags::sndmore);
    socket.send(make_msg(type), zmq::send_flags::dontwait);
  }

  void handle_incoming() {
    zmq::multipart_t message{socket_};

    if (message.size() != 3) {
      // Unexpected message structure
      LOG_WARN("Client sent unexpectedly structured message. Frames: {}",
               message.size());
      LOG_TRACE("Message contents: {}", message.str());

      socket_.send(message[0], zmq::send_flags::sndmore);
      socket_.send(message[1], zmq::send_flags::sndmore);
      const auto type = MessageType::BAD_MESSAGE;
      socket_.send(zmq::const_buffer(&type, sizeof(type)),
                   zmq::send_flags::dontwait);
      return;
    }

    const std::string
        client_id{message[0].data<char>(), message[0].size()};

    const auto client_log = [&client_id](const auto& format_string,
                                         const auto&... args) {
      return fmt::format(
          "Client id: {}, {}",
          client_id,
          fmt::format(std::forward<decltype(format_string)>(format_string),
                      std::forward<decltype(args)>(args)...));
    };

    std::size_t offset = 0;

    const auto type = Unpack<MessageType>(message[2].data<char>(),
                                          message[2].size(),
                                          offset)
                      .value_or(MessageType::BAD_MESSAGE);
    LOG_DEBUG("Message received: from: {}, type: {}" ,
              client_id, MessageTypeName(type));
    LOG_TRACE("Message contents: {}", message.str());


    if (not clients[client_id].authenticated
        and (not std::any_of(allowed_before_auth.cbegin(),
                             allowed_before_auth.cend(),
                             [=](MessageType t){ return t == type; }))) {
      LOG_WARN(client_log("Client '{}' sent wrong type message before "
                          "authenticating. Denying...", client_id));
      message[2] = make_msg(MessageType::DENY);
      message.send(socket_);
      return;
    }

    switch (type) {
      case MessageType::BAD_MESSAGE:
        LOG_WARN(client_log("Client sent BAD_MESSGE. Protocol error?"));
        message[2] = make_msg(MessageType::ACK);
        message.send(socket_);
        return;
      case MessageType::DENY:
        LOG_WARN(client_log("Client denied the connection"));
        message[2] = make_msg(MessageType::ACK);
        message.send(socket_);
        return;
      case MessageType::ID: {
        std::stringstream buffer;
        msgpack::pack(buffer, client_id);
        const auto buffer_str = buffer.str();
        message[2].rebuild(buffer_str.data(), buffer_str.size());
        message.send(socket_);
        return;
      }
      case MessageType::AUTH: {
        LOG_DEBUG(
            client_log("Forwarding AUTH message to the handshaker"));
        message.send(handshaker_socket_);
        break;
      }
      case MessageType::AUTH_CONFIRM: {
        auto dec_header = Unpack<crypto::CryptoHeader>(
            message[2].data<char>(), message[2].size(), offset);

        auto& ci = clients[client_id];

        const auto send_protocol_error = [&]{
          const auto type = MessageType::PROTOCOL_ERROR;
          message[2].rebuild(&type, sizeof(type));
          message.send(socket_);
          clients.erase(client_id);
        };

        if (not (std::holds_alternative<CryptoKey>(ci.decryption_ctx) and
                 std::holds_alternative<CryptoKey>(ci.encryption_ctx))) {
          LOG_ERROR(client_log("Client's context state is inconsistent. "
                               "Can't proceed with encryption setup"));
          send_protocol_error();
          break;
        }

        if (not dec_header.has_value()) {
          LOG_ERROR(
              client_log("Received malformed encryption header from client "
                         "'{}'", client_id));
          send_protocol_error();
          break;
        }

        auto dec_key = std::get<CryptoKey>(ci.decryption_ctx);

        ci.decryption_ctx = crypto::SodiumDecryptionContext{};
        auto& dec_ctx =
            std::get<crypto::SodiumDecryptionContext>(ci.decryption_ctx);

        auto ec = dec_ctx.Initialize(
            dec_key.data(), dec_key.size(),
            dec_header.value().data(), dec_header.value().size());

        if (ec) {
          LOG_ERROR(
              client_log("Protocol error while initializing decryption "
                         "context for '{}'", client_id));
          send_protocol_error();
          break;
        }

        auto enc_key = std::get<CryptoKey>(ci.encryption_ctx);
        ci.encryption_ctx = crypto::SodiumEncryptionContext{};
        auto& enc_ctx =
            std::get<crypto::SodiumEncryptionContext>(ci.encryption_ctx);

        crypto::CryptoHeader enc_header;
        ec = enc_ctx.Initialize(enc_key.data(), enc_key.size(),
                                enc_header.data(), enc_header.size());
        if (ec) {
          LOG_ERROR(
              client_log("Protocol error while initializing encryption "
                         "context for '{}'", client_id));
          send_protocol_error();
          break;
        }

        ci.authenticated = true;

        LOG_DEBUG(client_log("Sending AUTH_FINISHED to client"));

        message[2] = make_msg(MessageType::AUTH_FINISHED, enc_header);
        message.send(socket_);
        break;
      }
      case MessageType::AUTH_FINISHED: {
        auto dec_header = Unpack<crypto::CryptoHeader>(
            message[2].data<char>(), message[2].size(), offset);

        auto& ci = clients[client_id];

        const auto send_protocol_error = [&]{
          const auto type = MessageType::PROTOCOL_ERROR;
          message[2].rebuild(&type, sizeof(type));
          message.send(socket_);
          clients.erase(client_id);
        };

        if (not (std::holds_alternative<CryptoKey>(ci.decryption_ctx) and
                 std::holds_alternative<crypto::SodiumEncryptionContext>(
                     ci.encryption_ctx))) {
          LOG_ERROR(
              client_log("Client state is inconsistent. Can't proceed with "
                         "encryption setup"));
          send_protocol_error();
          break;
        }

        if (not dec_header.has_value()) {
          LOG_ERROR(
              client_log("Received malformed encryption header from client"));
          send_protocol_error();
          break;
        }

        auto dec_key = std::get<CryptoKey>(ci.decryption_ctx);

        ci.decryption_ctx = crypto::SodiumDecryptionContext{};
        auto& dec_ctx =
            std::get<crypto::SodiumDecryptionContext>(ci.decryption_ctx);

        auto ec = dec_ctx.Initialize(
            dec_key.data(), dec_key.size(),
            dec_header.value().data(), dec_header.value().size());
        if (ec) {
          LOG_ERROR(
              client_log("Protocol error while initializing decryption "
                         "context\n"));
          send_protocol_error();
          break;
        }

        ci.authenticated = true;

        message[2] = make_msg(MessageType::ACK);
        message.send(socket_);
        break;
      }
      case MessageType::ENCRYPTED_DATA: {
        auto& ci = clients[client_id];

        auto request_id = Unpack<req_id_t>(message[2].data<char>(),
                                           message[2].size(), offset)
                          .value_or(0);
        if (0 == request_id) {
          LOG_ERROR(client_log("Client didn't include request id "
                               "with the request"));
          message[2] = make_msg(MessageType::PROTOCOL_ERROR);
          message.send(socket_);
          break;
        }
        LOG_TRACE(client_log("request id: {}", request_id));

        if (not (std::holds_alternative<crypto::SodiumEncryptionContext>(
                ci.encryption_ctx) and
                 std::holds_alternative<crypto::SodiumDecryptionContext>(
                     ci.decryption_ctx))) {
          LOG_ERROR(client_log("Inconsistent state in client's context. "
                               "Can't proceed with the decryption"));
          message[2] = make_msg(MessageType::PROTOCOL_ERROR, request_id);
          message.send(socket_);
          break;
        }
        auto& dec_ctx =
            std::get<crypto::SodiumDecryptionContext>(ci.decryption_ctx);

        auto maybe_ciphertext = Unpack<Bytes>(message[2].data<char>(),
                                              message[2].size(), offset);
        if (not maybe_ciphertext) {
          LOG_ERROR(client_log("Error unpacking ciphertext: {}",
                               maybe_ciphertext.error().message()));
          message[2] = make_msg(MessageType::PROTOCOL_ERROR, request_id);
          message.send(socket_);
          break;
        }

        const Bytes& ciphertext = maybe_ciphertext.value();

        static_assert(sizeof(char) == sizeof(crypto::byte));
        auto maybe_cleartext = dec_ctx.Decrypt(ciphertext);

        if (std::holds_alternative<std::error_code>(maybe_cleartext)) {
          auto ec = std::get<std::error_code>(maybe_cleartext);
          if (ec == std::errc::bad_message){
            LOG_ERROR(client_log("Couldn't decrypt. Bad message sent by "
                                 "the client"));
            message[2] = make_msg(MessageType::PROTOCOL_ERROR, request_id);
          } else if (ec == std::errc::operation_not_permitted) {
            LOG_ERROR(client_log("Couldn't decrypt. Decryption context "
                                 "is uninitialized"));
            message[2] = make_msg(MessageType::PROTOCOL_ERROR, request_id);
          } else if (ec == std::errc::invalid_argument){
            LOG_ERROR(client_log("One of the buffers for decryption "
                                 "has wrong size"));
            message[2] = make_msg(MessageType::PROTOCOL_ERROR, request_id);
          } else if (ec == std::errc::connection_aborted){
            LOG_WARN(client_log("Encrypted message stored stream abort "
                                "command"));
            message[2] = make_msg(MessageType::ACK, request_id);
          }
          message.send(socket_);
          break;
        }

        tl::expected<MessageHandlerResult, bool> cleartext_response =
            [this, &maybe_cleartext, &client_log]()
            -> tl::expected<MessageHandlerResult, bool> {
          try {
            return user_data_handler_(
                std::move(std::get<crypto::Bytes>(maybe_cleartext)));
          } catch (const std::exception& e) {
            LOG_ERROR(client_log(
                "Throw in the user's message handler: {}", e.what()));
            return tl::unexpected(false);
          } catch (...) {
            LOG_ERROR(client_log(
                "Throw in the user's message handler. Type of the "
                "exception unknown, so no more data provided."));
            return tl::unexpected(false);
          }
        }();

        if (not cleartext_response) {
          message[2] = make_msg(MessageType::PROTOCOL_ERROR, request_id);
          message.send(socket_);
          break;
        }

        auto& enc_ctx =
            std::get<crypto::SodiumEncryptionContext>(ci.encryption_ctx);
        const auto enc_result =
            enc_ctx.Encrypt(std::data(cleartext_response.value()),
                            std::size(cleartext_response.value()));
        if (std::holds_alternative<std::error_code>(enc_result)) {
          // TODO: Handle error codes
          // auto ec = std::get<std::error_code>(enc_result);
          LOG_ERROR(client_log("Error encrypting data"));

          message[2] = make_msg(MessageType::PROTOCOL_ERROR, request_id);
          message.send(socket_);
          break;
        }

        LOG_TRACE(client_log(
            "Sending encrypted data to the client: {}",
            to_hex(std::get<crypto::Bytes>(enc_result))));

        message[2] = make_msg(MessageType::ENCRYPTED_DATA,
                              request_id,
                              std::get<crypto::Bytes>(enc_result));
        message.send(socket_);

        break;
      }
      default: {
        LOG_ERROR(client_log("Unhandled message type: {}",
                             MessageTypeName(type)));
        message[2] = make_msg(MessageType::BAD_MESSAGE);
        message.send(socket_);
        break;
      }
    }
  }

  void handle_handshaker() {
    // All messages arriving on this socket are responses from the
    // handshaker to the client, so we just forward them.

    // TODO: Examine the message. If it's a DENY message, increase
    //       ci.suspicious_actions and if it hits a certain number, block
    //       any connection attempts for some time.

    zmq::multipart_t message(handshaker_socket_);

    assert(message.size() == 3);

    std::size_t offset = 0;
    auto type = Unpack<HandshakerMessageType>(
        message[2].data<char>(), message[2].size(), offset);

    assert(type.has_value());
    LOG_DEBUG("Received {} message from the handshaker",
              HandshakerMessageTypeName(type.value()));
    LOG_TRACE("Message contents: {}", message.str());

    const std::string client_id{
      message[0].data<char>(), message[0].size()};
    assert(not client_id.empty());

    std::stringstream buffer;

    switch (type.value()) {
      case HandshakerMessageType::MESSAGE: {
        LOG_DEBUG("Passing handshaker message to peer: {}", client_id);

        buffer.write(message[2].data<char>() + offset,
                     message[2].size() - offset);
        offset = message[2].size(); // just in case

        break;
      }
      case HandshakerMessageType::KEYS: {
        auto maybe_keypair = Unpack<EncKeys>(message[2].data<char>(),
                                             message[2].size(),
                                             offset);
        if (not maybe_keypair) {
          LOG_ERROR("Failed to unpack encryption keys sent from the"
                    " handshaker. Client id: {}", client_id);
          send_msg(socket_, client_id, MessageType::PROTOCOL_ERROR);
          return;
        }

        auto& keypair = maybe_keypair.value();

        client_info& ci = clients[client_id];

        const auto& enc_key = keypair.get<0>();
        ci.decryption_ctx = std::move(keypair.get<1>());

        auto& enc_ctx =
            std::get<crypto::SodiumEncryptionContext>(ci.encryption_ctx);

        crypto::CryptoHeader enc_header;
        const auto ec = enc_ctx.Initialize(
            enc_key.data(), enc_key.size(),
            enc_header.data(), enc_header.size());

        if (ec) {
          LOG_ERROR("Error initializing encryption context for client "
                    "'{}'", client_id);
          msgpack::pack(buffer, MessageType::PROTOCOL_ERROR);
        } else {
          LOG_DEBUG("Encryption context for '{}' initialized. Sending "
                    "AUTH_CONFIRM");
          msgpack::pack(buffer, MessageType::AUTH_CONFIRM);
          msgpack::pack(buffer, enc_header);
        }

        break;
      }
      case HandshakerMessageType::KEYS_AND_MESSAGE: {
        auto maybe_keypair = Unpack<EncKeys>(message[2].data<char>(),
                                             message[2].size(),
                                             offset);
        if (not maybe_keypair) {
          LOG_ERROR("Failed to unpack encryption keys sent from the"
                    " handshaker. Client id: {}", client_id);
          send_msg(socket_, client_id, MessageType::PROTOCOL_ERROR);
          return;
        }

        auto& keypair = maybe_keypair.value();

        client_info& ci = clients[client_id];

        // We don't need a crypto header yet. We can generate it when we
        // receive AUTH_CONFIRM.

        ci.encryption_ctx = std::move(keypair.get<0>());
        ci.decryption_ctx = std::move(keypair.get<1>());

        LOG_DEBUG("Passing handshaker message to peer: {}", client_id);

        buffer.write(message[2].data<char>() + offset,
                     message[2].size() - offset);
        offset = message[2].size(); // just in case

        break;
      }
    }

    // Don't reuse the message to be sure no sensitive data leaks on the line.
    socket_.send(zmq::buffer(client_id), zmq::send_flags::sndmore);
    socket_.send(zmq::const_buffer("", 0), zmq::send_flags::sndmore);

    const auto buffer_str = buffer.str();
    socket_.send(zmq::const_buffer(buffer_str.data(), buffer_str.size()),
                 zmq::send_flags::dontwait);
    LOG_DEBUG("Message sent to client '{}'", client_id);
  }

  // -------------------- PRIVATE FIELDS --------------------
  static constexpr std::array allowed_before_auth = {
    MessageType::AUTH,
    MessageType::AUTH_CONFIRM,
    MessageType::AUTH_FINISHED,
    MessageType::ID,
    MessageType::PROTOCOL_ERROR,
    MessageType::BAD_MESSAGE,
    MessageType::DENY
  };

  std::atomic_bool run = false;

  zmq::context_t& ctx_;
  std::shared_ptr<Handshaker> handshaker_;

  zmq::socket_t socket_;
  zmq::socket_t handshaker_socket_;

  std::unordered_map<std::string, client_info> clients;

  MessageHandler user_data_handler_;
};
}

#endif /* CHANNELING_SERVER_H */
