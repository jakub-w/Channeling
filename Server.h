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

#ifndef SERVER_H
#define SERVER_H

#include <algorithm>
#include <functional>
#include <iostream>
#include <memory>
#include <string_view>
#include <unordered_map>

#include <variant>
#include <zmq.h>
#include <zmq.hpp>
#include <zmq_addon.hpp>

#include <msgpack.hpp>

#include "SodiumCipherStream/SodiumCipherStream.h"

#include "ProtocolCommon.h"
#include "Util.h"

template <class Handshaker>
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
  Server(zmq::context_t& context,
         std::shared_ptr<Handshaker> handshaker,
         std::function<Bytes(Bytes&&)>&& message_handler)
      : handshaker_{std::move(handshaker)},
        socket_{context, ZMQ_ROUTER},
        handshaker_socket_{context, ZMQ_PAIR},
        user_data_handler_{std::move(message_handler)} {}

  constexpr void Bind(std::string_view address) {
    socket_.bind(address.data());
  }

  constexpr void Close() {
    run = false;
  }

  void Run() {
    if (run.exchange(true)) return;

    handshaker_->Start();
    handshaker_socket_.connect(handshaker_->GetAddress());

    std::array<zmq::pollitem_t, 3> items = {{
        {static_cast<void*>(socket_), 0, ZMQ_POLLIN, 0},
        {static_cast<void*>(handshaker_socket_), 0, ZMQ_POLLIN, 0}
      }};

    while (run) {
      zmq::poll(items.data(), items.size(), std::chrono::milliseconds(500));

      // router socket (external, incoming messages)
      if (items[0].revents & ZMQ_POLLIN) {
        handle_incoming();
      }

      // handshaker socket
      if (items[1].revents & ZMQ_POLLIN)  {
        handle_handshaker();
      }
    }

    std::cout << "Server exiting...\n";
  }

 private:
  inline static void send_msg(zmq::socket_t& socket,
                              std::string_view client_id, MessageType type) {
    socket.send(zmq::buffer(client_id), zmq::send_flags::sndmore);
    socket.send(zmq::buffer(""), zmq::send_flags::sndmore);
    socket.send(make_msg(type), zmq::send_flags::dontwait);
  }

  inline Bytes handle_user_data(Bytes&& data) {
    return user_data_handler_(std::move(data));
  }

  void handle_incoming() {
    zmq::multipart_t message{socket_};
    std::cout << "Server received message: " << message.str() << '\n';

    if (message.size() != 3) {
      // Unexpected message structure
      std::cerr << "Client sent bad message: " << message.str() << '\n';

      socket_.send(message[0], zmq::send_flags::sndmore);
      socket_.send(message[1], zmq::send_flags::sndmore);
      const auto type = MessageType::BAD_MESSAGE;
      socket_.send(zmq::const_buffer(&type, sizeof(type)),
                   zmq::send_flags::dontwait);
      return;
    }

    const std::string
        client_id{message[0].data<char>(), message[0].size()};
    std::cout << "Client id: " << to_hex(client_id) << '\n';

    std::size_t offset = 0;

    const auto type = Unpack<MessageType>(message[2].data<char>(),
                                          message[2].size(),
                                          offset)
                      .value_or(MessageType::BAD_MESSAGE);
    std::cout << "Message type: " << MessageTypeName(type) << '\n';

    if (not clients[client_id].authenticated
        and (not std::any_of(allowed_before_auth.cbegin(),
                             allowed_before_auth.cend(),
                             [=](MessageType t){ return t == type; }))) {
      message[2] = make_msg(MessageType::DENY);

      message.send(socket_);
      return;
    }

    switch (type) {
      case MessageType::BAD_MESSAGE:
        std::cerr << "Client sent BAD_MESSGE. Protocol error?\n";
        message[2] = make_msg(MessageType::ACK);
        message.send(socket_);
        return;
      case MessageType::DENY:
        std::cerr << "Client denied the connection\n";
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
        message.send(handshaker_socket_);
        std::cout << "Forwarded to the handshaker\n\n";
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
          std::cerr << "Client state is inconsistent. Can't proceed with "
              "encryption setup\n";
          send_protocol_error();
          break;
        }

        if (not dec_header.has_value()) {
          std::cerr << "Received malformed encryption header from client\n";
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
          std::cerr << "Protocol error while initializing decryption "
              "context\n";
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
          std::cerr << "Protocol error while initializing encryption "
              "context\n";
          send_protocol_error();
          break;
        }

        ci.authenticated = true;

        std::cout << "Sending AUTH_FINISHED to client\n";

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
          std::cerr << "Client state is inconsistent. Can't proceed with "
              "encryption setup\n";
          send_protocol_error();
          break;
        }

        if (not dec_header.has_value()) {
          std::cerr << "Received malformed encryption header from client\n";
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
          std::cerr << "Protocol error while initializing decryption "
              "context\n";
          send_protocol_error();
          break;
        }

        ci.authenticated = true;

        message[2] = make_msg(MessageType::ACK);
        message.send(socket_);
        break;
      }
      case MessageType::ENCRYPTED_DATA: {
        std::cout << "Encrypted data received\n";

        auto& ci = clients[client_id];

        if (not (std::holds_alternative<crypto::SodiumEncryptionContext>(
                     ci.encryption_ctx) and
                 std::holds_alternative<crypto::SodiumDecryptionContext>(
                     ci.decryption_ctx))) {
          message[2] = make_msg(MessageType::PROTOCOL_ERROR);
          message.send(socket_);
          break;
        }
        auto& dec_ctx =
            std::get<crypto::SodiumDecryptionContext>(ci.decryption_ctx);

        auto maybe_ciphertext = Unpack<Bytes>(message[2].data<char>(),
                                              message[2].size(), offset);
        if (not maybe_ciphertext) {
          std::cerr << "Error unpacking ciphertext: "
                    << maybe_ciphertext.error().message() << '\n';
          message[2] = make_msg(MessageType::PROTOCOL_ERROR);
          message.send(socket_);
          break;
        }

        const Bytes& ciphertext = maybe_ciphertext.value();

        static_assert(sizeof(char) == sizeof(crypto::byte));
        auto maybe_cleartext = dec_ctx.Decrypt(ciphertext);

        if (std::holds_alternative<std::error_code>(maybe_cleartext)) {
          auto ec = std::get<std::error_code>(maybe_cleartext);
          if (ec == std::errc::bad_message or
              ec == std::errc::operation_not_permitted){
            std::cerr << "PROTOCOL_ERROR on Decrypt()\n";
            std::cerr << ec << '\n';
            message[2] = make_msg(MessageType::PROTOCOL_ERROR);
          } else if (ec == std::errc::invalid_argument){
            std::cerr << "Bad argument for Decrypt()\n";
            message[2] = make_msg(MessageType::PROTOCOL_ERROR);
          } else if (ec == std::errc::connection_aborted){
            std::cerr << "Connection aborted on Decrypt()\n";
            message[2] = make_msg(MessageType::ACK);
          }
          message.send(socket_);
          break;
        }

        Bytes cleartext_response;
        try {
          cleartext_response = handle_user_data(
              std::move(std::get<crypto::Bytes>(maybe_cleartext)));
        } catch (const std::exception& e) {
          std::cerr << "Throw in the user's message handler: "
                    << e.what() << '\n';
          message[2] = make_msg(MessageType::PROTOCOL_ERROR);
          message.send(socket_);
          break;
        } catch (...) {
          std::cerr << "Throw in the user's message handler. Type of the "
              "exception unknown, so no more data provided.\n";
          message[2] = make_msg(MessageType::PROTOCOL_ERROR);
          message.send(socket_);
          break;
        }

        auto& enc_ctx =
            std::get<crypto::SodiumEncryptionContext>(ci.encryption_ctx);
        const auto enc_result = enc_ctx.Encrypt(cleartext_response);
        if (std::holds_alternative<std::error_code>(enc_result)) {
          // auto ec = std::get<std::error_code>(enc_result);
          std::cerr << "Error encrypting data\n";

          message[2] = make_msg(MessageType::PROTOCOL_ERROR);
          message.send(socket_);
          break;
        }

        message[2] = make_msg(MessageType::ENCRYPTED_DATA,
                              std::get<crypto::Bytes>(enc_result));
        message.send(socket_);

        break;
      }
      default: {
        std::cerr << "Unhandled message type: "
                  << MessageTypeName(type) << "\n\n";

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

    std::cout << "Server: message from the handshaker. "
        "Passing to the client...\n\n";
    zmq::multipart_t message(handshaker_socket_);

    assert(message.size() == 3);

    std::size_t offset = 0;
    auto type = Unpack<HandshakerMessageType>(
        message[2].data<char>(), message[2].size(), offset);

    assert(type.has_value());

    const std::string client_id{
          message[0].data<char>(), message[0].size()};
    assert(not client_id.empty());

    std::stringstream buffer;

    switch (type.value()) {
      case HandshakerMessageType::MESSAGE: {
        std::cout << "Passing message to peer\n";

        buffer.write(message[2].data<char>() + offset,
                     message[2].size() - offset);
        offset = message[2].size(); // just in case

        break;
      }
      case HandshakerMessageType::KEYS: {
        std::cout << "Keys received from the handshaker\n";

        auto maybe_keypair = Unpack<EncKeys>(message[2].data<char>(),
                                             message[2].size(),
                                             offset);
        if (not maybe_keypair) {
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
          msgpack::pack(buffer, MessageType::PROTOCOL_ERROR);
          std::cerr << "Error initializing encryption context for client\n";
        } else {
          msgpack::pack(buffer, MessageType::AUTH_CONFIRM);
          msgpack::pack(buffer, enc_header);
        }

        break;
      }
      case HandshakerMessageType::KEYS_AND_MESSAGE: {
        std::cout << "Keys and a message received from the handshaker\n";

        auto maybe_keypair = Unpack<EncKeys>(message[2].data<char>(),
                                             message[2].size(),
                                             offset);
        if (not maybe_keypair) {
          std::cerr << "Protocol error!\n";
          send_msg(socket_, client_id, MessageType::PROTOCOL_ERROR);
          return;
        }

        auto& keypair = maybe_keypair.value();

        client_info& ci = clients[client_id];

        // We don't need a crypto header yet. We can generate it when we
        // receive AUTH_CONFIRM.

        ci.encryption_ctx = std::move(keypair.get<0>());
        ci.decryption_ctx = std::move(keypair.get<1>());

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
    std::cout << "Message sent to the client\n";
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

  std::shared_ptr<Handshaker> handshaker_;

  zmq::socket_t socket_;
  zmq::socket_t handshaker_socket_;

  std::unordered_map<std::string, client_info> clients;

  std::function<Bytes(Bytes&&)> user_data_handler_;
};

#endif /* SERVER_H */
