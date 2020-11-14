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

#ifndef CLIENT_H
#define CLIENT_H

#include <chrono>
#include <exception>
#include <future>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <string_view>
#include <system_error>
#include <thread>
#include <variant>

#include <msgpack.hpp>

#include <tl/expected.hpp>

#include <zmq.h>
#include <zmq.hpp>
#include <zmq_addon.hpp>

#include "SodiumCipherStream/SodiumCipherStream.h"

#include "ProtocolCommon.h"
#include "RequestProcessor.h"
#include "Util.h"

template <typename Handshaker>
class Client {
  using HandshakerMessageType = typename Handshaker::HandshakerMessageType;

 public:
  using MaybeResponse = tl::expected<Bytes, std::error_code>;

  Client(std::shared_ptr<zmq::context_t> context,
         std::shared_ptr<Handshaker> handshaker)
      noexcept
      : ctx_{std::move(context)},
        socket_{*ctx_, ZMQ_DEALER},
        handshaker_socket_{*ctx_, ZMQ_PAIR},
        handshaker_{std::move(handshaker)},
        req_processor_{zmq::socket_ref{}, nullptr, nullptr} {}

  ~Client() noexcept {
    Stop();
  }

  [[nodiscard]]
  bool Connect(std::string_view address) {
    socket_.connect(address.data());
    handshaker_->Start();
    handshaker_socket_.connect(handshaker_->GetAddress());

    send_to_server(make_msg(MessageType::ID));

    zmq::message_t message;
    if (recv_from_dealer(socket_, message)) { // error code returned
      std::cerr << "Received bad ID response\n";
      return false;
    }

    std::size_t offset = 0;
    const std::string id = Unpack<std::string>(message.data<char>(),
                                               message.size(),
                                               offset)
                           .value_or("");

    if (id.empty()) {
      std::cerr << "Id received from the server was either blank or bunk\n";
      return false;
    }

    send_to_server(handshaker_->GetAuthRequest(id));

    for(;;) {
      if (recv_from_dealer(socket_, message)) { // returned error code
        std::cerr << "Bad message received\n";
        return false;
      }

      size_t offset = 0;
      const auto type = Unpack<MessageType>(message.data<char>(),
                                            message.size(),
                                            offset)
                        .value_or(MessageType::UNKNOWN);

      switch (type) {
        case MessageType::AUTH_CONFIRM: {
          std::cout << "AUTH_FINISHED received\n";

          auto dec_header = Unpack<crypto::CryptoHeader>(
              message.data<char>(), message.size(), offset);

          if (not (std::holds_alternative<CryptoKey>(decryption_ctx) and
                   std::holds_alternative<CryptoKey>(encryption_ctx))) {
            std::cerr << "Client state inconsistent. Can't proceed with "
                "encryption setup\n";
            return false;
          }
          if (not dec_header.has_value()) {
            std::cerr << "Decryption header was malformed\n";
            return false;
          }

          auto dec_key = std::get<CryptoKey>(decryption_ctx);

          decryption_ctx = crypto::SodiumDecryptionContext{};
          auto& dec_ctx =
              std::get<crypto::SodiumDecryptionContext>(decryption_ctx);

          auto ec = dec_ctx.Initialize(
              dec_key.data(), dec_key.size(),
              dec_header.value().data(), dec_header.value().size());
          if (ec) {
            std::cerr << "Protocol error while initializing decryption "
                "context\n";
            return false;
          }

          auto enc_key = std::get<CryptoKey>(encryption_ctx);
          encryption_ctx = crypto::SodiumEncryptionContext{};
          auto& enc_ctx =
              std::get<crypto::SodiumEncryptionContext>(encryption_ctx);

          crypto::CryptoHeader enc_header;
          ec = enc_ctx.Initialize(enc_key.data(), enc_key.size(),
                                  enc_header.data(), enc_header.size());
          if (ec) {
            std::cerr << "Protocol error while initializing encryption "
                "context\n";
            return false;
          }

          send_to_server(make_msg(MessageType::AUTH_FINISHED, enc_header));
          break;
        }
        case MessageType::AUTH_FINISHED: {
          std::cout << "AUTH_FINISHED received\n";

          auto dec_header = Unpack<crypto::CryptoHeader>(
              message.data<char>(), message.size(), offset);

          if (not (std::holds_alternative<CryptoKey>(decryption_ctx) and
                   std::holds_alternative<crypto::SodiumEncryptionContext>(
                       encryption_ctx))) {
            std::cerr << "Client state inconsistent. Can't proceed with "
                "encryption setup\n";
            return false;
          }
          if (not dec_header.has_value()) {
            std::cerr << "Decryption header was malformed\n";
            return false;
          }

          auto dec_key = std::get<CryptoKey>(decryption_ctx);

          decryption_ctx = crypto::SodiumDecryptionContext{};
          auto& dec_ctx =
              std::get<crypto::SodiumDecryptionContext>(decryption_ctx);

          auto ec = dec_ctx.Initialize(
              dec_key.data(), dec_key.size(),
              dec_header.value().data(), dec_header.value().size());
          if (ec) {
            std::cerr << "Protocol error while initializing decryption "
                "context\n";
            return false;
          }

          return true;
        }
        case MessageType::ACK: {
          if (not (std::holds_alternative<crypto::SodiumDecryptionContext>(
                       decryption_ctx) and
                   std::holds_alternative<crypto::SodiumEncryptionContext>(
                       encryption_ctx))) {
            std::cerr << "State inconsistent\n";
            return false;
          }

          const auto& enc_ctx =
              std::get<crypto::SodiumEncryptionContext>(encryption_ctx);
          const auto& dec_ctx =
              std::get<crypto::SodiumDecryptionContext>(decryption_ctx);

          if (not (enc_ctx.Initialized() and dec_ctx.Initialized())) {
            std::cerr << "State inconsistent\n";
            return false;
          }

          return true;
        }
        case MessageType::DENY:
        case MessageType::BAD_MESSAGE:
        case MessageType::PROTOCOL_ERROR:
          std::cerr << "Not authenticated. Message received:\n"
                    << "Type: " << MessageTypeName(type) << '\n'
                    << "Data: " << to_hex(message.data<char>() + offset,
                                          message.size() - offset) << '\n';
          return false;
        case MessageType::AUTH: {
          zmq::multipart_t msg;
          msg.addstr(id);
          msg.addstr("");
          msg.add(std::move(message));
          msg.send(handshaker_socket_);
          std::cout << "Forwarded to the handshaker\n\n";

          msg.recv(handshaker_socket_);

          auto maybe_message = handle_handshaker_message(msg[2]);

          if (not maybe_message) {
            std::cerr << "Error while processing a handshaker message\n";
            return false;
          }

          send_to_server(std::move(maybe_message.value()));
          break;
        }
        default:
          std::cerr << "Unhandled message type: "
                    << MessageTypeName(type) << "\n\n";
          send_to_server(make_msg(MessageType::BAD_MESSAGE));
          return false;
      }
    }
  }

  /// \return \e std::errc::operation_not_permitted if called when in wrong
  /// state. Make sure \ref Connect() returned \e true.
  /// \return \e std::errc::protocol_error when internal error occured.
  [[nodiscard]]
  std::error_code Start() noexcept {
    if (not (
            std::holds_alternative<crypto::SodiumEncryptionContext>(
                encryption_ctx) and
            std::holds_alternative<crypto::SodiumDecryptionContext>(
                decryption_ctx) and
            socket_.connected())) {
      std::cerr << "Wrong state to call Run(). "
          "The client isn't properly connected to the server.\n";
      return std::make_error_code(std::errc::operation_not_permitted);
    }
    try {
      // TODO: This should be initialized in the last stage of Connect().
      //       RequestProcessor should probably take ownership over the
      //       contexts.
      req_processor_ = RequestProcessor{
        socket_,
        &std::get<crypto::SodiumEncryptionContext>(encryption_ctx),
        &std::get<crypto::SodiumDecryptionContext>(decryption_ctx)};

      req_processor_.Start();
      return {};
    } catch (const std::exception& e) {
      std::cerr << "Start() - " << e.what() << '\n';
      return std::make_error_code(std::errc::protocol_error);
    } catch (...) {
      std::cerr << "Start() - unknown error\n";
      return std::make_error_code(std::errc::protocol_error);
    }
  }

  void Stop() noexcept {
    req_processor_.Stop();
  }

  /// \brief Send a request to the server.
  ///
  /// Must be connected, so make sure you've run \ref Connect() and
  /// \ref Start() first.
  ///
  /// Thread safe.
  ///
  /// \return \e std::errc::operation_not_permitted if client is not running.
  /// \return \e std::errc::protocol_error if internal error occured.
  /// \return Otherwise data returned from the server.
  [[nodiscard]]
  inline MaybeResponse
  Request(const unsigned char* data, size_t size) noexcept {
    return req_processor_.MakeRequest(data, size).get();
  }

  template <typename Container>
  [[nodiscard]]
  inline MaybeResponse
  Request(const Container& data) noexcept {
    return Request(std::data(data), std::size(data));
  }

 private:
  std::optional<zmq::message_t>
  handle_handshaker_message(const zmq::message_t& message) {
    std::size_t offset = 0;
    auto maybe_type = Unpack<HandshakerMessageType>(
        message.data<char>(), message.size(), offset);
    if (not maybe_type) {
      std::cerr << "Error determining message type from the handshaker "
          "socket\n";
      return {};
    }

    std::stringstream buffer;

    switch (maybe_type.value()) {
      case HandshakerMessageType::MESSAGE: {
        std::cout << "Passing handshaker message to peer\n";

        // TODO: Check if the message from the handshaker is DENY or
        //       BAD_MESSAGE and drop the connection if so.

        buffer.write(message.data<char>() + offset,
                     message.size() - offset);
        offset = message.size(); // just in case

        break;
      }
      case HandshakerMessageType::KEYS: {
        std::cout << "Keys received from the handshaker\n";

        auto maybe_keypair =
            Unpack<EncKeys>(message.data<char>(), message.size(), offset);
        if (not maybe_keypair) {
          msgpack::pack(buffer, MessageType::PROTOCOL_ERROR);
          break;
        }

        auto& keypair = maybe_keypair.value();

        const auto& enc_key = keypair.get<0>();
        decryption_ctx = std::move(keypair.get<1>());

        encryption_ctx = crypto::SodiumEncryptionContext{};
        auto& enc_ctx =
            std::get<crypto::SodiumEncryptionContext>(encryption_ctx);

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

        auto maybe_keypair =
            Unpack<EncKeys>(message.data<char>(), message.size(), offset);
        if (not maybe_keypair) {
          msgpack::pack(buffer, MessageType::PROTOCOL_ERROR);
          break;
        }

        auto& keypair = maybe_keypair.value();

        // We don't need a crypto header yet. We can generate it when we
        // receive AUTH_CONFIRM.

        encryption_ctx = std::move(keypair.get<0>());
        decryption_ctx = std::move(keypair.get<1>());

        buffer.write(message.data<char>() + offset,
                     message.size() - offset);
        offset = message.size(); // just in case

        break;
      }
    }

    const auto buffer_str = buffer.str();
    return zmq::message_t{buffer_str.data(), buffer_str.size()};
  }

  inline auto send_to_server(zmq::message_t&& message) {
    socket_.send(zmq::const_buffer(nullptr, 0), zmq::send_flags::sndmore);
    // socket_.send(zmq::str_buffer(""), zmq::send_flags::sndmore);
    return socket_.send(std::move(message), zmq::send_flags::dontwait);
  }

  static constexpr char user_data_socket_address[] =  "inproc://user-data";

  std::shared_ptr<zmq::context_t> ctx_;
  zmq::socket_t socket_;
  zmq::socket_t handshaker_socket_;

  std::shared_ptr<Handshaker> handshaker_;

  std::variant<CryptoKey, crypto::SodiumEncryptionContext>
  encryption_ctx = CryptoKey{};
  std::variant<CryptoKey, crypto::SodiumDecryptionContext>
  decryption_ctx = CryptoKey{};

  RequestProcessor req_processor_;
};

#endif /* CLIENT_H */
