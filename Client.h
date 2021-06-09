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

#ifndef CHANNELING_CLIENT_H
#define CHANNELING_CLIENT_H

#include <chrono>
#include <exception>
#include <future>
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

#include "Handshaker.h"
#include "Logging.h"
#include "ProtocolCommon.h"
#include "RequestProcessor.h"
#include "Util.h"

namespace Channeling {
template <typename Handshaker>
class Client {
  using HandshakerMessageType = typename Handshaker::HandshakerMessageType;

 public:
  using MaybeResponse = tl::expected<Bytes, std::error_code>;

  Client(std::shared_ptr<Handshaker> handshaker)
      noexcept
      : ctx_{get_context()},
        socket_{*ctx_, ZMQ_DEALER},
        handshaker_socket_{*ctx_, ZMQ_PAIR},
        handshaker_{std::move(handshaker)},
        req_processor_{zmq::socket_ref{}, nullptr, nullptr} {}

  ~Client() noexcept {
    Stop();
  }

  [[nodiscard]]
  bool Connect(std::string_view address) {
    LOG_INFO("Connecting to {}...", address);

    socket_.connect(address.data());
    handshaker_->Start();
    handshaker_socket_.connect(handshaker_->GetAddress());

    LOG_DEBUG("Requesting ID from server");
    send_to_server(make_msg(MessageType::ID));

    zmq::message_t message;
    if (recv_from_dealer(socket_, message)) { // error code returned
      LOG_ERROR("Received bad ID response");
      LOG_TRACE("Contents: {}", message.str());
      return false;
    }

    std::size_t offset = 0;
    const std::string id = Unpack<std::string>(message.data<char>(),
                                               message.size(),
                                               offset)
                           .value_or("");

    if (id.empty()) {
      LOG_ERROR("Id received from the server was either blank or bunk");
      return false;
    }

    LOG_DEBUG("Sending an initial AUTH request to the server");
    send_to_server(handshaker_->GetAuthRequest(id));

    for(;;) {
      if (recv_from_dealer(socket_, message)) { // returned error code
        LOG_ERROR("Bad message received");
        LOG_TRACE("Contents: {}", message.str());
        return false;
      }

      size_t offset = 0;
      const auto type = Unpack<MessageType>(message.data<char>(),
                                            message.size(),
                                            offset)
                        .value_or(MessageType::UNKNOWN);

      LOG_DEBUG("Received {} message from server", MessageTypeName(type));
      LOG_TRACE("Contents: {}", message.str());

      switch (type) {
        case MessageType::AUTH_CONFIRM: {
          auto dec_header = Unpack<crypto::CryptoHeader>(
              message.data<char>(), message.size(), offset);

          if (not (std::holds_alternative<CryptoKey>(decryption_ctx) and
                   std::holds_alternative<CryptoKey>(encryption_ctx))) {
            LOG_ERROR("Client state inconsistent. Can't proceed with "
                      "encryption setup");
            return false;
          }
          if (not dec_header.has_value()) {
            LOG_ERROR("Decryption header was malformed");
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
            LOG_ERROR("Protocol error while initializing decryption "
                      "context");
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
            LOG_ERROR("Protocol error while initializing encryption "
                      "context");
            return false;
          }

          LOG_DEBUG("Sending AUTH_FINISHED message to server");
          send_to_server(make_msg(MessageType::AUTH_FINISHED, enc_header));
          break;
        }
        case MessageType::AUTH_FINISHED: {
          auto dec_header = Unpack<crypto::CryptoHeader>(
              message.data<char>(), message.size(), offset);

          if (not (std::holds_alternative<CryptoKey>(decryption_ctx) and
                   std::holds_alternative<crypto::SodiumEncryptionContext>(
                       encryption_ctx))) {
            LOG_ERROR("Client state inconsistent. Can't proceed with "
                      "encryption setup");
            return false;
          }
          if (not dec_header.has_value()) {
            LOG_ERROR("Decryption header was malformed");
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
            LOG_ERROR("Protocol error while initializing decryption "
                      "context");
            return false;
          }

          LOG_INFO("Handshake with {} successfull", address);
          return true;
        }
        case MessageType::ACK: {
          if (not (std::holds_alternative<crypto::SodiumDecryptionContext>(
                       decryption_ctx) and
                   std::holds_alternative<crypto::SodiumEncryptionContext>(
                       encryption_ctx))) {
            LOG_ERROR("State inconsistent. Encryption not initialized");
            return false;
          }

          const auto& enc_ctx =
              std::get<crypto::SodiumEncryptionContext>(encryption_ctx);
          const auto& dec_ctx =
              std::get<crypto::SodiumDecryptionContext>(decryption_ctx);

          if (not (enc_ctx.Initialized() and dec_ctx.Initialized())) {
            LOG_ERROR("State inconsistent. Encryption not initialized");
            return false;
          }

          LOG_INFO("Handshake with {} successfull", address);
          return true;
        }
        case MessageType::DENY:
        case MessageType::BAD_MESSAGE:
        case MessageType::PROTOCOL_ERROR:
          LOG_ERROR("Not authenticated. Wrong type message received");
          return false;
        case MessageType::AUTH: {
          zmq::multipart_t msg;
          msg.addstr(id);
          msg.addstr("");
          msg.add(std::move(message));
          msg.send(handshaker_socket_);
          LOG_DEBUG("Forwarding a message to the handshaker");

          msg.recv(handshaker_socket_);

          auto maybe_message = handle_handshaker_message(msg[2]);

          if (not maybe_message) {
            LOG_ERROR("Error while processing a handshaker message");
            return false;
          }

          send_to_server(std::move(maybe_message.value()));
          break;
        }
        default:
          LOG_ERROR("Unhandled message type. Sending BAD_MESSAGE to the "
                    "server");
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
      LOG_ERROR("Wrong state to call Run(). "
                "The client isn't properly connected to the server.");
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

      LOG_INFO("Client started");
      return {};
    } catch (const std::exception& e) {
      LOG_ERROR("Error starting the client: {}", e.what());
      return std::make_error_code(std::errc::protocol_error);
    } catch (...) {
      LOG_ERROR("Error starting the client: unknown error");
      return std::make_error_code(std::errc::protocol_error);
    }
  }

  void Stop() noexcept {
    req_processor_.Stop();
    handshaker_->Stop();
    LOG_INFO("Client stopped");
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
  template <typename TimeoutT = decltype(std::chrono::seconds::max())>
  [[nodiscard]]
  inline MaybeResponse
  Request(const unsigned char* data, size_t size,
          const TimeoutT& timeout = std::chrono::seconds::max())
      noexcept {
    auto future = req_processor_.MakeRequest(data, size);
    if (std::future_status::ready != future.wait_for(timeout)) {
      return tl::unexpected(std::make_error_code(std::errc::timed_out));
    }
    try {
      return future.get();
    } catch (const std::future_error& e) {
      if (e.code() == std::future_errc::broken_promise) {
        return tl::unexpected(
            std::make_error_code(std::errc::operation_canceled));
      } else {
        LOG_ERROR("Error getting value from a future: {}", e.what());
        return tl::unexpected(
            std::make_error_code(std::errc::protocol_error));
      }
    }
  }

  template <typename Container,
            typename TimeoutT = decltype(std::chrono::seconds::max())>
  [[nodiscard]]
  inline MaybeResponse
  Request(const Container& data,
          const TimeoutT& timeout = std::chrono::seconds(1800))
      noexcept {
    return Request(std::data(data), std::size(data), timeout);
  }

  [[nodiscard]]
  inline std::future<MaybeResponse>
  RequestAsync(const unsigned char* data, size_t size) noexcept {
    return req_processor_.MakeRequest(data, size);
  }

  template <typename Container>
  [[nodiscard]]
  inline std::future<MaybeResponse>
  RequestAsync(const Container& data) noexcept {
    return req_processor_.MakeRequest(std::data(data), std::size(data));
  }

 private:
  std::optional<zmq::message_t>
  handle_handshaker_message(const zmq::message_t& message) {
    std::size_t offset = 0;
    auto maybe_type = Unpack<HandshakerMessageType>(
        message.data<char>(), message.size(), offset);
    if (not maybe_type) {
      LOG_ERROR("Error determining message type of a message received "
                "from the handshaker");
      return {};
    }

    LOG_DEBUG("Message {} received from the handshaker",
              HandshakerMessageTypeName(maybe_type.value()));

    std::stringstream buffer;

    switch (maybe_type.value()) {
      case HandshakerMessageType::MESSAGE: {
        LOG_DEBUG("Passing handshaker message to the server");

        // TODO: Check if the message from the handshaker is DENY or
        //       BAD_MESSAGE and drop the connection if so.

        buffer.write(message.data<char>() + offset,
                     message.size() - offset);
        offset = message.size(); // just in case

        break;
      }
      case HandshakerMessageType::KEYS: {
        auto maybe_keypair =
            Unpack<EncKeys>(message.data<char>(), message.size(), offset);
        if (not maybe_keypair) {
          LOG_ERROR("Failed to unpack encryption keys received from the "
                    "handshaker");
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
          LOG_ERROR("Error initializing encryption context for client");
          msgpack::pack(buffer, MessageType::PROTOCOL_ERROR);
        } else {
          LOG_DEBUG("Sending AUTH_CONFIRM to the server");
          msgpack::pack(buffer, MessageType::AUTH_CONFIRM);
          msgpack::pack(buffer, enc_header);
        }

        break;
      }
      case HandshakerMessageType::KEYS_AND_MESSAGE: {
        auto maybe_keypair =
            Unpack<EncKeys>(message.data<char>(), message.size(), offset);
        if (not maybe_keypair) {
          LOG_ERROR("Failed to unpack encryption keys received from the "
                    "handshaker");
          msgpack::pack(buffer, MessageType::PROTOCOL_ERROR);
          break;
        }

        auto& keypair = maybe_keypair.value();

        // We don't need a crypto header yet. We can generate it when we
        // receive AUTH_CONFIRM.

        encryption_ctx = std::move(keypair.get<0>());
        decryption_ctx = std::move(keypair.get<1>());

        LOG_ERROR("Passing handshaker message to the server");
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
}

#endif /* CHANNELING_CLIENT_H */
