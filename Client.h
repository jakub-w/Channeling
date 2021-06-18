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
class ClientBase {
  using HandshakerMessageType = HandshakerMessageType_internal;

 public:
  using MaybeResponse = tl::expected<Bytes, std::error_code>;

  explicit ClientBase(std::string_view handshaker_address) noexcept
      : handshaker_address_{handshaker_address},
        ctx_{get_context()},
        socket_{*ctx_, ZMQ_DEALER},
        handshaker_socket_{*ctx_, ZMQ_PAIR},
        req_processor_(zmq::socket_ref{}, nullptr, nullptr) {}

  virtual inline ~ClientBase() noexcept {
    Stop();
  }

  [[nodiscard]]
  bool Connect(std::string_view address);

  inline void Stop() noexcept {
    req_processor_.Stop();
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
  /// \return \e std::errc::operation_not_permitted if called when in wrong
  /// state. Make sure \ref Connect() returned \e true.
  /// \return \e std::errc::protocol_error when internal error occured.
  [[nodiscard]]
  std::error_code run_async() noexcept;

 protected:
  const std::string handshaker_address_;

 private:
  tl::expected<zmq::message_t, std::error_code>
  get_auth_request(const std::string& id) noexcept;

  std::optional<zmq::message_t>
  handle_handshaker_message(const zmq::message_t& message);

  // TODO: Make it noexcept
  inline auto send_to_server(zmq::message_t&& message) {
    socket_.send(zmq::const_buffer(nullptr, 0), zmq::send_flags::sndmore);
    return socket_.send(std::move(message), zmq::send_flags::dontwait);
  }

  std::shared_ptr<zmq::context_t> ctx_;
  zmq::socket_t socket_;
  zmq::socket_t handshaker_socket_;

  std::variant<CryptoKey, crypto::SodiumEncryptionContext>
  encryption_ctx = CryptoKey{};
  std::variant<CryptoKey, crypto::SodiumDecryptionContext>
  decryption_ctx = CryptoKey{};

  RequestProcessor req_processor_;
};

template <typename Handshaker>
class Client : public ClientBase {
  Handshaker handshaker_;

 public:
  /// \param args Arguments for \ref Handshaker.
  template <typename... Args>
  Client(Args... args) : ClientBase{Handshaker::make_address()},
                         handshaker_{std::forward<Args>(args)...} {
    handshaker_.SetAddress(handshaker_address_);
    handshaker_.RunAsync();
  }

  virtual ~Client() {
    handshaker_.Stop();
  }
};

/// \brief Create a client.
/// \param args Arguments for \ref Handshaker's constructor.
template <typename Handshaker>
inline auto MakeClient(auto... args) {
  return Client<Handshaker>(std::forward<decltype(args)>(args)...);
}
}

#endif /* CHANNELING_CLIENT_H */
