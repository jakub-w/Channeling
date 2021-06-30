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

#ifndef CHANNELING_HANDSHAKER_H
#define CHANNELING_HANDSHAKER_H

#include <chrono>
#include <thread>
#include <unordered_map>

#include <zmq.hpp>
#include <zmq_addon.hpp>

#include <msgpack.hpp>

#include "ProtocolCommon.h"
#include "Util.h"

namespace Channeling {
namespace {
enum class HandshakerMessageType_internal {
    MESSAGE,
    KEYS,
    KEYS_AND_MESSAGE
  };
}

constexpr auto
HandshakerMessageTypeName(HandshakerMessageType_internal type) {
  switch (type) {
    case HandshakerMessageType_internal::MESSAGE:
      return "MESSAGE";
    case HandshakerMessageType_internal::KEYS:
      return "KEYS";
    case HandshakerMessageType_internal::KEYS_AND_MESSAGE:
      return "KEYS_AND_MESSAGE";
  }
  return "UNKNOWN";
}

// The messages handshaker receives are zmq multipart messages. The first
// frame is a client id, the second one is empty, the third one contains
// msgpack packed data with the first object being MessageType and the rest
// a Handshaker-specific, arbitrary data.
template <typename T>
class Handshaker {
 public:
  using HandshakerMessageType = HandshakerMessageType_internal;

  constexpr Handshaker()
      : address_{address_base() + std::to_string(++socknum_)},
        ctx_{get_context()},
        socket_{*ctx_, ZMQ_PAIR} {
    // If the handshaker has static lifetime spdlog could deinitialize before
    // the handshaker is destroyed, which would cause a segfault. This is a
    // workaround.
    spdlog::default_logger();
  }

  ~Handshaker() {
    Stop();
  }

  inline void Run() {
    if (listening.exchange(true)) return;
    worker();
  }

  inline void RunAsync() {
    if (listening.exchange(true)) return;
    thread_ = std::thread(&Handshaker<T>::worker, this);
  }

  inline void Stop() {
    // LOG_DEBUG("Handshaker stopping...");
    listening = false;
    if (thread_.joinable()) thread_.join();
  }

  inline constexpr const std::string& GetAddress() const {
    return address_;
  }

  inline constexpr void SetAddress(std::string_view address) {
    address_ = address;
  }

  static std::string make_address() {
    return address_base() + std::to_string(++socknum_);
  }

 protected:
  inline void worker() {
    LOG_DEBUG("Handshaker started...");
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
        zmq::poll(std::data(items), std::size(items),
                  std::chrono::milliseconds(500));
      } catch (const zmq::error_t& e) {
        if (EINTR != e.num()) {
          LOG_ERROR("Handshaker poll error: {}", e.what());
        }
        break;
      }

      if (items[0].revents & ZMQ_POLLIN) {
        zmq::multipart_t message(zmq::multipart_t{socket_});

        if (3 != message.size()) {
          LOG_ERROR("Handshaker received an unexpectedly structured "
                    "message. Frames: {}. Discarding.", message.size());
          LOG_TRACE("Contents: {}", message.str());
          continue;
        }

        std::size_t offset{0};
        const auto client_id =
            std::string{message[0].data<char>(), message[0].size()};

        const char* data = message[2].data<char>();
        const size_t data_size = message[2].size();

        const auto type = Unpack<MessageType>(data, data_size, offset)
                          .value_or(MessageType::BAD_MESSAGE);

        LOG_DEBUG(
            "Handshaker received a message. Type: {}, client id: {}",
            MessageTypeName(type), client_id);
        LOG_TRACE("Contents: {}", message.str());

        if (type == MessageType::AUTH_REQUEST) {
          message[2] = handle_auth_request(data + offset, data_size - offset);
          LOG_TRACE("Handshaker responding to AUTH_REQUEST. Contents: {}",
                    message.str());
          message.send(socket_);
          continue;
        }

        zmq::message_t out_data = static_cast<T*>(this)->handle_message(
            client_id, data, data_size);

        LOG_TRACE("Contents: {}", to_hex(out_data.data(), out_data.size()));

        message[2] = std::move(out_data);

        message.send(socket_);
      }
    }

    LOG_DEBUG("Handshaker stopped");
  }

  std::string address_;

  std::atomic_bool listening = false;

  std::shared_ptr<zmq::context_t> ctx_;


 private:
  static const std::string& address_base() {
    static const std::string addr =
        std::string("inproc://handshaker-") + typeid(T).name() + '-';
    return addr;
  }

  inline zmq::message_t get_auth_request(const std::string& id) const {
    return static_cast<const T*>(this)->get_auth_request(id);
  }

  zmq::message_t handle_auth_request(const char* data, size_t size) {
    auto auth_client_id = Unpack<std::string>(data, size);

    if (not auth_client_id) {
      LOG_ERROR("Bad auth request received");
      return make_msg(MessageType::BAD_MESSAGE);
    }

    return static_cast<T*>(this)->get_auth_request(auth_client_id.value());
  }

  std::thread thread_;

  static size_t socknum_;
  zmq::socket_t socket_;
};

template <typename T>
size_t Handshaker<T>::socknum_ = 0;


class StupidHandshaker : public Handshaker<StupidHandshaker> {
 public:
  StupidHandshaker(std::string_view password)
      : password_{password} {}

  StupidHandshaker(const StupidHandshaker&) = delete;
  StupidHandshaker operator=(const StupidHandshaker&) = delete;

  ~StupidHandshaker() {
    Stop();
  }

  // constexpr void Start() {
  //   if (listening.exchange(true)) return;

  //   thread_ = std::thread(&StupidHandshaker::worker, this);
  // }

  // constexpr void Stop() {
  //   listening = false;
  //   if (thread_.joinable()) thread_.join();
  // }

  zmq::message_t get_auth_request(const std::string&) {
    std::stringstream buffer;
    msgpack::pack(buffer, MessageType::AUTH);
    msgpack::pack(buffer, password_);

    const std::string buffer_str = buffer.str();
    return {buffer_str.data(), buffer_str.size()};
  }

 private:
  zmq::message_t handle_message(const std::string& /* client_id */,
                                const char* data,
                                size_t data_size) const {
    std::size_t offset = 0;

    auto type = Unpack<MessageType>(data, data_size, offset)
                .value_or(MessageType::BAD_MESSAGE);
    if (MessageType::AUTH != type) {
      return make_msg(MessageType::BAD_MESSAGE);
    } else {
      const auto maybe_password =
          Unpack<std::string>(data, data_size, offset);

      if (maybe_password and
          maybe_password.value() == password_) {
        msgpack::type::tuple<CryptoKey, CryptoKey> keypair;

        std::stringstream buffer;
        msgpack::pack(buffer, HandshakerMessageType::KEYS);
        msgpack::pack(buffer, keypair);
        const std::string buffer_str = buffer.str();

        return zmq::message_t{buffer_str.data(), buffer_str.size()};
      } else {
        std::stringstream buffer;

        if (not maybe_password) {
          LOG_ERROR("Incomplete message");
          msgpack::pack(buffer, MessageType::BAD_MESSAGE);
        } else {
          LOG_ERROR("Wrong password");
          msgpack::pack(buffer, MessageType::DENY);
        }

        std::string buffer_str = buffer.str();
        LOG_TRACE("Handshaker sending: {}\n", buffer_str);

        return zmq::message_t{buffer_str.data(), buffer_str.size()};
      }
    }
  }

  zmq::socket_t socket_;
  const std::string password_;

  friend class Handshaker;
};
}

MSGPACK_ADD_ENUM(Channeling::HandshakerMessageType_internal);

#endif /* CHANNELING_HANDSHAKER_H */
