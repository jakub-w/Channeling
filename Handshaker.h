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
      : address_{address_base() + std::to_string(socknum_++)},
        ctx_{get_context()},
        socket_{*ctx_, ZMQ_PAIR} {}

  ~Handshaker() {
    Stop();
  }

  inline constexpr void Start() {
    if (listening.exchange(true)) return;
    thread_ = std::thread(&Handshaker<T>::worker, this);
  }

  inline constexpr void Stop() {
    listening = false;
    if (thread_.joinable()) thread_.join();
  }

  inline zmq::message_t GetAuthRequest(const std::string& id) const {
    return static_cast<const T*>(this)->GetAuthRequest(id);
  }

  inline constexpr const std::string& GetAddress() const {
    return address_;
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
        std::optional<zmq::multipart_t> message(zmq::multipart_t{socket_});
        message = static_cast<T*>(this)->handle_message(
            std::move(message.value()));
        if (message.has_value()) {
          message.value().send(socket_);
        }
      }
    }

    LOG_DEBUG("Handshaker stopped");

    // static_cast<T*>(this)->worker();
  }

  const std::string address_;

  std::atomic_bool listening = false;

  std::shared_ptr<zmq::context_t> ctx_;


 private:
  static const std::string& address_base() {
    static const std::string addr =
        std::string("inproc://handshaker-") + typeid(T).name() + '-';
    return addr;
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
      : socket_{*ctx_, ZMQ_PAIR},
        password_{password} {}

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

  zmq::message_t GetAuthRequest(const std::string&) {
    std::stringstream buffer;
    msgpack::pack(buffer, MessageType::AUTH);
    msgpack::pack(buffer, password_);

    const std::string buffer_str = buffer.str();
    return {buffer_str.data(), buffer_str.size()};
  }

 private:
  std::optional<zmq::multipart_t> handle_message(zmq::multipart_t&& message) {
    LOG_TRACE("Handshaker received: {}\n",message.str());

    std::string client_id{message[0].data<char>(), message[0].size()};
    std::size_t offset = 0;

    auto type = Unpack<MessageType>(message[2].data<char>(),
                                    message[2].size(),
                                    offset)
                .value_or(MessageType::BAD_MESSAGE);
    if (MessageType::AUTH != type) {
      type = MessageType::BAD_MESSAGE;
      message[2].rebuild(&type, sizeof(type));
      return std::optional<zmq::multipart_t>{std::move(message)};
    } else {
      const auto maybe_password =
          Unpack<std::string>(message[2].data<char>(),
                              message[2].size(),
                              offset);

      if (maybe_password and
          maybe_password.value() == password_) {
        msgpack::type::tuple<CryptoKey, CryptoKey> keypair;

        std::stringstream buffer;
        msgpack::pack(buffer, HandshakerMessageType::KEYS);
        msgpack::pack(buffer, keypair);
        const std::string buffer_str = buffer.str();
        message[2].rebuild(buffer_str.data(), buffer_str.size());

        return std::optional<zmq::multipart_t>{std::move(message)};
      } else {
        std::stringstream ss;

        if (not maybe_password) {
          LOG_ERROR("Incomplete message");
          msgpack::pack(ss, MessageType::BAD_MESSAGE);
        } else {
          LOG_ERROR("Wrong password");
          msgpack::pack(ss, MessageType::DENY);
        }

        std::string message_str = ss.str();
        message[2].rebuild(message_str.data(), message_str.size());

        LOG_TRACE("Handshaker sending: {}\n", message.str());

        return std::optional<zmq::multipart_t>{std::move(message)};
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
