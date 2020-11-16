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

#ifndef HANDSHAKER_H
#define HANDSHAKER_H

#include <iostream>

#include <thread>
#include <unordered_map>

#include <zmq.hpp>
#include <zmq_addon.hpp>

#include "msgpack.hpp"

#include "ProtocolCommon.h"

template <typename T>
class Channel;

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
      : address_{address_base() + std::to_string(socknum_++)} {}

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
  inline constexpr void worker() {
    static_cast<T*>(this)->worker();
  }

  const std::string address_;

  std::atomic_bool listening = false;

 private:
  static const std::string& address_base() {
    static const std::string addr =
        std::string("inproc://handshaker-") + typeid(T).name() + '-';
    return addr;
  }

  std::thread thread_;

  static size_t socknum_;

  friend class Channel<T>;
};

template <typename T>
size_t Handshaker<T>::socknum_ = 0;

MSGPACK_ADD_ENUM(HandshakerMessageType_internal);


class StupidHandshaker : public Handshaker<StupidHandshaker> {
 public:
  StupidHandshaker(std::shared_ptr<zmq::context_t> context,
                   std::string_view password)
      : ctx_{std::move(context)},
        socket_{*ctx_, ZMQ_PAIR},
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
  void worker() {
    try {
      socket_.bind(address_);
    } catch (const zmq::error_t& e) {
      std::cerr << "Zmq exception thrown on bind(): " << e.what() << '\n';
      return;
    }

    std::array<zmq::pollitem_t, 1> items = {{
        {static_cast<void*>(socket_), 0, ZMQ_POLLIN, 0},
      }};

    while (listening) {
      zmq::poll(items.data(), items.size(), std::chrono::milliseconds(500));

      // normal socket
      if (items[0].revents & ZMQ_POLLIN) {
        zmq::multipart_t message(socket_);

        std::cout << "Handshaker received: " << message.str() << "\n\n";

        std::string client_id{message[0].data<char>(), message[0].size()};
        std::size_t offset = 0;

        auto type = Unpack<MessageType>(message[2].data<char>(),
                                        message[2].size(),
                                        offset)
                    .value_or(MessageType::BAD_MESSAGE);
        if (MessageType::AUTH != type) {
          type = MessageType::BAD_MESSAGE;
          message[2].rebuild(&type, sizeof(type));
          message.send(socket_);
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

            message.send(socket_);
          } else {
            std::stringstream ss;

            if (not maybe_password) {
              std::cerr << "Incomplete message\n";
              msgpack::pack(ss, MessageType::BAD_MESSAGE);
            } else {
              std::cerr << "Wrong password\n";
              msgpack::pack(ss, MessageType::DENY);
            }

            std::string message_str = ss.str();
            message[2].rebuild(message_str.data(), message_str.size());

            std::cout << message.str() << "\n\n";

            message.send(socket_);
          }
        }
      }
    }
    std::cout << "Handshaker closing...\n";
  }

  std::shared_ptr<zmq::context_t> ctx_;
  zmq::socket_t socket_;
  const std::string password_;

  // std::thread thread_;
  // std::atomic_bool listening = false;

  friend class Handshaker;
};

#endif /* HANDSHAKER_H */
