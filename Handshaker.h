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


// The messages handshaker receives are zmq multipart messages. The first
// frame is a client id, the second one is empty, the third one contains
// msgpack packed data with the first object being MessageType and the rest
// a Handshaker-specific, arbitrary data.
template <typename T>
class Handshaker {
 public:
  constexpr Handshaker()
      : address_{address_base_ + std::to_string(socknum_++)},
        crypto_address_{address_base_ + std::to_string(socknum_++)} {}

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

  zmq::message_t GetAuthRequest(const std::string& id) const {
    return static_cast<const T*>(this)->GetAuthRequest(id);
  }

  inline constexpr const std::string& GetAddress() const {
    return address_;
  }

  inline constexpr const std::string& GetCryptoAddress() const {
    return crypto_address_;
  }

 protected:
  inline constexpr void worker() {
    static_cast<T*>(this)->worker();
  }

  const std::string address_;
  const std::string crypto_address_;

  std::atomic_bool listening = false;

 private:
  std::thread thread_;

  static const std::string address_base_;
  static size_t socknum_;

  friend class Channel<T>;
};
template <typename T>
size_t Handshaker<T>::socknum_ = 0;

template <typename T>
const std::string Handshaker<T>::address_base_ =
    std::string("inproc://handshaker-") + typeid(T).name() + '-';

class StupidHandshaker : public Handshaker<StupidHandshaker> {
 public:
  StupidHandshaker(zmq::context_t& context, std::string_view password)
      : socket_{context, ZMQ_PAIR},
        crypto_socket_{context, ZMQ_PAIR},
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
    socket_.bind(address_);
    crypto_socket_.bind(crypto_address_);

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
            std::stringstream ss;
            msgpack::type::tuple<CryptoKey, CryptoKey> keypair;
            msgpack::pack(ss, keypair);

            std::string message_str = ss.str();
            message[2].rebuild(message_str.data(), message_str.size());

            message.send(crypto_socket_);
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

  zmq::socket_t socket_;
  zmq::socket_t crypto_socket_; // Used for sending cryptographic keys
  const std::string password_;

  // std::thread thread_;
  // std::atomic_bool listening = false;

  friend class Handshaker;
};

#endif /* HANDSHAKER_H */

// NOTES:
// Maybe the Handshaker should be a template class that takes Protocol
// template.
