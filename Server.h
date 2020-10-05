#ifndef SERVER_H
#define SERVER_H

#include <algorithm>
#include <iostream>
#include <memory>
#include <string_view>
#include <unordered_map>

#include <zmq.h>
#include <zmq.hpp>
#include <zmq_addon.hpp>

#include <msgpack.hpp>

#include "ProtocolCommon.h"
#include "Util.h"

// #include "Handshaker.h"
// #include "CryptoBase.h"

template <class Handshaker>
class Server {
  struct client_info {
    bool authenticated = false;
    CryptoKey encryption_key;
    CryptoKey decryption_key;
  };

 public:
  Server(zmq::context_t& context,
         std::shared_ptr<Handshaker> handshaker)
      : handshaker_{std::move(handshaker)},
        socket_{context, ZMQ_ROUTER},
        handshaker_socket_{context, ZMQ_PAIR},
        crypto_handshaker_socket_{context, ZMQ_PAIR} {}

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
    crypto_handshaker_socket_.connect(handshaker_->GetCryptoAddress());

    std::array<zmq::pollitem_t, 3> items = {{
        {static_cast<void*>(socket_), 0, ZMQ_POLLIN, 0},
        {static_cast<void*>(handshaker_socket_), 0, ZMQ_POLLIN, 0},
        {static_cast<void*>(crypto_handshaker_socket_), 0, ZMQ_POLLIN, 0}
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

      // handshaker crypto socket
      if (items[2].revents & ZMQ_POLLIN) {
        handle_handshaker_crypto();
      }
    }

    std::cout << "Server exiting...\n";
  }

 private:
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

    switch (type) {
      case MessageType::BAD_MESSAGE:
        std::cerr << "Protocol error?\n";
        return;
      case MessageType::DENY:
        std::cerr << "Client denied the connection\n";
        return;
      case MessageType::ID: {
        std::stringstream buffer;
        msgpack::pack(buffer, client_id);
        const auto buffer_str = buffer.str();
        message[2].rebuild(buffer_str.data(), buffer_str.size());
        message.send(socket_);
        return;
      }
      default:
        break;
    }

    if (not clients[client_id].authenticated
        and MessageType::AUTH != type) {
      std::stringstream response_ss;
      msgpack::pack(response_ss, MessageType::DENY);
      std::string response = response_ss.str();
      message[2].rebuild(response.data(), response.size());

      message.send(socket_);
      return;
    }

    switch (type) {
      case MessageType::AUTH: {
        message.send(handshaker_socket_);
        std::cout << "Forwarded to the handshaker\n\n";
        break;
      }
      default: {
        std::cerr << "Unhandled message type: "
                  << MessageTypeName(type) << "\n\n";

        const auto type = MessageType::BAD_MESSAGE;
        message[2].rebuild(&type, sizeof(type));
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
    message.send(socket_);
  }

  void handle_handshaker_crypto() {
    // Messages arriving on this socket are only messages containing
    // sensitive crypto data. The message received here implies that the
    // client authorization succeeded and the handshaker successfully
    // established cryptographic keys with the client.

    std::cout << "Server: message from the crypto handshaker socket.";

    zmq::multipart_t message(crypto_handshaker_socket_);
    std::cout << message.str() << "\n";

    const std::string
        client_id{message[0].data<char>(), message[0].size()};

    {
      auto keypair =
          Unpack<msgpack::type::tuple<CryptoKey, CryptoKey>>(
              message[2].data<char>(), message[2].size())
          .value();

      client_info& ci = clients[client_id];
      ci.authenticated = true;
      ci.encryption_key = std::move(keypair.get<0>());
      ci.decryption_key = std::move(keypair.get<1>());
    }

    // Don't reuse the message to be sure no sensitive data leaks on the
    // line.
    // Don't encrypt the confirmation message. Every message after this
    // one will be encrypted though.

    socket_.send(zmq::buffer(client_id), zmq::send_flags::sndmore);
    socket_.send(zmq::const_buffer("", 0), zmq::send_flags::sndmore);

    std::stringstream buffer;
    msgpack::pack(buffer, MessageType::AUTH_CONFIRM);
    const auto buffer_str = buffer.str();
    socket_.send(zmq::const_buffer(buffer_str.data(), buffer_str.size()),
                 zmq::send_flags::dontwait);

    std::cout << "Sent AUTH_CONFIRM to the client\n\n";
  }

  // -------------------- PRIVATE FIELDS --------------------

  std::atomic_bool run = false;

  std::shared_ptr<Handshaker> handshaker_;

  zmq::socket_t socket_;
  zmq::socket_t handshaker_socket_;
  zmq::socket_t crypto_handshaker_socket_;

  std::unordered_map<std::string, client_info> clients;
};

#endif /* SERVER_H */


// The handshaker should have two sockets: one for passing messages to the
// client, and the second one for passing encryption keys to the server.
// All messages received by the server from the first socket would be passed
// to the client unchanged.
// Messages from the second socket would authenticate the connection.
// To prevent inconsistent state between server and the client, the last
// message about confirming the authentication would be sent only over the
// second socket and the server would react by setting encryption keys,
// setting auth status and sending the proper response to the client.

// Messages should be encrypted. How can we differentiate between encrypted
// and AUTH messages? Send a flag as a first part of the message, specifying
// it? How would it differ from sending the MessageType unencrypted?
