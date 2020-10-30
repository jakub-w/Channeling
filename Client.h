#ifndef CLIENT_H
#define CLIENT_H

#include <chrono>
#include <exception>
#include <iostream>
#include <optional>
#include <system_error>
#include <thread>
#include <variant>

#include <zmq.h>
#include <zmq.hpp>
#include <zmq_addon.hpp>

#include "SodiumCipherStream.h"

#include "ProtocolCommon.h"
#include "Util.h"
#include "msgpack/v3/unpack_decl.hpp"
#include "tl/expected.hpp"

template <typename Handshaker>
class Client {
  using HandshakerMessageType = typename Handshaker::HandshakerMessageType;

 public:
  Client(zmq::context_t& context, std::shared_ptr<Handshaker> handshaker)
      noexcept
      : socket_{context, ZMQ_REQ},
        handshaker_socket_{context, ZMQ_PAIR},
        handshaker_{std::move(handshaker)},
        user_data_socket_resp_{context, ZMQ_PAIR},
        user_data_socket_req_{context, ZMQ_PAIR}
  {}

  ~Client() noexcept {
    Stop();
    if (user_data_thread_.joinable()) {
      try {
        user_data_thread_.join();
      } catch (...) {}
    }
  }

  [[nodiscard]]
  bool Connect(std::string_view address) {
    socket_.connect(address.data());
    handshaker_->Start();
    handshaker_socket_.connect(handshaker_->GetAddress());

    socket_.send(make_msg(MessageType::ID), zmq::send_flags::none);

    zmq::message_t id_response;
    while (not socket_.recv(id_response).has_value());

    std::size_t offset = 0;
    const std::string id = Unpack<std::string>(id_response.data<char>(),
                                               id_response.size(),
                                               offset)
                           .value_or("");

    if (id.empty()) {
      std::cerr << "Id received from the server was either blank or bunk\n";
      return false;
    }

    socket_.send(handshaker_->GetAuthRequest(id), zmq::send_flags::none);

    for(;;) {
      // FIXME: ZMQ_REQ
      zmq::message_t message;
      // NOTE: If it doesn't have a value, it means the error EAGAIN was
      //       received.
      if (not socket_.recv(message).has_value()) continue;

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

          socket_.send(make_msg(MessageType::AUTH_FINISHED,enc_header),
                       zmq::send_flags::none);
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

          socket_.send(maybe_message.value(), zmq::send_flags::none);
          break;
        }
        default:
          std::cerr << "Unhandled message type: "
                    << MessageTypeName(type) << "\n\n";
          const auto bad_msg = MessageType::BAD_MESSAGE;
          message.rebuild(&bad_msg, sizeof(bad_msg));
          socket_.send(message, zmq::send_flags::none);
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
      user_data_socket_resp_.bind(user_data_socket_address);
      user_data_socket_req_.connect(user_data_socket_address);
      running_ = true;

      user_data_thread_ =
          std::thread(&Client<Handshaker>::user_data_loop, this);

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
    running_ = false;
  }

  /// \brief Send a request to the server.
  ///
  /// Must be connected, so make sure you've run \ref Connect() and
  /// \ref Start() first.
  ///
  /// Thread safe.
  ///
  /// \return \e std::errc::no_message_available if there's no data.
  /// \return \e std::errc::operation_not_permitted if client is not running.
  /// \return \e std::errc::protocol_error if internal error occured.
  /// \return Otherwise data returned from the server.
  [[nodiscard]]
  tl::expected<Bytes, std::error_code> Request(const Bytes& data) noexcept {
    const auto make_unexpected = [](std::errc errc) {
      return tl::unexpected{std::make_error_code(errc)};
    };

    try {
      if (not running_) {
        return make_unexpected(std::errc::operation_not_permitted);
      }

      zmq::message_t message{data.data(), data.size()};

      std::cout << "Request() - Passing the message\n";
      user_data_socket_req_.send(message, zmq::send_flags::none);
      std::cout << "Request() - Message sent, waiting for a response\n";

      while (not user_data_socket_req_.recv(message).has_value()) {}
      std::cout << "Request() - Response received: " << message << '\n';

      if (message.size() == 0) {
        return make_unexpected(std::errc::no_message_available);
      }
      return Bytes(message.data<unsigned char>(),
                   message.data<unsigned char>() + message.size());
    } catch (const std::exception& e) {
      std::cerr << "Request() - error: " << e.what() << '\n';
      return make_unexpected(std::errc::protocol_error);
    } catch (...) {
      std::cerr << "Request() - unknown error\n";
      return make_unexpected(std::errc::protocol_error);
    }
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

  void user_data_loop() noexcept {
    zmq::message_t message;

    std::array<zmq::pollitem_t, 1> items = {{
        zmq::pollitem_t{user_data_socket_resp_, 0, ZMQ_POLLIN, 0}
      }};

    while (running_) {
      try {
        zmq::poll(items.data(), items.size(), std::chrono::milliseconds(500));
      } catch (const zmq::error_t& e) {
        std::cerr << "Error on poll: " << e.what() << '\n';
        running_ = false;
        return;
      }

      if (items[0].revents & ZMQ_POLLIN) {
        try {
          if (not user_data_socket_resp_.recv(message)) continue;
          std::cout << "Run() - message received: " << message << '\n';;

          auto& enc_ctx =
              std::get<crypto::SodiumEncryptionContext>(encryption_ctx);
          crypto::Bytes ciphertext(message.size() + crypto::NA_SS_ABYTES);
          auto ec = enc_ctx.Encrypt(message.data<unsigned char>(),
                                    message.size(),
                                    ciphertext.data(),
                                    ciphertext.size());

          if (ec) {
            // TODO: Handle ec
            std::cerr << "Error while encrypting data\n";
            user_data_socket_resp_.send(zmq::message_t(),
                                        zmq::send_flags::none);
            continue;
          }

          std::cout << "Sending to server...\n";
          socket_.send(make_msg(MessageType::ENCRYPTED_DATA, ciphertext),
                       zmq::send_flags::none);
          while (not socket_.recv(message));

          std::size_t offset = 0;
          auto type = Unpack<MessageType>(message.data<char>(),
                                          message.size(), offset)
                      .value_or(MessageType::UNKNOWN);

          if (MessageType::ENCRYPTED_DATA != type) {
            // TODO: Handle more types
            std::cerr << "Wrong message received - type: "
                      << MessageTypeName(type) << '\n';
            user_data_socket_resp_.send(zmq::message_t(),
                                        zmq::send_flags::none);
            continue;
          }

          Unpack<Bytes>(message.data<char>(), message.size(), offset)
              .map([this, &message](crypto::Bytes&& ciphertext){
                auto& dec_ctx =
                    std::get<crypto::SodiumDecryptionContext>(decryption_ctx);
                auto maybe_cleartext = dec_ctx.Decrypt(ciphertext);

                if (std::holds_alternative<std::error_code>(
                        maybe_cleartext)) {
                  std::cerr << "Error decrypting message\n";
                  message.rebuild("", 0);
                  return;
                }

                const auto& cleartext =
                    std::get<crypto::Bytes>(maybe_cleartext);
                message.rebuild(cleartext.data(), cleartext.size());
              })
              .or_else([this, &message](std::error_code&& /*ec*/){
                std::cerr << "Error unpacking message\n";
                message.rebuild("", 0);
              });

          user_data_socket_resp_.send(message, zmq::send_flags::none);
        } catch (const std::exception& e) {
          std::cerr << "Error when handling user data message: " << e.what()
                    << '\n';
          running_ = false;
          return;
        } catch (...) {
          std::cerr << "Error when handling user data message\n";
          running_ = false;
          return;
        }
      }
    }
  }

  static constexpr char user_data_socket_address[] =  "inproc://user-data";

  zmq::socket_t socket_;
  zmq::socket_t handshaker_socket_;

  std::shared_ptr<Handshaker> handshaker_;

  std::variant<CryptoKey, crypto::SodiumEncryptionContext>
  encryption_ctx = CryptoKey{};
  std::variant<CryptoKey, crypto::SodiumDecryptionContext>
  decryption_ctx = CryptoKey{};

  zmq::socket_t user_data_socket_resp_;
  zmq::socket_t user_data_socket_req_;
  std::atomic_bool running_ = false;
  std::thread user_data_thread_;
};

#endif /* CLIENT_H */
