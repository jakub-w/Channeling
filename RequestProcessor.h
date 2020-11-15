#ifndef C_REQUESTPROCESSOR_H_
#define C_REQUESTPROCESSOR_H_

#include <future>
#include <mutex>

#include <utility>
#include <zmq.hpp>
#include <zmq_addon.hpp>

#include "SodiumCipherStream/SodiumCipherStream.h"
#include "ProtocolCommon.h"
#include "Util.h"

class RequestProcessor {
 public:
  using MaybeResponse = tl::expected<Bytes, std::error_code>;

  RequestProcessor(zmq::socket_ref server,
                   crypto::SodiumEncryptionContext* enc_ctx,
                   crypto::SodiumDecryptionContext* dec_ctx)
      : server_{server},
        enc_ctx_{enc_ctx},
        dec_ctx_{dec_ctx} {}

  RequestProcessor(RequestProcessor&& other)
      : server_{std::move(other.server_)},
        enc_ctx_{std::move(other.enc_ctx_)},
        dec_ctx_{std::move(other.dec_ctx_)}
  {
    bool was_running = other.running_;
    if (was_running) {
      other.Stop();
    }
    promises_ = std::move(other.promises_);
    if (was_running) {
      Start();
    }
  }

  const RequestProcessor& operator=(RequestProcessor&& other) {
    server_ = std::move(other.server_);
    enc_ctx_ = std::move(other.enc_ctx_);
    dec_ctx_ = std::move(other.dec_ctx_);
    bool was_running = other.running_;
    if (was_running) {
      other.Stop();
    }
    promises_ = std::move(other.promises_);
    if (was_running) {
      Start();
    }
    return *this;
  }

  RequestProcessor(const RequestProcessor& other) = delete;
  const RequestProcessor& operator=(const RequestProcessor& other) = delete;

  ~RequestProcessor() {
    Stop();
  }

  [[nodiscard]]
  std::future<MaybeResponse>
  MakeRequest(const unsigned char* data, size_t size) {
    decltype(promises_)::iterator it;
    const req_id_t num = ++counter_;
    {
      std::lock_guard lck(promises_mtx_);
      it = promises_.insert_or_assign(num, std::promise<MaybeResponse>{})
           .first;
    }
    auto future = it->second.get_future();

    const auto make_error = [this, it](std::errc type) {
      it->second.set_value(
          tl::unexpected{std::make_error_code(type)});
      auto future = it->second.get_future();
      std::lock_guard lck{promises_mtx_};
      promises_.erase(it);
      return future;
    };

    if (not running_) {
      return make_error(std::errc::operation_not_permitted);
    }

    crypto::Bytes ciphertext(size + crypto::NA_SS_ABYTES);
    auto ec = enc_ctx_->Encrypt(data, size,
                                ciphertext.data(), ciphertext.size());
    if (ec) {
      // TODO: Handle ec
      std::cerr << "Error while encrypting data\n";
      return make_error(std::errc::protocol_error);
    }

    std::cout << "Sending to server...\n";
    try {
      std::lock_guard lck(send_mtx_);
      server_.send(zmq::str_buffer(""), zmq::send_flags::sndmore);
      server_.send(make_msg(MessageType::ENCRYPTED_DATA, num, ciphertext),
                   zmq::send_flags::dontwait);
    } catch (const std::exception& e) {
      std::cerr << "Error packing or sending message: " << e.what() << '\n';
      return make_error(std::errc::protocol_error);
    }

    return future;
  }

  inline void Stop() {
    running_ = false;
    if (thread_.joinable()) {
      thread_.join();
    }
  }

  inline void Start() {
    if (running_.exchange(true)) return;
    thread_ = std::thread(&RequestProcessor::server_loop, this);
  }

 private:
  void server_loop() noexcept {
    zmq::message_t message;

    std::array<zmq::pollitem_t, 1> items {{
        zmq::pollitem_t{server_.handle(), 0, ZMQ_POLLIN, 0}
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
          if (recv_from_dealer(server_, message)) { // returned an error code
            std::cerr << "Received bad message. Discarding.\n";
            continue;
          }

          std::cout << "server_loop() - message received: "
                    << to_hex(message.to_string_view()) << '\n';

          std::size_t offset = 0;
          const auto type = Unpack<MessageType>(message.data<char>(),
                                                message.size(), offset)
                            .value_or(MessageType::UNKNOWN);
          const auto request_id = Unpack<req_id_t>(message.data<char>(),
                                                   message.size(), offset)
                                  .value_or(0);
          if (0 == request_id) {
            std::cerr << "Error: server_loop() - request_id is 0!\n";
            continue;
          }

          const auto promise_handle = [this, request_id]() {
            std::lock_guard lck{promises_mtx_};
            return promises_.extract(request_id);
          }();

          if (promise_handle.empty()) {
            std::cerr << "Error: server_loop() - request_id of '"
                      << request_id << "' is invalid!\n";
            continue;
          }

          auto& promise = promise_handle.mapped();

          if (MessageType::ENCRYPTED_DATA != type) {
            std::cerr << "Wrong message received - type: "
                      << MessageTypeName(type) << '\n';
            promise.set_value(make_unexpected(std::errc::protocol_error));
            continue;
          }

          Unpack<Bytes>(message.data<char>(), message.size(), offset)
              .map([this, &promise](crypto::Bytes&& ciphertext){
                const auto maybe_cleartext = dec_ctx_->Decrypt(ciphertext);
                if (std::holds_alternative<std::error_code>(
                        maybe_cleartext)) {
                  std::cerr << "Error decrypting message\n";
                  promise.set_value(
                      make_unexpected(std::errc::protocol_error));
                  return;
                }

                promise.set_value(std::move(
                    std::get<crypto::Bytes>(maybe_cleartext)));
              })
              .or_else([&promise](std::error_code&& /*ec*/){
                std::cerr << "Error unpacking message\n";
                promise.set_value(make_unexpected(std::errc::protocol_error));
              });
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

  inline static std::atomic<req_id_t> counter_ = 0;

  zmq::socket_ref server_;
  crypto::SodiumEncryptionContext* enc_ctx_;
  crypto::SodiumDecryptionContext* dec_ctx_;

  std::map<req_id_t, std::promise<MaybeResponse>> promises_;
  std::mutex promises_mtx_;

  std::mutex send_mtx_;

  std::thread thread_;
  std::atomic_bool running_ = false;
};

#endif  // C_REQUESTPROCESSOR_H_
