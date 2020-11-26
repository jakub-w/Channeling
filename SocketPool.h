#ifndef CHANNELING_SOCKETPOOL_H_
#define CHANNELING_SOCKETPOOL_H_

namespace channeling {
namespace detail {
template <size_t size>
class socket_pool_instance_t
    : public std::enable_shared_from_this<socket_pool_instance_t<size>> {
 public:
  class socket_handle {
    friend class socket_pool_instance_t;

    std::shared_ptr<socket_pool_instance_t> pool;
    int socknum;

    socket_handle(std::shared_ptr<socket_pool_instance_t>&& pool, int socknum)
        : pool{std::move(pool)}, socknum{socknum} {}

   public:
    ~socket_handle() {
      pool->put(socknum);
    }

    inline zmq::socket_t& socket() { return pool->sockets[socknum]; }
  };

  socket_pool_instance_t(std::string_view address) {
    for (size_t i = 0; i < size; ++i) {
      sockets[i] = zmq::socket_t(client_ctx, ZMQ_REQ);
      sockets[i].connect(address.data());
      free_sockets.push_back(i);
    }
  }

  socket_handle get() {
    std::unique_lock lk(mtx);
    cv.wait(lk, [&]{return not free_sockets.empty();});

    int socknum = std::move(free_sockets.front());
    free_sockets.pop_front();

    lk.unlock();
    cv.notify_one();

    return socket_handle{this->shared_from_this(), socknum};
  }

 private:
  void put(int socknum) {
    std::unique_lock lk(mtx);

    free_sockets.push_back(socknum);

    lk.unlock();
    cv.notify_one();
  }

 private:
  std::array<zmq::socket_t, size> sockets;
  std::deque<int> free_sockets;
  std::mutex mtx;
  std::condition_variable cv;

  friend class socket_handle;
};
}

template <size_t size>
class SocketPool {
  std::shared_ptr<detail::socket_pool_instance_t<size>> pool;

 public:
  using SocketHandle =
      typename detail::socket_pool_instance_t<size>::socket_handle;

  SocketPool(std::string_view address)
      : pool{std::make_shared<detail::socket_pool_instance_t<size>>(address)}
  {}

  inline SocketHandle get() {
    return pool->get();
  }
};
}

#endif  // CHANNELING_SOCKETPOOL_H_
