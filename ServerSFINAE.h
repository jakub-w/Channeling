#ifndef C_SERVERSFINAE_H_
#define C_SERVERSFINAE_H_

namespace {
template <typename T>
struct has_size {
  template <typename A>
  static constexpr std::true_type test(decltype(std::size<A>)*) {
    return std::true_type();
  }

  template <typename A,
            std::enable_if_t<std::is_array_v<A>, bool> = 0>
  static constexpr std::true_type test(
      decltype(std::size<std::remove_extent_t<A>, std::extent_v<A>>)*) {
    return std::true_type();
  }

  template <typename A>
  static constexpr std::false_type test(...) {
    return std::false_type();
  }

 public:
  typedef decltype(test<T>(0)) type;
  static const bool value = type::value;
};

template <typename T>
struct has_data {
  template <typename A>
  static constexpr std::true_type test(
      decltype(std::data(std::declval<A>()))*) {
    return std::true_type();
  }

  template <typename A,
            std::enable_if_t<std::is_array_v<A>, bool> = 0>
  static constexpr std::true_type test(
      decltype(std::data<std::remove_extent_t<A>, std::extent_v<A>>)*) {
    return std::true_type();
  }

  template <typename A>
  static constexpr std::false_type test(...) {
    return std::false_type();
  }

 public:
  typedef decltype(test<T>(0)) type;
  static const bool value = type::value;
};

template <typename T>
inline constexpr bool has_size_v = has_size<T>::value;

template <typename T>
inline constexpr bool has_data_v = has_data<T>::value;

template <typename T>
inline constexpr bool has_data_and_size_v = has_size_v<T> and has_data_v<T>;
}

#endif  // C_SERVERSFINAE_H_
