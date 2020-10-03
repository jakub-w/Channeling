project('zeromq-protocol', 'cpp',
        default_options: ['cpp_std=c++17'])

# Build types
if get_option('buildtype').startswith('debug')
  add_project_arguments('-Wall', '-Wextra', '-Werror', '-DFORTIFY_SOURCE=1',
			'-Wno-unused-variable',
                        '-ggdb3',
                        '-fsanitize=address',
                        # '-fsanitize=leak',
                        '-fsanitize=undefined',
			'-g',
			'-Og',
                        language : 'cpp')
  add_project_link_arguments(
    '-lasan',
    # '-ltsan',
    '-lubsan',
    language : 'cpp')
elif get_option('buildtype') == 'release'
  add_project_arguments('-DNDEBUG', '-O3', '-s',
                        language : 'cpp')
endif


# Dependencies
zmq_dep = dependency('libzmq')
sodium_dep = dependency('libsodium')

required_deps = [zmq_dep, sodium_dep]


# Includes
includes = include_directories('msgpack-c/include',
			       'expected/include')

# Binaries
executable('server',
	   sources: ['server-main.cpp'],
	   include_directories: includes,
	   dependencies: required_deps)

executable('client',
	   sources: ['client-main.cpp'],
	   include_directories: includes,
	   dependencies: required_deps)

# executable('test_all',
# 	   sources: ['test/main.cpp'],
# 	   include_directories: includes,
# 	   dependencies: zmq_dep)

executable('zeromq-protocol',
           sources: ['main.cpp'],
	   include_directories: includes,
           dependencies: required_deps)
