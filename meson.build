# Copyright (C) 2020 by Jakub Wojciech

# This file is part of Channeling

# Lelo Remote Music Player is free software: you can redistribute it
# and/or modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation, either version 3 of
# the License, or (at your option) any later version.

# Lelo Remote Music Player is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with Lelo Remote Music Player. If not, see
# <https://www.gnu.org/licenses/>.

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
  add_project_arguments('-DNDEBUG', '-O2', language : 'cpp')
endif


# Dependencies
zmq_dep = dependency('libzmq')
sodium_dep = dependency('libsodium')
msgpack_dep = dependency('msgpack')

required_deps = [zmq_dep, sodium_dep, msgpack_dep]


# Includes
includes = include_directories('expected/include')


# Subprojects
cipher_stream_inc = include_directories('SodiumCipherStream')


# Binaries
executable('server',
	   sources: ['server-main.cpp',
		     'EncryptionCommon.cpp',
		     'SodiumCipherStream/SodiumCipherStream.cpp'],
	   include_directories: [includes, cipher_stream_inc],
	   dependencies: required_deps)

executable('client',
	   sources: ['client-main.cpp',
		     'EncryptionCommon.cpp',
		     'SodiumCipherStream/SodiumCipherStream.cpp'],
	   include_directories: [includes, cipher_stream_inc],
	   dependencies: required_deps)

# executable('test_all',
# 	   sources: ['test/main.cpp'],
# 	   include_directories: includes,
# 	   dependencies: zmq_dep)
