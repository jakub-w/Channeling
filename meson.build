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

project('channeling', 'cpp',
        default_options: ['cpp_std=c++20'])

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
spdlog_dep = dependency('spdlog')

meson.get_compiler('cpp').check_header('tl/expected.hpp', required: true)

required_deps = [zmq_dep, sodium_dep, msgpack_dep, spdlog_dep]


# Subprojects
cipher_stream_proj = subproject('SodiumCipherStream',
				default_options: 'static=true')
cipher_stream_lib = cipher_stream_proj.get_variable('libscs_static')

subproject_incs = include_directories('subprojects')


# Binaries
executable('server',
	   sources: ['server-main.cpp',
		     'EncryptionCommon.cpp'],
	   include_directories: [subproject_incs],
	   link_with: [cipher_stream_lib],
	   dependencies: required_deps)

executable('client',
	   sources: ['client-main.cpp',
		     'EncryptionCommon.cpp',
		     'Client.cpp'],
	   include_directories: [subproject_incs],
	   link_with: [cipher_stream_lib],
	   dependencies: required_deps)

# executable('test_all',
# 	   sources: ['test/main.cpp'],
# 	   include_directories: includes,
# 	   dependencies: zmq_dep)
