/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014,  Regents of the University of California
 *
 * This file is part of Simple BT.
 * See AUTHORS.md for complete list of Simple BT authors and contributors.
 *
 * NSL is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NSL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NSL, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * \author Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef SBT_COMMON_HPP
#define SBT_COMMON_HPP

#include "config.hpp"

#ifdef HAVE_TESTS
#define SBT_VIRTUAL_WITH_TESTS virtual
#define SBT_PUBLIC_WITH_TESTS_ELSE_PROTECTED public
#define SBT_PUBLIC_WITH_TESTS_ELSE_PRIVATE public
#define SBT_PROTECTED_WITH_TESTS_ELSE_PRIVATE protected
#else
#define SBT_VIRTUAL_WITH_TESTS
#define SBT_PUBLIC_WITH_TESTS_ELSE_PROTECTED protected
#define SBT_PUBLIC_WITH_TESTS_ELSE_PRIVATE private
#define SBT_PROTECTED_WITH_TESTS_ELSE_PRIVATE private
#endif

// require C++11
#if __cplusplus < 201103L && !defined(__GXX_EXPERIMENTAL_CXX0X__)
#  error "Simple BT must be compiled using the C++11 standard"
#endif

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <unistd.h>
#include <iostream>

namespace sbt {

using std::shared_ptr;
using std::unique_ptr;
using std::weak_ptr;
using std::bad_weak_ptr;
using std::make_shared;
using std::enable_shared_from_this;

using std::static_pointer_cast;
using std::dynamic_pointer_cast;
using std::const_pointer_cast;

using std::function;
using std::bind;
using std::ref;
using std::cref;

} // namespace sbt


#endif // SBT_COMMON_HPP
