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

#ifndef SBT_UTIL_HASH_HPP
#define SBT_UTIL_HASH_HPP

#include "cryptopp.hpp"
#include "buffer.hpp"

namespace sbt {
namespace util {

std::string
sha1(const std::string& input);

std::vector<uint8_t>
sha1(const std::vector<uint8_t>& input);

ConstBufferPtr
sha1(ConstBufferPtr input);

} // namespace util
} // namespace sbt

#endif // SBT_UTIL_HASH_HPP
