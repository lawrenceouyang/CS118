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

#ifndef SBT_HTTP_URL_ENCODING_HPP
#define SBT_HTTP_URL_ENCODING_HPP

#include "../common.hpp"
#include "../util/buffer.hpp"
#include <string>

namespace sbt {
namespace url {

std::string
encode(const uint8_t* buf, size_t size);

ConstBufferPtr
decode(const std::string& input);

} // namespace url
} // namespace sbt

#endif // SBT_HTTP_URL_ENCODING_HPP
