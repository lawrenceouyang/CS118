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

#include "hash.hpp"
#include <iostream>
#include <string>


namespace sbt {
namespace util {

std::string
sha1(const std::string& input)
{
  using namespace CryptoPP;

  std::string result;
  SHA1 hash;

  StringSource(input, true, new HashFilter(hash, new StringSink(result)));

  return result;
}

std::vector<uint8_t>
sha1(const std::vector<uint8_t>& input)
{
  using namespace CryptoPP;

  std::vector<uint8_t> result(20, 0);
  SHA1 hash;

  StringSource(&input.front(), input.size(),
               true, new HashFilter(hash, new ArraySink(&result.front(), 20)));

  return result;
}

ConstBufferPtr
sha1(ConstBufferPtr input)
{
  using namespace CryptoPP;

  auto result = make_shared<Buffer>(20, 0);
  SHA1 hash;

  StringSource(input->buf(), input->size(),
               true, new HashFilter(hash, new ArraySink(result->buf(), 20)));

  return result;
}

} // namespace util
} // namespace sbt
