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
 * \author Alex Afanasyev <alexander.afanasyev@ucla.edu>
 */


#include "buffer.hpp"
#include "cryptopp.hpp"

namespace sbt {

#if HAVE_IS_MOVE_CONSTRUCTIBLE
static_assert(std::is_move_constructible<Buffer>::value,
              "Buffer must be MoveConstructible");
#endif // HAVE_IS_MOVE_CONSTRUCTIBLE

#if HAVE_IS_MOVE_ASSIGNABLE
static_assert(std::is_move_assignable<Buffer>::value,
              "Buffer must be MoveAssignable");
#endif // HAVE_IS_MOVE_ASSIGNABLE

Buffer::Buffer()
{
}

Buffer::Buffer(size_t size)
  : std::vector<uint8_t>(size, 0)
{
}

Buffer::Buffer(const void* buf, size_t length)
  : std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(buf),
                         reinterpret_cast<const uint8_t*>(buf) + length)
{
}

void
Buffer::print(std::ostream& os) const
{
  using namespace CryptoPP;

  StringSource(&front(), size(), true, new HexEncoder(new FileSink(os), false));
}

} // namespace sbt
