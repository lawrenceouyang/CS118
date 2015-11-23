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

#include "handshake.hpp"
#include "../util/buffer-stream.hpp"

namespace sbt {
namespace msg {

const size_t HandShake::HANDSHAKE_LENGTH = 68;
const uint8_t HandShake::PSTR_LENGTH = 19;
const std::string HandShake::PSTR("BitTorrent protocol");
const Buffer HandShake::RESERVED(8, 0);

const size_t HandShake::INFOHASH_OFFSET = 28;
const size_t HandShake::INFOHASH_LENGTH = 20;
const size_t HandShake::PEERID_OFFSET = 48;
const size_t HandShake::PEERID_LENGTH = 20;

HandShake::HandShake()
{
}

HandShake::HandShake(ConstBufferPtr infoHash, std::string peerId)
  : m_infoHash(infoHash)
  , m_peerId(peerId)
{
}

ConstBufferPtr
HandShake::encode()
{
  OBufferStream os;

  os.write(reinterpret_cast<const char*>(&PSTR_LENGTH), 1);
  os.write(&PSTR.front(), PSTR.size());
  os.write(reinterpret_cast<const char*>(&RESERVED.front()), RESERVED.size());
  os.write(reinterpret_cast<const char*>(&m_infoHash->front()), m_infoHash->size());
  os.write(&m_peerId.front(), m_peerId.size());

  return os.buf();
}

void
HandShake::decode(ConstBufferPtr msg)
{
  if (msg->size() != HANDSHAKE_LENGTH)
    throw Error("Wrong handshake length");

  m_infoHash = std::make_shared<Buffer>(&(*msg)[INFOHASH_OFFSET], INFOHASH_LENGTH);
  m_peerId = std::string(reinterpret_cast<const char*>(&(*msg)[PEERID_OFFSET]), PEERID_LENGTH);
}


} // namespace msg
} // namespace sbt
