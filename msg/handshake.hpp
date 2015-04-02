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

#ifndef SBT_MSG_HANDSHAKE_HPP
#define SBT_MSG_HANDSHAKE_HPP

#include "msg-base.hpp"
#include <string>

namespace sbt {
namespace msg {

class HandShake
{
public:
  HandShake();

  HandShake(ConstBufferPtr infoHash, std::string peerId);

  void
  setInfoHash(ConstBufferPtr infoHash)
  {
    m_infoHash = infoHash;
  }

  ConstBufferPtr
  getInfoHash()
  {
    return m_infoHash;
  }

  void
  setPeerId(std::string peerId)
  {
    m_peerId = peerId;
  }

  const std::string&
  getPeerId()
  {
    return m_peerId;
  }

  ConstBufferPtr
  encode();

  void
  decode(ConstBufferPtr msg);

private:
  static const size_t HANDSHAKE_LENGTH;
  static const uint8_t PSTR_LENGTH;
  static const std::string PSTR;
  static const Buffer RESERVED;

  static const size_t INFOHASH_OFFSET;
  static const size_t INFOHASH_LENGTH;
  static const size_t PEERID_OFFSET;
  static const size_t PEERID_LENGTH;

  ConstBufferPtr m_infoHash;
  std::string m_peerId;
};

} // namespace msg
} // namespace sbt

#endif // SBT_MSG_HANDSHAKE_HPP
