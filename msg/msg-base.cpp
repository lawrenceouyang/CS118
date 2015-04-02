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

#include "msg-base.hpp"
#include "../util/buffer-stream.hpp"
#include <arpa/inet.h>

namespace sbt {
namespace msg {

const size_t MsgBase::ID_OFFSET = 4;
const size_t MsgBase::PAYLOAD_OFFSET = 5;

MsgBase::MsgBase()
  : m_id(MSG_ID_KEEP_ALIVE)
{
}

MsgBase::MsgBase(uint8_t id, ConstBufferPtr payload)
  : m_id(id)
  , m_payload(payload)
{
}

MsgBase::~MsgBase()
{
}

ConstBufferPtr
MsgBase::encode()
{
  encodePayload();

  OBufferStream os;

  if (m_id == MSG_ID_KEEP_ALIVE)
    return std::make_shared<Buffer>(4, 0);

  uint32_t hLength;
  if (static_cast<bool>(m_payload))
    hLength = m_payload->size() + 1;
  else
    hLength = 1;

  encodeUint32(os, hLength);
  os.put(m_id);

  if (static_cast<bool>(m_payload))
    os.write(reinterpret_cast<const char*>(m_payload->buf()), m_payload->size());

  return os.buf();
}

void
MsgBase::decode(ConstBufferPtr msg)
{
  size_t totalLength = decodeUint32(msg->get());

  if (totalLength == 0) {
    m_id = MSG_ID_KEEP_ALIVE;
    m_payload = nullptr;
    return;
  }

  m_id = (*msg)[ID_OFFSET];

  if (totalLength > 1)
    m_payload = make_shared<Buffer>(msg->get() + PAYLOAD_OFFSET,  totalLength - 1);
  else
    m_payload = nullptr;

  decodePayload();
}

uint32_t
MsgBase::decodeUint32(const uint8_t* buf)
{
  const uint32_t* value  = reinterpret_cast<const uint32_t*>(buf);
  return ntohl(*value);
}

void
MsgBase::encodeUint32(std::ostream& os, uint32_t value)
{
  uint32_t tmpValue = htonl(value);
  os.write(reinterpret_cast<const char*>(&tmpValue), 4);
}

KeepAlive::KeepAlive()
  : MsgBase(MSG_ID_KEEP_ALIVE)
{
}

Choke::Choke()
  : MsgBase(MSG_ID_CHOKE)
{
}

Unchoke::Unchoke()
  : MsgBase(MSG_ID_UNCHOKE)
{
}

Interested::Interested()
  : MsgBase(MSG_ID_INTERESTED)
{
}

NotInterested::NotInterested()
  : MsgBase(MSG_ID_NOT_INTERESTED)
{
}

Have::Have()
  : MsgBase(MSG_ID_HAVE)
{
}

Have::Have(uint32_t index)
  : MsgBase(MSG_ID_HAVE)
  , m_index(index)
{
}

void
Have::encodePayload()
{
  OBufferStream os;

  encodeUint32(os, m_index);

  setPayload(os.buf());
}

void
Have::decodePayload()
{
  if (getPayload()->size() != 4)
    throw Error("Wrong have payload!");

  m_index = decodeUint32(getPayload()->get());
}


Request::Request()
  : MsgBase(MSG_ID_REQUEST)
{
}

Request::Request(uint32_t index, uint32_t begin, uint32_t length)
  : MsgBase(MSG_ID_REQUEST)
  , m_index(index)
  , m_begin(begin)
  , m_length(length)
{
}

void
Request::encodePayload()
{
  OBufferStream os;

  encodeUint32(os, m_index);
  encodeUint32(os, m_begin);
  encodeUint32(os, m_length);

  setPayload(os.buf());
}

void
Request::decodePayload()
{
  if (getPayload()->size() != 12)
    throw Error("Wrong request payload!");

  const uint8_t* payload = getPayload()->get();
  m_index = decodeUint32(payload);
  m_begin = decodeUint32(payload + 4);
  m_length = decodeUint32(payload + 8);
}

Bitfield::Bitfield()
  : MsgBase(MSG_ID_BITFIELD)
{
}

Bitfield::Bitfield(ConstBufferPtr bitfield)
  : MsgBase(MSG_ID_BITFIELD)
  , m_bitfield(bitfield)
{
}

Piece::Piece()
  : MsgBase(MSG_ID_PIECE)
{
}

Piece::Piece(uint32_t index, uint32_t begin, ConstBufferPtr block)
  : MsgBase(MSG_ID_PIECE)
  , m_index(index)
  , m_begin(begin)
  , m_block(block)
{
}

void
Piece::encodePayload()
{
  OBufferStream os;

  encodeUint32(os, m_index);
  encodeUint32(os, m_begin);
  if (static_cast<bool>(m_block))
    os.write(reinterpret_cast<const char*>(m_block->buf()), m_block->size());

  setPayload(os.buf());
}

void
Piece::decodePayload()
{
  if (getPayload()->size() < 8)
    throw Error("Wrong piece payload!");

  const uint8_t* payload = getPayload()->get();
  m_index = decodeUint32(payload);
  m_begin = decodeUint32(payload + 4);
  m_block = make_shared<Buffer>(payload + 8, getPayload()->size() - 8);
}

Cancel::Cancel()
  : MsgBase(MSG_ID_CANCEL)
{
}

Cancel::Cancel(uint32_t index, uint32_t begin, uint32_t length)
  : MsgBase(MSG_ID_CANCEL)
  , m_index(index)
  , m_begin(begin)
  , m_length(length)
{
}

void
Cancel::encodePayload()
{
  OBufferStream os;

  encodeUint32(os, m_index);
  encodeUint32(os, m_begin);
  encodeUint32(os, m_length);

  setPayload(os.buf());
}

void
Cancel::decodePayload()
{
  if (getPayload()->size() != 12)
    throw Error("Wrong request payload!");

  const uint8_t* payload = getPayload()->get();
  m_index = decodeUint32(payload);
  m_begin = decodeUint32(payload + 4);
  m_length = decodeUint32(payload + 8);
}


} // namespace msg
} // namespace sbt
