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

#ifndef SBT_MSG_BASE_HPP
#define SBT_MSG_BASE_HPP

#include "../util/buffer.hpp"

namespace sbt {
namespace msg {

class Error : public std::runtime_error
{
public:
  explicit
  Error(const std::string& what)
    : std::runtime_error(what)
  {
  }
};

enum MsgId {
  MSG_ID_KEEP_ALIVE = 255, // the keep-alive msg does not have an id

  MSG_ID_CHOKE = 0,
  MSG_ID_UNCHOKE = 1,
  MSG_ID_INTERESTED = 2,
  MSG_ID_NOT_INTERESTED = 3,
  MSG_ID_HAVE = 4,
  MSG_ID_BITFIELD = 5,
  MSG_ID_REQUEST = 6,
  MSG_ID_PIECE = 7,
  MSG_ID_CANCEL = 8,
  MSG_ID_PORT = 9
};

class MsgBase
{
public:
  MsgBase();

  explicit
  MsgBase(uint8_t id, ConstBufferPtr payload = nullptr);

  virtual
  ~MsgBase();

  uint8_t
  getId()
  {
    return m_id;
  }

  void
  setId(uint8_t id)
  {
    m_id = id;
  }

  ConstBufferPtr
  getPayload()
  {
    return m_payload;
  }

  void
  setPayload(ConstBufferPtr payload)
  {
    m_payload = payload;
  }

  ConstBufferPtr
  encode();

  void
  decode(ConstBufferPtr msg);

protected:
  virtual void
  encodePayload() = 0;

  virtual void
  decodePayload() = 0;

  static uint32_t
  decodeUint32(const uint8_t* buf);

  static void
  encodeUint32(std::ostream& os, uint32_t value);


protected:
  static const size_t ID_OFFSET;
  static const size_t PAYLOAD_OFFSET;

  uint8_t m_id;
  ConstBufferPtr m_payload;
};

class KeepAlive : public MsgBase
{
public:
  KeepAlive();

  virtual void
  encodePayload()
  {
  }

  virtual void
  decodePayload()
  {
  }
};

class Choke : public MsgBase
{
public:
  Choke();

  virtual void
  encodePayload()
  {
  }

  virtual void
  decodePayload()
  {
  }
};

class Unchoke : public MsgBase
{
public:
  Unchoke();

  virtual void
  encodePayload()
  {
  }

  virtual void
  decodePayload()
  {
  }
};

class Interested : public MsgBase
{
public:
  Interested();

  virtual void
  encodePayload()
  {
  }

  virtual void
  decodePayload()
  {
  }
};

class NotInterested : public MsgBase
{
public:
  NotInterested();

  virtual void
  encodePayload()
  {
  }

  virtual void
  decodePayload()
  {
  }
};

class Have : public MsgBase
{
public:
  Have();

  explicit
  Have(uint32_t index);

  uint32_t
  getIndex() const
  {
    return m_index;
  }

  void
  setIndex(uint32_t index)
  {
    m_index = index;
  }

  virtual void
  encodePayload();

  virtual void
  decodePayload();

private:
  uint32_t m_index;
};

class Bitfield : public MsgBase
{
public:
  Bitfield();

  explicit
  Bitfield(ConstBufferPtr bitfield);

  ConstBufferPtr
  getBitfield() const
  {
    return m_bitfield;
  }

  void
  setBitfield(ConstBufferPtr bitfield)
  {
    m_bitfield = bitfield;
  }

  virtual void
  encodePayload()
  {
    setPayload(m_bitfield);
  }

  void
  decodePayload()
  {
    m_bitfield = getPayload();
  }

private:
  ConstBufferPtr m_bitfield;
};

class Request : public MsgBase
{
public:
  Request();

  Request(uint32_t index, uint32_t begin, uint32_t length);

  uint32_t
  getIndex() const
  {
    return m_index;
  }

  void
  setIndex(uint32_t index)
  {
    m_index = index;
  }

  uint32_t
  getBegin() const
  {
    return m_begin;
  }

  void
  setBegin(uint32_t begin)
  {
    m_begin = begin;
  }

  uint32_t
  getLength() const
  {
    return m_length;
  }

  void
  setLength(uint32_t length)
  {
    m_length = length;
  }

  virtual void
  encodePayload();

  virtual void
  decodePayload();

private:
  uint32_t m_index;
  uint32_t m_begin;
  uint32_t m_length;
};

class Piece : public MsgBase
{
public:
  Piece();

  Piece(uint32_t index, uint32_t begin, ConstBufferPtr block);

  uint32_t
  getIndex() const
  {
    return m_index;
  }

  void
  setIndex(uint32_t index)
  {
    m_index = index;
  }

  uint32_t
  getBegin() const
  {
    return m_begin;
  }

  void
  setBegin(uint32_t begin)
  {
    m_begin = begin;
  }

  ConstBufferPtr
  getBlock() const
  {
    return m_block;
  }

  void
  setBlock(ConstBufferPtr block)
  {
    m_block = block;
  }

  virtual void
  encodePayload();

  virtual void
  decodePayload();

private:
  uint32_t m_index;
  uint32_t m_begin;
  ConstBufferPtr m_block;
};

class Cancel : public MsgBase
{
public:
  Cancel();

  Cancel(uint32_t index, uint32_t begin, uint32_t length);

  uint32_t
  getIndex() const
  {
    return m_index;
  }

  void
  setIndex(uint32_t index)
  {
    m_index = index;
  }

  uint32_t
  getBegin() const
  {
    return m_begin;
  }

  void
  setBegin(uint32_t begin)
  {
    m_begin = begin;
  }

  uint32_t
  getLength() const
  {
    return m_length;
  }

  void
  setLength(uint32_t length)
  {
    m_length = length;
  }

  virtual void
  encodePayload();

  virtual void
  decodePayload();

private:
  uint32_t m_index;
  uint32_t m_begin;
  uint32_t m_length;
};


} // namespace msg
} // namespace sbt

#endif // SBT_MSG_BASE_HPP
