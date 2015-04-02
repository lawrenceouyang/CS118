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

#include "meta-info.hpp"
#include "util/buffer-stream.hpp"
#include "util/hash.hpp"

using std::string;
using std::make_shared;
using std::dynamic_pointer_cast;

namespace sbt {

const std::string MetaInfo::ANNOUNCE("announce");
const std::string MetaInfo::INFO("info");
const std::string MetaInfo::NAME("name");
const std::string MetaInfo::PIECE_LENGTH("piece length");
const std::string MetaInfo::PIECES("pieces");
const std::string MetaInfo::LENGTH("length");
const std::string MetaInfo::FILES("files");
const std::string MetaInfo::PATH("path");

std::shared_ptr<bencoding::Dictionary>
MetaInfo::File::encode() const
{
  auto dict = make_shared<bencoding::Dictionary>();

  dict->insert(LENGTH, make_shared<bencoding::Integer>(length));

  auto p = make_shared<bencoding::List>();

  for (const auto& i : path)
    p->append(make_shared<bencoding::String>(i));

  dict->insert(PATH, p);

  return dict;
}

void
MetaInfo::File::decode(const bencoding::Dictionary& dict)
{
  auto l = dict.get(LENGTH);

  if (static_cast<bool>(l))
    length = dynamic_pointer_cast<bencoding::Integer>(l)->getValue();
  else
    throw Error("No length in files");

  auto p = dict.get(PATH);
  if (static_cast<bool>(p)) {
    auto list = dynamic_pointer_cast<bencoding::List>(p)->getList();

    for (const auto& i : list) {
      path.push_back(dynamic_pointer_cast<bencoding::String>(i)->toString());
    }
  }
  else
    throw Error("No path in files");
}

MetaInfo::MetaInfo()
  : m_info(new bencoding::Dictionary)
{
  m_root.insert(INFO, m_info);
}

void
MetaInfo::wireEncode(std::ostream& os) const
{
  m_root.wireEncode(os);
}

void
MetaInfo::wireDecode(std::istream& is)
{
  m_root = bencoding::Dictionary();
  m_root.wireDecode(is);

  if (static_cast<bool>(m_root.get(INFO))) {
    m_info = dynamic_pointer_cast<bencoding::Dictionary>(m_root.get(INFO));
  }
  else {
    m_root = bencoding::Dictionary();
    throw bencoding::Error("no info in meta-info");
  }
}

void
MetaInfo::setAnnounce(const std::string& announce)
{
  m_root.insert(ANNOUNCE, make_shared<bencoding::String>(announce));
}

std::string
MetaInfo::getAnnounce()
{
  auto i = m_root.get(ANNOUNCE);

  if (static_cast<bool>(i)) {
    return dynamic_pointer_cast<bencoding::String>(i)->toString();
  }
  else
    return string();
}

void
MetaInfo::setName(const std::string& name)
{
  m_info->insert(NAME, make_shared<bencoding::String>(name));
}

std::string
MetaInfo::getName()
{
  auto i = m_info->get(NAME);

  if (static_cast<bool>(i)) {
    return dynamic_pointer_cast<bencoding::String>(i)->toString();
  }
  else
    return string();
}

void
MetaInfo::setPieceLength(int64_t length)
{
  m_info->insert(PIECE_LENGTH, make_shared<bencoding::Integer>(length));
}

int64_t
MetaInfo::getPieceLength()
{
  auto i = m_info->get(PIECE_LENGTH);

  if (static_cast<bool>(i)) {
    return dynamic_pointer_cast<bencoding::Integer>(i)->getValue();
  }
  else
    return -1;
}

void
MetaInfo::setPieces(const std::vector<uint8_t> pieces)
{
  m_info->insert(PIECES, make_shared<bencoding::String>(&pieces.front(), pieces.size()));
}

std::vector<uint8_t>
MetaInfo::getPieces()
{
  auto i = m_info->get(PIECES);

  if (static_cast<bool>(i))
    return dynamic_pointer_cast<bencoding::String>(i)->getValue();
  else
    return std::vector<uint8_t>();
}

void
MetaInfo::setLength(int64_t length)
{
  m_info->erase(FILES);

  m_info->insert(LENGTH, make_shared<bencoding::Integer>(length));
}

int64_t
MetaInfo::getLength()
{
  auto i = m_info->get(LENGTH);

  if (static_cast<bool>(i))
    return dynamic_pointer_cast<bencoding::Integer>(i)->getValue();
  else
    return -1;
}

void
MetaInfo::addFile(const MetaInfo::File file)
{
  m_info->erase(LENGTH);

  auto i = m_info->get(FILES);

  if (!static_cast<bool>(i)) {
    i = make_shared<bencoding::List>();
    m_info->insert(FILES, i);
  }

  dynamic_pointer_cast<bencoding::List>(i)->append(file.encode());
}

std::vector<MetaInfo::File>
MetaInfo::getFiles()
{
  std::vector<MetaInfo::File> result;
  auto f = m_info->get(FILES);

  if (static_cast<bool>(f)) {
    auto list = dynamic_pointer_cast<bencoding::List>(f)->getList();
    for (const auto& i : list) {
      MetaInfo::File file;
      file.decode(*dynamic_pointer_cast<bencoding::Dictionary>(i));
      result.push_back(file);
    }
  }

  return result;
}

ConstBufferPtr
MetaInfo::getHash()
{
  OBufferStream os;

  m_info->wireEncode(os);

  return util::sha1(os.buf());
}

} // namespace sbt
