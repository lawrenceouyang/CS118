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

#ifndef SBT_META_INFO_HPP
#define SBT_META_INFO_HPP

#include "util/bencoding.hpp"

namespace sbt {

class MetaInfo
{
public:
  class File
  {
  public:
    class Error : public bencoding::Error
    {
    public:
      explicit
      Error(const std::string& what)
        : bencoding::Error(what)
      {
      }
    };

    std::shared_ptr<bencoding::Dictionary>
    encode() const;

    void
    decode(const bencoding::Dictionary& dict);

  public:
    int64_t length;
    std::vector<std::string> path;
  };

public:
  MetaInfo();

  void
  wireEncode(std::ostream& os) const;

  void
  wireDecode(std::istream& is);

  void
  setAnnounce(const std::string& announce);

  std::string
  getAnnounce();

  void
  setName(const std::string& name);

  std::string
  getName();

  void
  setPieceLength(int64_t length);

  int64_t
  getPieceLength();

  void
  setPieces(const std::vector<uint8_t> pieces);

  std::vector<uint8_t>
  getPieces();

  void
  setLength(int64_t length);

  int64_t
  getLength();

  void
  addFile(const MetaInfo::File file);

  std::vector<MetaInfo::File>
  getFiles();

  const bencoding::Dictionary&
  getRoot() const
  {
    return m_root;
  }

  ConstBufferPtr
  getHash();

private:
  static const std::string ANNOUNCE;
  static const std::string INFO;
  static const std::string NAME;
  static const std::string PIECE_LENGTH;
  static const std::string PIECES;
  static const std::string LENGTH;
  static const std::string FILES;
  static const std::string PATH;


  bencoding::Dictionary m_root;
  std::shared_ptr<bencoding::Dictionary> m_info;
};

} // namespace sbt

#endif // SBT_META_INFO_HPP
