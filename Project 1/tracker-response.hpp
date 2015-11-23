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

#ifndef SBT_TRACKER_RESPONSE_HPP
#define SBT_TRACKER_RESPONSE_HPP

#include "util/buffer.hpp"
#include "util/bencoding.hpp"
#include <vector>

namespace sbt {

class PeerInfo
{
public:
  shared_ptr<bencoding::Dictionary>
  encode();

  void
  decode(const bencoding::Dictionary& dict);

public:
  std::string peerId;
  std::string ip;
  uint16_t port;

private:
  static const std::string PEER_ID;
  static const std::string IP;
  static const std::string PORT;
};

class TrackerResponse
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

public:
  TrackerResponse();

  TrackerResponse(uint64_t interval);

  TrackerResponse(const std::string& failure);

  bool
  isFailure()
  {
    return m_isFailure;
  }

  std::string
  getFailure()
  {
    return m_failure;
  }

  uint64_t
  getInterval()
  {
    return m_interval;
  }

  void
  addPeer(const PeerInfo& peer);

  const std::vector<PeerInfo>&
  getPeers() const
  {
    return m_peers;
  }

  shared_ptr<bencoding::Dictionary>
  encode();

  void
  decode(const bencoding::Dictionary& response);

private:
  static const std::string FAILURE;
  static const std::string INTERVAL;
  static const std::string PEERS;

  bool m_isFailure;
  std::string m_failure;
  uint64_t m_interval; // seconds
  std::vector<PeerInfo> m_peers;
};

} // namespace sbt

#endif // SBT_TRACKER_RESPONSE_HPP
