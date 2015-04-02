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

#include "tracker-response.hpp"
#include "util/buffer-stream.hpp"

namespace sbt {

const std::string PeerInfo::PEER_ID("peer id");
const std::string PeerInfo::IP("ip");
const std::string PeerInfo::PORT("port");

const std::string TrackerResponse::FAILURE("failure");
const std::string TrackerResponse::INTERVAL("interval");
const std::string TrackerResponse::PEERS("peers");

shared_ptr<bencoding::Dictionary>
PeerInfo::encode()
{
  auto peerInfo = make_shared<bencoding::Dictionary>();
  peerInfo->insert(PEER_ID, make_shared<bencoding::String>(peerId));
  peerInfo->insert(IP, make_shared<bencoding::String>(ip));
  peerInfo->insert(PORT, make_shared<bencoding::Integer>(port));

  return peerInfo;
}

void
PeerInfo::decode(const bencoding::Dictionary& dict)
{
  auto idEntry = dict.get(PEER_ID);
  if (static_cast<bool>(idEntry))
    peerId = dynamic_pointer_cast<bencoding::String>(idEntry)->toString();
  else
    throw TrackerResponse::Error("No peer id in peer info");

  auto ipEntry = dict.get(IP);
  if (static_cast<bool>(ipEntry))
    ip = dynamic_pointer_cast<bencoding::String>(ipEntry)->toString();
  else
    throw TrackerResponse::Error("No ip in peer info");

  auto portEntry = dict.get(PORT);
  if (static_cast<bool>(portEntry))
    port = dynamic_pointer_cast<bencoding::Integer>(portEntry)->getValue();
  else
    throw TrackerResponse::Error("No port in peer info");
}

TrackerResponse::TrackerResponse()
  : m_isFailure(true)
  , m_failure("response is not initialize")
{
}

TrackerResponse::TrackerResponse(uint64_t interval)
  : m_isFailure(false)
  , m_interval(interval)
{
}

TrackerResponse::TrackerResponse(const std::string& failure)
  : m_isFailure(true)
  , m_failure(failure)
{
}

void
TrackerResponse::addPeer(const PeerInfo& peer)
{
  if (m_isFailure)
    throw Error("Cannot add peer in failure response");

  m_peers.push_back(peer);
}

shared_ptr<bencoding::Dictionary>
TrackerResponse::encode()
{
  OBufferStream os;
  auto dict = make_shared<bencoding::Dictionary>();

  if (m_isFailure)
    dict->insert(FAILURE, make_shared<bencoding::String>(m_failure));
  else {
    dict->insert(INTERVAL, make_shared<bencoding::Integer>(m_interval));

    auto list = make_shared<bencoding::List>();
    for (auto peer : m_peers)
      list->append(peer.encode());
    dict->insert(PEERS, list);
  }

  return dict;
}

void
TrackerResponse::decode(const bencoding::Dictionary& response)
{
  m_peers.clear();

  auto failure = response.get(FAILURE);
  if (static_cast<bool>(failure)) {
    m_isFailure = true;
    m_failure = dynamic_pointer_cast<bencoding::String>(failure)->toString();
  }
  else {
    m_isFailure = false;

    auto interval = response.get(INTERVAL);
    if (static_cast<bool>(interval))
      m_interval = dynamic_pointer_cast<bencoding::Integer>(interval)->getValue();
    else
      throw TrackerResponse::Error("No interval in positive tracker response ");

    auto peers = response.get(PEERS);
    if (static_cast<bool>(peers)) {
      for (auto peer : *dynamic_pointer_cast<bencoding::List>(peers)) {
        PeerInfo info;
        info.decode(*dynamic_pointer_cast<const bencoding::Dictionary>(peer));
        m_peers.push_back(info);
      }
    }
    else
      throw TrackerResponse::Error("No peers in positive tracker response");
  }
}

} // namespace sbt
