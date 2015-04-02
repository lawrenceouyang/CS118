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

#ifndef SBT_CLIENT_HPP
#define SBT_CLIENT_HPP

#include "common.hpp"
#include "meta-info.hpp"
#include "http/url-encoding.hpp"
#include "http/http-request.hpp"
#include "http/http-response.hpp"
#include "msg/handshake.hpp"
#include "msg/msg-base.hpp"
#include "util/hash.hpp"
#include "tracker-response.hpp"
#include <fstream>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <sstream>
#include <math.h>
#include <algorithm>
#include <vector>
#include <error.h>
#include <stdio.h>
#include <stdlib.h>

namespace sbt {

const int MAX_CONNECTIONS = 4;
class Client
{
public:
  Client(const std::string& port, const std::string& torrent);
  ~Client();
  void checkFile();
  void formatGet();
  void formatHttp();
  void sendRequest();
  void formatResponse(std::string response);
  std::string parseHost();
  unsigned short parsePort();
  void initBitfield();
  int checkFreeThread();


  void downloadInc(int inc);
  void leftDec(int dec);
  void uploadInc(int inc);


  //Multithreading
  void setConArgs(int thread, std::string peer, unsigned short port, Client* client);
  static void* connectionManager(void *args);
  static void* peerConnection(void *args);
  static void* acceptManager(void* args);
  static void* acceptConnection(void *args);

  //accessors
  int getRefused() const;
  std::string getEvent() const;
  uint64_t getTrackInterval();

  //bitField mutators
  void setBitZero(uint8_t* bitArray, int index);
  void setBitOne(uint8_t* bitArray, int index);
  int getBit(uint8_t* bitArray, int index);

private:
  char* m_formatReq;
  int m_formatLen;
  int m_connectionRefused;

  struct con_Args {
    int thread;
    unsigned short port;
    std::string peer;
    Client* client_p;
  };

  //  bool m_printed;
  std::string m_event;
  std::string m_port;
  std::string m_getReq;
  std::string m_peerID;
  int m_connections;
  int m_uploaded;
  int m_downloaded;
  int m_left;
  int m_numPieces;
  uint8_t* m_bitArray;

  MetaInfo m_torrentMetaInfo;
  HttpRequest m_httpReq;
  HttpResponse m_httpRes;
  TrackerResponse m_trackRes;
  ConstBufferPtr m_handshake;
  msg::Bitfield m_bitfield;
  bool m_usingThread[MAX_CONNECTIONS];

  std::vector<PeerInfo> m_peerList;
  std::vector<std::string> m_connectedList;

  con_Args m_conArgs[MAX_CONNECTIONS];
};

} // namespace sbt

#endif // SBT_CLIENT_HPP
