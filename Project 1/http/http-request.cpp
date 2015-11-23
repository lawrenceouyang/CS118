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
 * \author Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "http-request.hpp"

#include <string> // C++ STL string
#include <string.h> // helpers to copy C-style strings

#include "compat.hpp"

using std::string;

// comment the following line to disable debug output
#define _DEBUG 1

#ifdef _DEBUG
#include <iostream>
#define TRACE(x) std::clog << x << endl;
#else
#endif // _DEBUG

#include <boost/lexical_cast.hpp>
#include <boost/tokenizer.hpp>

namespace sbt {

HttpRequest::HttpRequest()
  : m_method(UNSUPPORTED)
  , m_port(0)
{
}

const char*
HttpRequest::parseRequest(const char* buffer, size_t size)
{
  const char* curPos = buffer;

  const char* endline = (const char*)memmem(curPos, size - (curPos - buffer), "\r\n", 2);
  if (endline == 0)
    throw ParseError("HTTP Request doesn't end with \\r\\n");

  boost::char_separator<char> sep(" ");
  string requestLine(curPos, endline - curPos);
  boost::tokenizer<boost::char_separator<char>> tokens(requestLine,
                                                       boost::char_separator<char>(" "));

  // 1. Request type
  auto token = tokens.begin();
  if (token == tokens.end())
    throw ParseError("Incorrectly formatted request");

  // TRACE("Token1: " << *token);
  if (*token != "GET")
    throw ParseError("Request is not GET");

  setMethod(GET);

  // 2. Request path
  ++token;
  if (token == tokens.end())
    throw ParseError("Incorrectly formatted request");

  // TRACE("Token2: " << *token);
  size_t pos = token->find("://");
  if (pos == string::npos) {
    // just path
    setPath(*token);
  }
  else {
    // combined Host and Path
    string protocol = token->substr(0, pos);
    // TRACE(protocol);

    pos += 3;
    size_t posSlash = token->find("/", pos);
    if (posSlash == string::npos)
      throw ParseError("Request line is not correctly formatted");

    // TRACE(string(curPos, endline-curPos));
    // TRACE(*token);
    // TRACE(pos << ", " << posSlash);

    size_t posPort = token->find(":", pos);
    if (posPort != string::npos && posPort < posSlash) { // port is specified
      string port = token->substr(posPort + 1, posSlash - posPort - 1);
      // TRACE(port);
      setPort(boost::lexical_cast<unsigned short>(port));

      string host = token->substr(pos, posPort - pos);
      // TRACE(host);
      setHost(host);
    }
    else {
      setPort(80);

      string host = token->substr(pos, posSlash - pos);
      // TRACE(host);
      setHost(host);
    }

    string path = token->substr(posSlash, token->size() - posSlash);
    // TRACE(path);
    setPath(path);
  }

  // 3. Request version
  ++token;
  if (token == tokens.end())
    throw ParseError("Incorrectly formatted request");
  // TRACE("Token3: " << *token);
  size_t posHTTP = token->find("HTTP/");
  if (posHTTP == string::npos)
    throw ParseError("Incorrectly formatted HTTP request");

  string version = token->substr(5, token->size() - 5);
  // TRACE(version);
  setVersion(version);

  curPos = endline + 2;
  return parseHeaders(curPos, size - (curPos - buffer));
}


size_t
HttpRequest::getTotalLength() const
{
  if (m_method != GET)
    throw ParseError("Only GET method is supported");

  size_t len = 4; // 'GET '
  len += m_path.size() + 1; // '<path> '
  len += 5; // 'HTTP/'
  len += m_version.size(); // '1.0'
  len += 2; // '\r\n'

  len += HttpHeaders::getTotalLength();

  len += 2; // '\r\n'

  return len;
}

char*
HttpRequest::formatRequest(char* buffer) const
{
  if (m_method != GET)
    throw ParseError("Only GET method is supported");

  char* bufLastPos = buffer;

  bufLastPos = stpncpy(bufLastPos, "GET ", 4);
  bufLastPos = stpncpy(bufLastPos, m_path.c_str(), m_path.size());
  bufLastPos = stpncpy(bufLastPos, " HTTP/", 6);
  bufLastPos = stpncpy(bufLastPos, m_version.c_str(), m_version.size());
  bufLastPos = stpncpy(bufLastPos, "\r\n", 2);

  bufLastPos = HttpHeaders::formatHeaders(bufLastPos);
  bufLastPos = stpncpy(bufLastPos, "\r\n", 2);

  return bufLastPos;
}


HttpRequest::MethodEnum
HttpRequest::getMethod() const
{
  return m_method;
}

void
HttpRequest::setMethod(HttpRequest::MethodEnum method)
{
  m_method = method;
}

// const std::string&
// HttpRequest::GetProtocol() const
// {
//   return m_protocol;
// }

// void
// HttpRequest::SetProtocol(const std::string& protocol)
// {
//   m_protocol = protocol;
// }

const std::string&
HttpRequest::getHost() const
{
  return m_host;
}

void
HttpRequest::setHost(const std::string& host)
{
  m_host = host;

  if (m_port != 80)
    modifyHeader("Host", m_host + ":" + boost::lexical_cast<string>(m_port));
  else
    modifyHeader("Host", m_host);
}

unsigned short
HttpRequest::getPort() const
{
  return m_port;
}

void
HttpRequest::setPort(unsigned short port)
{
  m_port = port;

  if (m_port != 80)
    modifyHeader("Host", m_host + ":" + boost::lexical_cast<string> (m_port));
  else
    modifyHeader("Host", m_host);
}

const std::string&
HttpRequest::getPath() const
{
  return m_path;
}

void
HttpRequest::setPath(const std::string& path)
{
  m_path = path;
}

const std::string&
HttpRequest::getVersion() const
{
  return m_version;
}

void
HttpRequest::setVersion(const std::string& version)
{
  m_version = version;
}

} // namespace sbt
