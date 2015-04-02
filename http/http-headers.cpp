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

#include "http-headers.hpp"

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
#include <boost/algorithm/string.hpp>

namespace sbt {

HttpHeaders::HttpHeaders()
{
}

const char*
HttpHeaders::parseHeaders(const char* buffer, size_t size)
{
  const char* curPos = buffer;

  string key;
  string value;

  while (((size_t)(curPos - buffer) <= size - 2) &&
         (*curPos != '\r' && *(curPos + 1) != '\n')) {

    const char* endline = (const char*)memmem(curPos, size - (curPos - buffer), "\r\n", 2);

    if (endline == 0)
      throw ParseError("Header line does end with \\r\\n");

    if (*curPos == ' ' || *curPos == '\t') { // multi-line header
      if (key == "")
        throw ParseError("Multi-line header without actual header");

      string newline(curPos, endline - curPos);
      // TRACE ("Multi-line header: " << value << " + " << newline);

      // reusing key from previous iteration
      value += "\r\n" + newline;
      modifyHeader(key, value);
    }
    else {
      const char* header_key = (const char*)memmem(curPos, endline - curPos, ":", 1);

      if (header_key == 0)
        throw ParseError("HTTP header doesn't contain ':'");

      key = string(curPos, header_key-curPos);
      value = string(header_key + 1, endline - header_key - 1);
      boost::trim (value); // remove any leading spaces if present

      // TRACE ("Key: [" << key << "], value: [" << value << "]");

      modifyHeader(key, value);
    }

    curPos = endline + 2;
  }

  // TRACE ("Left: " << (int)(curPos-buffer) << ", size: " << size);
  if (static_cast<size_t>(curPos-buffer+2) <= size)
    curPos += 2; // skip '\r\n'
  else
    throw ParseError("Parsed buffer does not contain \\r\\n");

  return curPos;
}

size_t
HttpHeaders::getTotalLength() const
{
  size_t len = 0;

  for (const auto& header : m_headers)
    len += header.m_key.size () + 2/*: */+ header.m_value.size () + 2/*\r\n*/;

  return len;
}

char*
HttpHeaders::formatHeaders(char* buffer) const
{
  char* bufLastPos = buffer;

  for (const auto& header : m_headers) {
    bufLastPos = stpncpy(bufLastPos, header.m_key.c_str(), header.m_key.size());
    bufLastPos = stpncpy(bufLastPos, ": ", 2);
    bufLastPos = stpncpy(bufLastPos, header.m_value.c_str(), header.m_value.size());
    bufLastPos = stpncpy(bufLastPos, "\r\n", 2);
  }

  return bufLastPos;
}


void
HttpHeaders::addHeader(const std::string& key, const std::string& value)
{
  m_headers.push_back(HttpHeader(key, value));
}

void
HttpHeaders::removeHeader(const std::string& key)
{
  auto item = std::find(m_headers.begin(), m_headers.end(), key);
  if (item != m_headers.end())
    m_headers.erase(item);
}

void
HttpHeaders::modifyHeader(const std::string& key, const std::string& value)
{
  auto item = std::find(m_headers.begin(), m_headers.end(), key);
  if (item != m_headers.end())
    item->m_value = value;
  else
    addHeader (key, value);
}

std::string
HttpHeaders::findHeader(const std::string& key)
{
  auto item = std::find(m_headers.begin(), m_headers.end(), key);
  if (item != m_headers.end())
    return item->m_value;
  else
    return "";
}

} // namespace sbt
