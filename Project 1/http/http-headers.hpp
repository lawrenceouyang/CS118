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

#ifndef SBT_HTTP_HEADER_HPP
#define SBT_HTTP_HEADER_HPP

#include "../common.hpp"
#include <string>
#include <list>

namespace sbt {

class ParseError : public std::runtime_error
{
public:
  explicit
  ParseError(const std::string& what)
    : std::runtime_error(what)
  {
  }
};

/**
 * @brief Class to parse/create HTTP headers
 */
class HttpHeaders
{
public:
  /**
   * @brief Default constructor
   */
  HttpHeaders();

  /**
   * @brief Parse HTTP headers
   */
  const char*
  parseHeaders(const char* buffer, size_t size);

  /**
   * @brief Get total length of the HTTP headers
   *        (buffer size necessary to hold formatted HTTP headers)
   */
  size_t
  getTotalLength() const;

  /**
   * @brief Format HTTP headers
   *
   * Another note. Buffer size should be enough to hold the request
   * (e.g., obtained from getTotalLength () call). Otherwise, anything can happen.
   *
   * @param buffer [out] Buffer that will hold formatted request
   * @returns Number of bytes actually written to the buffer
   */
  char*
  formatHeaders(char* buffer) const;

  // Getters/Setters for HTTP request fields

  /**
   * @brief Add HTTP header
   */
  void
  addHeader(const std::string& key, const std::string& value);

  /**
   * @brief Remove HTTP header
   */
  void
  removeHeader(const std::string& key);

  /**
   * @brief Modify HTTP header
   *
   * Note that if header is currently not present, it will be added
   */
  void
  modifyHeader(const std::string& key, const std::string& value);

  /**
   * @brief Find value for the `key' http header
   *
   * If header doesn't exist, it the method will return a blank line
   */
  std::string
  findHeader(const std::string& key);

private:
  struct HttpHeader
  {
    HttpHeader(const std::string& key, const std::string& value)
      : m_key(key)
      , m_value(value)
    {
    }

    bool
    operator==(const std::string& key) const
    {
      return key == m_key;
    }

    std::string m_key;
    std::string m_value;
  };

  std::list<HttpHeader> m_headers;
};

} // namespace sbt

#endif // SBT_HTTP_HEADER_HPP
