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

#ifndef SBT_HTTP_RESPONSE_HPP
#define SBT_HTTP_RESPONSE_HPP

#include "http-headers.hpp"

namespace sbt {
/**
 * @brief Class to parse/create HTTP responses
 *
 *  HttpResponse objects are created from parsing a buffer containing a HTTP
 *  response.
 */
class HttpResponse : public HttpHeaders
{
public:
  /**
   * @brief Default constructor
   *
   * Example:
   * HttpResponse resp;
   * ...
   */
  HttpResponse();

  /**
   * @brief Parse HTTP header
   *
   * Example:
   * HttpResponse resp;
   * resp.ParseResponse (buf, size);
   */
  const char*
  parseResponse(const char* buffer, size_t size);

  /**
   * @brief Get total length of the HTTP header
   *        (buffer size necessary to hold formatted HTTP response)
   */
  size_t
  getTotalLength() const;

  /**
   * @brief Format HTTP response
   *
   * Note that buffer size should be enough to hold the response
   * (e.g., obtained from GetTotalLength () call). Otherwise, anything can happen.
   *
   * @param buffer [out] Buffer that will hold formatted response
   * @returns Number of bytes actually written to the buffer
   */
  char*
  formatResponse(char* buffer) const;

  // Getters/Setters for HTTP response fields

  /**
   * @brief Get version of the HTTP response
   */
  const std::string&
  getVersion() const;

  /**
   * @brief Set version of the HTTP response
   */
  void
  setVersion(const std::string& version);

  /**
   * @brief Get status code
   */
  const std::string&
  getStatusCode() const;

  /**
   * @brief Set status code
   */
  void
  setStatusCode(const std::string& code);

  /**
   * @brief Get status message
   */
  const std::string&
  getStatusMsg() const;

  /**
   * @brief Set status message
   */
  void
  setStatusMsg(const std::string& msg);

private:
  std::string m_version;
  std::string m_statusCode;
  std::string m_statusMsg;
};

} // namespace sbt

#endif // SBT_HTTP_RESPONSE_HPP
