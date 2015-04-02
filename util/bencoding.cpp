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

#include "bencoding.hpp"

#include <boost/lexical_cast.hpp>

using std::string;
using std::vector;
using std::ostream;
using std::istream;
using std::shared_ptr;
using std::make_shared;

namespace sbt {
namespace bencoding {

Base::Base(Type type)
  : m_type(type)
{
}

Base::~Base()
{
}

String::String()
  : Base(TYPE_STRING)
{
}

String::String(const std::string& value)
  : Base(TYPE_STRING)
  , m_value(value.begin(), value.end())
{
}

String::String(const void* value, size_t size)
  : Base(TYPE_STRING)
  , m_value(reinterpret_cast<const uint8_t*>(value),
            reinterpret_cast<const uint8_t*>(value) + size)
{
}

String::~String()
{
}

void
String::wireEncode(ostream& os) const
{
  os << m_value.size() << ":";
  os.write(reinterpret_cast<const char*>(&m_value.front()), m_value.size());
}

void
String::wireDecode(istream& is)
{
  char c;
  string size;
  bool hasColon = false;
  while (is.get(c)) {
    if (c == ':') {
      hasColon = true;
      break;
    }
    size += c;
  }

  if (!hasColon)
    throw Error("Bad encoding");

  int s = 0;
  try {
    s = boost::lexical_cast<int>(size);
  }
  catch(const boost::bad_lexical_cast &) {
    throw Error("Bad size: " + size);
  }

  if (s > 0 && size[0] == '0')
    throw Error("Bad size: " + size);

  if (s == 0 && size.size() != 1)
    throw Error("Bad size: " + size);

  if (s < 0)
    throw Error("Bad size: " + size);

  m_value = vector<uint8_t>(s, 0);
  int readSize = is.readsome(reinterpret_cast<char*>(&m_value.front()), s);

  if (readSize != s)
    throw Error("Bad encoding");
}

string
String::toString()
{
  return string(m_value.begin(), m_value.end());
}

void
String::print(std::ostream& os, const std::string& indent)
{
  os << indent << toString();
}


Integer::Integer()
  : Base(TYPE_INTEGER)
  , m_value(0)
{
}

Integer::Integer(int64_t value)
  : Base(TYPE_INTEGER)
  , m_value(value)
{
}

Integer::~Integer()
{
}

void
Integer::wireEncode(std::ostream& os) const
{
  os << "i" << m_value << "e";
}

void
Integer::wireDecode(std::istream& is)
{
  char c;

  is.get(c);
  if (c != 'i')
    throw Error("Bad integer encoding 0");


  string size;
  bool hasEnd = false;
  while (is.get(c)) {
    if (c == 'e') {
      hasEnd = true;
      break;
    }
    size += c;
  }

  if (!hasEnd)
    throw Error("Bad integer encoding 1");

  int s = 0;
  try {
    s = boost::lexical_cast<int>(size);
  }
  catch(const boost::bad_lexical_cast &) {
    throw Error("Bad integer: " + size);
  }

  if (s > 0 && size[0] == '0')
    throw Error("Bad integer: " + size);

  if (s == 0 && size.size() != 1)
    throw Error("Bad integer: " + size);

  if (s < 0 && size[1] == '0')
    throw Error("Bad integer: " + size);


  m_value = s;
}

void
Integer::print(std::ostream& os, const std::string& indent)
{
  os << indent << m_value;
}

List::List()
  : Base(TYPE_LIST)
{
}

List::~List()
{
}

void
List::wireEncode(std::ostream& os) const
{
  os << "l";

  for (const auto& i : m_list) {
    i->wireEncode(os);
  }

  os << "e";
}

void
List::wireDecode(std::istream& is)
{
  m_list.clear();

  char c;

  is.get(c);
  if (c != 'l')
    throw Error("Bad list encoding");

  bool hasEnd = false;
  c = is.peek();
  while (c != EOF) {
    if (c == 'e') {
      is.get(c);
      hasEnd = true;
      break;
    }

    switch (c) {
    case 'i':
      {
        auto i = make_shared<Integer>();
        i->wireDecode(is);
        m_list.push_back(i);
        break;
      }
    case 'l':
      {
        auto l = make_shared<List>();
        l->wireDecode(is);
        m_list.push_back(l);
        break;
      }
    case 'd':
      {
        auto d = make_shared<Dictionary>();
        d->wireDecode(is);
        m_list.push_back(d);
        break;
      }
    default:
      {
        auto s = make_shared<String>();
        s->wireDecode(is);
        m_list.push_back(s);
        break;
      }
    }
    c = is.peek();
  }

  if (!hasEnd)
    throw Error("Bad list encoding");
}

void
List::append(shared_ptr<Base> item)
{
  m_list.push_back(item);
}

List::iterator
List::begin()
{
  return m_list.begin();
}

List::iterator
List::end()
{
  return m_list.end();
}

List::const_iterator
List::begin() const
{
  return m_list.begin();
}

List::const_iterator
List::end() const
{
  return m_list.end();
}

void
List::print(std::ostream& os, const std::string& indent)
{
  os << indent << "list:";

  string newIndent = indent + "  ";
  for (const auto& i : m_list) {
    os << std::endl;
    i->print(os, newIndent);
  }
}

Dictionary::Dictionary()
  : Base(TYPE_DICTIONARY)
{
}

Dictionary::~Dictionary()
{
}

void
Dictionary::wireEncode(std::ostream& os) const
{
  os << "d";

  for (const auto& i : m_map) {
    os << i.first.size() << ":" << i.first;
    i.second->wireEncode(os);
  }

  os << "e";
}

void
Dictionary::wireDecode(std::istream& is)
{
  m_map.clear();

  char c;

  is.get(c);
  if (c != 'd')
    throw Error("Bad dictionary encoding");

  bool hasEnd = false;
  c = is.peek();
  while (c != EOF) {
    if (c == 'e') {
      is.get(c);
      hasEnd = true;
      break;
    }

    String key;
    key.wireDecode(is);

    c = is.peek();
    switch (c) {
    case 'i':
      {
        auto i = make_shared<Integer>();
        i->wireDecode(is);
        m_map[key.toString()] = i;
        break;
      }
    case 'l':
      {
        auto l = make_shared<List>();
        l->wireDecode(is);
        m_map[key.toString()] = l;
        break;
      }
    case 'd':
      {
        auto d = make_shared<Dictionary>();
        d->wireDecode(is);
        m_map[key.toString()] = d;
        break;
      }
    default:
      {
        auto s = make_shared<String>();
        s->wireDecode(is);
        m_map[key.toString()] = s;
        break;
      }
    }
    c = is.peek();
  }

  if (!hasEnd)
    throw Error("Bad map encoding");
}

void
Dictionary::insert(const std::string& key, std::shared_ptr<Base> value)
{
  m_map[key] = value;
}

void
Dictionary::erase(const std::string& key)
{
  m_map.erase(key);
}

std::shared_ptr<Base>
Dictionary::get(const std::string& key) const
{
  auto it = m_map.find(key);
  if (it != m_map.end())
    return it->second;
  else
    return shared_ptr<Base>();
}

Dictionary::iterator
Dictionary::begin()
{
  return m_map.begin();
}

Dictionary::iterator
Dictionary::end()
{
  return m_map.end();
}

Dictionary::const_iterator
Dictionary::begin() const
{
  return m_map.begin();
}

Dictionary::const_iterator
Dictionary::end() const
{
  return m_map.end();
}

void
Dictionary::print(std::ostream& os, const std::string& indent)
{
  os << indent << "dict:";

  string newIndent = indent + "  ";
  for (const auto& i : m_map) {
    os << std::endl;
    os << newIndent << i.first << ":" << std::endl;
    i.second->print(os, newIndent + "  ");
  }
}

} // namespace bencoding
} // namespace sbt
