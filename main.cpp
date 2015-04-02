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

#include "client.hpp"
#include "msg/msg-base.hpp"
#include <pthread.h>

int
main(int argc, char** argv)
{
  try
  {
    // Check command line arguments.
    if (argc != 3)
    {
      std::cerr << "Usage: simple-bt <port> <torrent_file>\n";
      return 1;
    }

    // Initialise the client.
    sbt::Client client(argv[1], argv[2]);
    pthread_t cManager, aManager;
    void* cManArgs = (void*)&client;
    pthread_create(&aManager, NULL, client.acceptManager, cManArgs);

    // Send first request
    client.checkFile();

    client.formatGet();
    client.formatHttp();
    client.sendRequest();  

    //create connection manager thread
    pthread_create(&cManager, NULL, client.connectionManager, cManArgs);

    sleep(client.getTrackInterval());
    // Repeat request until finished
    while (client.getEvent() != "stopped")
    {
      std::cout << "connecting to tracker" << std::endl;
       if (client.getRefused() >= 3)
        break;
      client.formatGet();
      client.formatHttp();
      client.sendRequest();
      sleep(client.getTrackInterval());
    }
    if (client.getRefused() >= 3) {
      std::cerr << "Connection failed. Exiting program.\n";
      exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
  }
  catch (std::exception& e)
  {
    std::cerr << "exception: " << e.what() << "\n";
  }

  return 0;
}

