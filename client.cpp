  #include  "client.hpp"

using namespace std;

namespace sbt {

pthread_mutex_t var = PTHREAD_MUTEX_INITIALIZER;

  Client::Client(const string& port, const string& torrent) {
    ifstream torrentInfo(torrent);
    if (torrentInfo.is_open())
      m_torrentMetaInfo.wireDecode(torrentInfo);
    
    m_peerID = "SIMPLEBT.TEST.PEERID";
    m_port = port;
    m_connectionRefused = 0;
    m_event = "started";
    m_uploaded = 0;
    m_downloaded = 0;
    m_left = m_torrentMetaInfo.getLength();
    m_connections = 0;

    for (unsigned i = 0; i < MAX_CONNECTIONS; i++)
      m_usingThread[i] = false;

    ConstBufferPtr infoHash = m_torrentMetaInfo.getHash();
    msg::HandShake hShake;
    hShake.setInfoHash(infoHash);
    hShake.setPeerId(m_peerID);
    m_handshake = hShake.encode();
    // m_printed = false;
  }

  Client::~Client() {
    delete [] m_formatReq;
    delete [] m_bitArray;
  }

  int Client::getRefused() const {
    return m_connectionRefused;
  }

  string Client::getEvent() const {
    return m_event;
  }
  
  uint64_t Client::getTrackInterval() {
    uint64_t interval = m_trackRes.getInterval();
    return interval;
  }
  
  void Client::checkFile() {
    ConstBufferPtr bits;
    bool hashMatch = true;
    ifstream file(m_torrentMetaInfo.getName());
    file.seekg(0, file.end);
    int length = file.tellg();
    file.seekg(0, file.beg);
    int count = 0;
    
    int numPieces = m_torrentMetaInfo.getLength()/m_torrentMetaInfo.getPieceLength() + 1;
    m_numPieces = numPieces;
    int numBytes = ceil(numPieces/8.0);
    m_bitArray = new uint8_t[numBytes];
    for (int i = 0; i < numBytes; i++)
      m_bitArray[i] = 0;

    if (length <= 0) { //Empty/nonexistent file
      ofstream newFile(m_torrentMetaInfo.getName());
      newFile.close();
      bits = make_shared<Buffer>(m_bitArray, 3);
      m_bitfield.setBitfield(bits);
      return;
    }

    int num = length/(int)m_torrentMetaInfo.getPieceLength();
    for (int i = 0; i < num; i++) {
      char* buffer = new char[m_torrentMetaInfo.getPieceLength()];
      file.read(buffer, m_torrentMetaInfo.getPieceLength());
      ConstBufferPtr constUnsignedBuf = make_shared<Buffer>(buffer, m_torrentMetaInfo.getPieceLength());
      ConstBufferPtr bufHash = util::sha1(constUnsignedBuf);
      for (int j = 0; j < 20; j++) {
        if (bufHash->buf()[j] != m_torrentMetaInfo.getPieces()[i*20 + j]) {
          hashMatch = false;
          break;
        }        
      }
      if (hashMatch) {
        setBitOne(m_bitArray, i);
        count++;
      }
      else 
        hashMatch = true;
    }

    m_left -= count*(int)m_torrentMetaInfo.getPieceLength();

    int remain = length % (int)m_torrentMetaInfo.getPieceLength();
    if (remain != 0) {
      char* buffer = new char[remain];
      file.read(buffer, remain);
      ConstBufferPtr constUnsignedBuf = make_shared<Buffer>(buffer, remain);
      ConstBufferPtr bufHash = util::sha1(constUnsignedBuf);
      for (int j = 0; j < 20; j++) {
        if (bufHash->buf()[j] != m_torrentMetaInfo.getPieces()[num*20 + j]) {
          hashMatch = false;
          break;
        }
      }
      if (hashMatch) {
        setBitOne(m_bitArray, num);
        m_left -= remain;
      }
        else 
          hashMatch = true;
    }
    bits = make_shared<Buffer>(m_bitArray, 3);
    m_bitfield.setBitfield(bits);
  }

  void Client::formatGet() {
    m_getReq = "";
    m_getReq.append(m_torrentMetaInfo.getAnnounce());
    m_getReq.append("?info_hash=");
    ConstBufferPtr infoHash = m_torrentMetaInfo.getHash();
    m_getReq.append(url::encode(infoHash->buf(), 20));
    m_getReq.append("&peer_id=");
    m_getReq.append(m_peerID);
    m_getReq.append("&ip=127.0.0.1");
    m_getReq.append("&port=");
    m_getReq.append(m_port);
    m_getReq.append("&uploaded=");
    stringstream uploadss;
    uploadss << m_uploaded;
    m_getReq.append(uploadss.str());
    m_getReq.append("&downloaded=0");
    m_getReq.append(to_string(m_downloaded));
    m_getReq.append("&left=");
    stringstream leftss;
    leftss << m_left;
    m_getReq.append(leftss.str());

    if (m_event == "started") {
      m_event = "inprogress";
      m_getReq.append("&event=started");
    }

    if (m_left <= 0) {
      m_event = "completed";
      m_getReq.append("&event=completed");
    }

    if (m_event != "inprogress") {
      m_getReq.append("&event=");
      m_getReq.append(m_event);
    }
  }
  
  void Client::formatHttp() {
    m_httpReq.setMethod(HttpRequest::GET);
    m_httpReq.setVersion("1.0");
    m_httpReq.setPath(m_getReq);
    m_httpReq.setHost(parseHost());
    m_httpReq.setPort(parsePort());
    size_t len = m_httpReq.getTotalLength() + 1000;
    m_formatReq = new char[len];
    m_formatLen = len;
    m_httpReq.formatRequest(m_formatReq);
    m_formatReq[len] = '\0';
  }
  
  void Client::sendRequest() {
    u_short sPort = parsePort();
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(sPort);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    memset(serverAddr.sin_zero, '\0', sizeof(serverAddr.sin_zero));
    
    if(connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1) {
      perror("connect");
      m_connectionRefused++;
      return;
    }
         
    struct sockaddr_in clientAddr;
    socklen_t clientAddrLen = sizeof(clientAddr);
    if (getsockname(sockfd, (struct sockaddr *)&clientAddr, &clientAddrLen) == -1) {
      perror("getsockname");
      return;
    }

    char ipstr[INET_ADDRSTRLEN] = {'\0'};
    inet_ntop(clientAddr.sin_family, &clientAddr.sin_addr, ipstr, sizeof(ipstr));

    char buf[10000] = {0};

    if (send(sockfd, m_formatReq, m_formatLen, 0) == -1) {
      perror("send");
      return;
    }
    if (recv(sockfd, buf, 10000, 0) == -1) {
      perror("recv");
      return;
    }
    
    string response = buf;
    formatResponse(response);
    close(sockfd);   
  }
  
  void Client::formatResponse(string response) {
    string length = "";
    size_t find = 0;
    find = response.find("Content-Length:");
    if (find == string::npos)
      return;
    find += 15;
    int i = find;
    while (response[i] != '\n')
      i++;
    length = response.substr(find, i - find);
    int cLength = stoi(length);
    string peers = response.substr(response.length() - cLength, cLength);
    bencoding::Dictionary dictionary;
    istringstream ipeers(peers);
    dictionary.wireDecode(ipeers);
    m_trackRes.decode(dictionary);
    vector<PeerInfo> vpeers = m_trackRes.getPeers();
    m_peerList = m_trackRes.getPeers();

  //     for (size_t i = 0; i < vpeers.size(); i++)
  // cout << vpeers[i].ip << ':' << vpeers[i].port << endl;
 }
  

  string Client::parseHost() {
    string announ = m_torrentMetaInfo.getAnnounce();
    string host;
    int i = 0;
    int j = 0;
    while (announ[i] != '/' && announ[i-1] != '/')
      i++;    
    i+=2;
    j = i;
    while (announ[j] != ':')
      j++;
    host = announ.substr(i, j - i);
    return host;
  }
  
  unsigned short Client::parsePort() {
    string announ = m_torrentMetaInfo.getAnnounce();
    string interResult = "";
    int result;
    int i = 0;
    int j = 0;
    int k = 0;

    while (announ[i] != '/' && announ[i-1] != '/')
      i++;    

    i+=2;
    j = i;

    while (announ[j] != ':')
      j++;   

    k = j;

    while(announ[k] != '/') {
      k++;
    }
    interResult = announ.substr(j+1, k - j);
    result = stoi(interResult);
    return (unsigned short) result;
  }

  void Client::setBitOne(uint8_t* bitArray, int index) 
  {
    bitArray[index/8] = bitArray[index/8] | (0x1) << (7-(index & 0x7));
  }

  void Client::setBitZero(uint8_t* bitArray, int index) 
  {
    uint8_t mask = 0;
    uint8_t* mask_p = &mask;
    for (int i = 0; i < 8; i++) {
      if (i == index % 8) {
        // cout << getBit(mask_p, i);
        continue;
      }
      setBitOne(mask_p, i);
      // cout << getBit(mask_p, i);
    }
    bitArray[index/8] = bitArray[index/8] & mask;
  }


  int Client::getBit(uint8_t* bitArray, int index)
  {
    return (bitArray[index/8] >> (7-(index & 0x7))) & 0x1;
  }

  void Client::downloadInc(int inc) {
    m_downloaded += inc;
  }

  void Client::leftDec(int dec) {
    m_left -= dec;
  }

  void Client::uploadInc(int inc) {
    m_uploaded += inc;
  }

  void Client::setConArgs(int thread, string peer, unsigned short port, Client* client) 
  {
    m_conArgs[thread].thread = thread;
    m_conArgs[thread].port = port;
    m_conArgs[thread].peer = peer;
    m_conArgs[thread].client_p = client;
  }

  int Client::checkFreeThread()
  {
    for (unsigned i = 0; i < MAX_CONNECTIONS; i++)
      if (!m_usingThread[i])
        return i;
    return -1;
  }
  void* Client::connectionManager(void *args)
  {
    int status = pthread_detach (pthread_self());
    if(status != 0) {
      perror("Detach thread");
      return args;
    }
    int openThread;
    pthread_t peerThread[MAX_CONNECTIONS];
    Client* client = (Client*)args;
    bool alreadyConnected = false;

    while (client->m_event != "completed") {
      cout << "looking for peers" << endl;
      for (unsigned i = 0; i < client->m_peerList.size(); i++) {      
        for (unsigned j = 0; j < client->m_connectedList.size(); j++) {
          if (client->m_connectedList[j] == client->m_peerList[i].peerId) {
            alreadyConnected = true;
            break;
          }
       }

       for (;;) {
          openThread = client->checkFreeThread();
          if (openThread == -1)
            sleep(1);
          else
            break;
       }
        if (alreadyConnected || client->m_peerList[i].peerId == client->m_peerID) {
          alreadyConnected = false;
          continue;
        }
        else {
          cout << "peer found!: " << client->m_peerList[i].peerId << endl;
          client->setConArgs(openThread, client->m_peerList[i].ip, client->m_peerList[i].port, client);
          cout << "connected to peer" << endl;
          pthread_create(&peerThread[openThread], NULL, client->peerConnection, (void*)&client->m_conArgs[openThread]);
          client->m_usingThread[openThread] = true;
          client->m_connectedList.push_back(client->m_peerList[i].peerId);
        }
     }
      sleep(client->getTrackInterval());
    }
    return args;
  }

  void* Client::peerConnection(void *args)
  {
    bool isInterested = false;
    bool isHash = false;
    int status = pthread_detach (pthread_self());
    if(status != 0) {
      perror("Detach thread");
      return args;
    }

    con_Args* conArgs = (con_Args*)args;  
    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd < 0) {
      perror("socket() failed");
      return args; 
    }
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(conArgs->port);
    serverAddr.sin_addr.s_addr = inet_addr(conArgs->peer.c_str());
    memset(serverAddr.sin_zero, '\0', sizeof(serverAddr.sin_zero));

    if(connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1) {
      perror("connect");
      return args;
    }
    if (send(sockfd, conArgs->client_p->m_handshake->buf(), conArgs->client_p->m_handshake->size(), 0) == -1) {
      perror("send handshake");
      return args;
    }
    char buf[100];
    if (recv(sockfd, buf, 100, 0) == -1) {
      perror("recv handshake");
      return args;
    }

    ConstBufferPtr peerHShake = make_shared<Buffer>(buf,68);
    msg::HandShake pShake;
    pShake.decode(peerHShake);

    if (url::encode(pShake.getInfoHash()->buf(), 20) !=
        url::encode(conArgs->client_p->m_torrentMetaInfo.getHash()->buf(), 20)) {
      cerr << "invalid info_hash" << endl;
      close(sockfd);
      return args;
    } 

    ConstBufferPtr clientBitfield = conArgs->client_p->m_bitfield.encode();
    const char* msg = reinterpret_cast<const char*>(clientBitfield->buf());
    if (send(sockfd, msg, 8, 0) == -1) {
      perror("send bitfield");
      return args;
    }

    sleep(2);
    char bufTwo[8];
    if (recv(sockfd, bufTwo, 8, 0) == -1) {
      perror("recv bitfield");
      return args;
    }

    ConstBufferPtr peerBitfield = make_shared<Buffer>(bufTwo, 8);
    msg::Bitfield peerField;
    peerField.decode(peerBitfield);
    uint8_t* bitDecoded = const_cast<uint8_t*>(peerField.getBitfield()->buf());

    for (int i = 0; i < conArgs->client_p->m_numPieces; i++)
      if (conArgs->client_p->getBit(conArgs->client_p->m_bitArray, i) == 0)
        if (conArgs->client_p->getBit(bitDecoded, i) == 1) {
          isInterested = true;
          break;
        }

    if (!isInterested)
      return args;
    msg::Interested interestMsg;
    if (send(sockfd, interestMsg.encode()->buf(), interestMsg.encode()->size(), 0) == -1) {
      perror("send interested");
      return args;
    }
    char bufThree[5];
    if (recv(sockfd, bufThree, 5, 0) == -1) {
      perror("recv unchoke");
      return args;
    }

    ConstBufferPtr uChoke = make_shared<Buffer>(bufThree,5);
    msg::Unchoke uchkMsg; 
    uchkMsg.decode(uChoke);
    if (uchkMsg.getId() != msg::MSG_ID_UNCHOKE)
      return args;

    vector<uint8_t> pieceCheck = conArgs->client_p->m_torrentMetaInfo.getPieces();

    for (int i = 0; i < conArgs->client_p->m_numPieces; i++) {
      if (conArgs->client_p->getBit(conArgs->client_p->m_bitArray, i) == 0) {
        if (conArgs->client_p->getBit(bitDecoded, i) == 1) {
          conArgs->client_p->setBitOne(conArgs->client_p->m_bitArray, i);
          msg::Request reqPiece(i, 0, conArgs->client_p->m_torrentMetaInfo.getPieceLength());
          if (i == conArgs->client_p->m_numPieces - 1)
            reqPiece.setLength(conArgs->client_p->m_torrentMetaInfo.getLength() % conArgs->client_p->m_torrentMetaInfo.getPieceLength());
          ConstBufferPtr reqBuffPtr = reqPiece.encode();
          const char* reqMsg = reinterpret_cast<const char*>(reqBuffPtr->buf());
          if (send(sockfd, reqMsg, reqBuffPtr->size(), 0) == -1) {
            perror("send request");
            return args;
          }

          char* bufPiece = new char[2200];
          if (recv(sockfd, bufPiece, 2200, 0) == -1) {
            perror("recv piece");
            return args;
          }

          ConstBufferPtr pieceBufPtr = make_shared<Buffer>(bufPiece, 2200);
          msg::Piece pieceMsg;
          pieceMsg.decode(pieceBufPtr);
          const char* block = reinterpret_cast<const char*>(pieceMsg.getBlock()->buf());
          string blockString = block;

          int count = 0;
          ConstBufferPtr blockHash = util::sha1(pieceMsg.getBlock());
          for (int j = 20*i; j < 20*i + 20; j++) {
            if (blockHash->buf()[count] != pieceCheck[j]) {
              isHash = true;              
              break;
            }
            count++;
          }

          if (isHash) {
            conArgs->client_p->setBitZero(conArgs->client_p->m_bitArray, i);
            i--;
            isHash = false;
            continue;
          }

          msg::Have have(i);
          ConstBufferPtr haveBufPtr = have.encode();
          const char* havMsg = reinterpret_cast<const char*>(haveBufPtr->buf());
          if (send(sockfd, havMsg, haveBufPtr->size(), 0) == -1) {
            perror("send have");
            return args;
          }
          int t = conArgs->client_p->m_torrentMetaInfo.getPieceLength();
          pthread_mutex_lock(&var);
          ofstream file(conArgs->client_p->m_torrentMetaInfo.getName(), ios::in | ios::out);
          file.seekp(long(t*i), ios::beg);
          if (i == 22) {
            file.write(blockString.c_str(), blockString.length() - 5);
            conArgs->client_p->leftDec(1766);
            conArgs->client_p->downloadInc(1766);
          }
          else {
            file.write(blockString.c_str(), blockString.length());
            conArgs->client_p->leftDec(pieceMsg.getBlock()->size()); 
            conArgs->client_p->downloadInc(pieceMsg.getBlock()->size());
          }
          file.close();
          delete [] bufPiece;
          pthread_mutex_unlock(&var);
        }
      }
      else {
          msg::Have have(i);
          ConstBufferPtr haveBufPtr = have.encode();
          const char* havMsg = reinterpret_cast<const char*>(haveBufPtr->buf());
          if (send(sockfd, havMsg, haveBufPtr->size(), 0) == -1) {
            perror("send have");
            return args;
          }
      }
    }
    return args;
  }

  void* Client::acceptManager(void* args)
  {
    int status = pthread_detach (pthread_self());
    if(status != 0) {
      perror("Detach thread");
      return args;
    }

    Client* client = (Client*)args;  
    pthread_t thread; 
    int serverfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int iPort = stoi(client->m_port);
    u_short sPort = (u_short)iPort
    ;
    if (serverfd < 0) {
      perror("socket() failed");
      return args; 
    }
    int clientS;
    struct sockaddr_in clientAddr; 
    unsigned int clientLength = sizeof(clientAddr); 
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(sPort);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    memset(serverAddr.sin_zero, '\0', sizeof(serverAddr.sin_zero));
    // int openThread;
    // pthread_t peerThread[MAX_CONNECTIONS];
    // bool alreadyConnected = false;

    if(bind(serverfd, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) < 0) {
      perror("bind() failed");
      return args;
    }
    if(listen(serverfd, MAX_CONNECTIONS) < 0) {
      perror("listen() failed");
      return args;
    }

   for (;;) {
    clientS = accept(serverfd, (struct sockaddr *) &clientAddr, &clientLength);
    cout << "accepted!" << endl;
    if (clientS < 0)
      perror("accept() failed");
      con_Args* conArgs = new con_Args;
      conArgs->thread = clientS;
      conArgs->client_p = client;
      pthread_create(&thread, NULL, client->acceptConnection, (void*)conArgs);
   }
   return args;
  }

  void* Client::acceptConnection(void* args)
  {
    cout << "hello111" << endl;
    pthread_detach(pthread_self());
    con_Args* conArgs = (con_Args*)args;

    char handBuf[68];
    if (recv(conArgs->thread, handBuf, 68, 0) < 0) {
      perror("recv handshake");
      return args;
    }

    ConstBufferPtr peerHShake = make_shared<Buffer>(handBuf,68);
    msg::HandShake pShake;
    pShake.decode(peerHShake);

    if (url::encode(pShake.getInfoHash()->buf(), 20) !=
        url::encode(conArgs->client_p->m_torrentMetaInfo.getHash()->buf(), 20) ||
        pShake.getPeerId() == conArgs->client_p->m_peerID) {
      cerr << "invalid info_hash" << endl;
      close(conArgs->thread);
      return args;
    }

    if (send(conArgs->thread, conArgs->client_p->m_handshake->buf(), conArgs->client_p->m_handshake->size(), 0) == -1) {
      perror("send handshake");
      return args;
    }

    char* bufTwo = new char[8];
    if (recv(conArgs->thread, bufTwo, 8, 0) == -1) {
      perror("recv bitfield");
      return args;
    }
    ConstBufferPtr peerBitfield = make_shared<Buffer>(bufTwo, 8);
    msg::Bitfield peerField;
    peerField.decode(peerBitfield);
    uint8_t* bitDecoded = const_cast<uint8_t*>(peerField.getBitfield()->buf());
    delete [] bufTwo;

    ConstBufferPtr clientBitfield = conArgs->client_p->m_bitfield.encode();
    const char* msg = reinterpret_cast<const char*>(clientBitfield->buf());
    if (send(conArgs->thread, msg, 8, 0) == -1) {
      perror("send bitfield");
      return args;
    }

    char bufThree[5];
    if (recv(conArgs->thread, bufThree, 5, 0) == -1) {
      perror("recv interested");
      return args;
    }

    ConstBufferPtr inter = make_shared<Buffer>(bufThree,5);
    msg::Interested interMsg; 
    interMsg.decode(inter);
    if (interMsg.getId() != msg::MSG_ID_INTERESTED) {
      close(conArgs->thread);
      return args;
    }

    msg::Unchoke unchokeMsg;
    if (send(conArgs->thread, unchokeMsg.encode()->buf(), unchokeMsg.encode()->size(), 0) == -1) {
      perror("send interested");
      return args;
    }

    for (;;) {
      cout << "waiting for request" << endl;
      char bufReq[100];
      if (recv(conArgs->thread, bufReq, 100, 0) < 0) {
        perror("recv req");
        return args;
      }
      cout << "checking request" << endl;
      ConstBufferPtr req = make_shared<Buffer>(bufReq, 100);
      msg::Request reqMsg;
      reqMsg.decode(req);
      if (reqMsg.getId() != msg::MSG_ID_REQUEST)
        cout << "noooooo" << endl;
      // if (reqMsg.getIndex() >= (uint32_t)conArgs->client_p->m_numPieces) {
      //   cerr << "no such piece" << endl;
      //   continue;
      // }
      cout << "prepare to send" << endl;
      ifstream file(conArgs->client_p->m_torrentMetaInfo.getName());
      if (reqMsg.getIndex() != (uint32_t)(conArgs->client_p->m_numPieces - 1)) {
        cout << "sending..." << endl;
        char* buffer = new char[conArgs->client_p->m_torrentMetaInfo.getPieceLength()];
        file.seekg(reqMsg.getIndex()*conArgs->client_p->m_torrentMetaInfo.getPieceLength());
        file.read(buffer, conArgs->client_p->m_torrentMetaInfo.getPieceLength());
        ConstBufferPtr bufBlock = make_shared<Buffer>(buffer, conArgs->client_p->m_torrentMetaInfo.getPieceLength());
        msg::Piece pieceMsg(reqMsg.getIndex(), 0, bufBlock);
        ConstBufferPtr encodeBlock = pieceMsg.encode();
        conArgs->client_p->uploadInc(conArgs->client_p->m_torrentMetaInfo.getPieceLength());
        delete [] buffer;        
        const char* msg = reinterpret_cast<const char*>(encodeBlock->buf());
        if (send(conArgs->thread, msg, encodeBlock->size(), 0) == -1) {
          perror("send piece");
          return args;
        }
      }

      if (reqMsg.getIndex() == (uint32_t)(conArgs->client_p->m_numPieces - 1)) {
        int size = (int)conArgs->client_p->m_torrentMetaInfo.getLength()% (int)conArgs->client_p->m_torrentMetaInfo.getPieceLength();
        char* buffer = new char[size];
        file.seekg(reqMsg.getIndex()*conArgs->client_p->m_torrentMetaInfo.getPieceLength());
        file.read(buffer, size);
        ConstBufferPtr bufBlock = make_shared<Buffer>(buffer, size);
        msg::Piece pieceMsg(reqMsg.getIndex(), 0, bufBlock);
        ConstBufferPtr encodeBlock = pieceMsg.encode();
        const char* msg = reinterpret_cast<const char*>(encodeBlock->buf());
        conArgs->client_p->uploadInc(size);
        delete [] buffer;
        if (send(conArgs->thread, msg, encodeBlock->size(), 0) == -1) {
          perror("send piece");
          return args;
        }
      }

      char bufHave[10];
      if (recv(conArgs->thread, bufHave, 10, 0) < 0) {
        perror ("recv have");
        return args;
      }
      ConstBufferPtr have = make_shared<Buffer>(bufHave, 10);
      msg::Have haveMsg;
      haveMsg.decode(have);
      int index = haveMsg.getIndex();
      cout << index << endl;
      if (haveMsg.getIndex() >= (uint32_t)conArgs->client_p->m_numPieces) {
        cerr << "no such piece" << endl;
        continue;
      }

      conArgs->client_p->setBitOne(bitDecoded, haveMsg.getIndex());
      cout << "bit set!" << endl;
    }
  return args;
  }
} //namespace sbt
