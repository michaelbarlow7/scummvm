/* ScummVM - Graphic Adventure Engine
 *
 * ScummVM is the legal property of its developers, whose names
 * are too numerous to list here. Please refer to the COPYRIGHT
 * file distributed with this source distribution.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "scumm/he/intern_he.h"
#include "scumm/he/moonbase/moonbase.h"
#include "scumm/he/moonbase/net_main.h"
#include "scumm/he/moonbase/net_defines.h"

namespace Scumm {

Net::Net(ScummEngine_v100he *vm) : _latencyTime(1), _fakeLatency(false), _vm(vm) {
	//some defaults for fields

	_tmpbuffer = (byte *)malloc(MAX_PACKET_SIZE);

	_enet = nullptr;

	_sessionHost = nullptr;
	_broadcastSocket = nullptr;

	_userNames = Common::Array<Common::String>();
	_myUserId = -1;
	_myPlayerKey = -1;
	_fromUserId = -1;
	_lastResult = 0;

	_sessionid = -1;
	_isHost = false;
	_sessionName = Common::String();
	_localSessions = Common::Array<_localSession>();
}

Net::~Net() {
	free(_tmpbuffer);
	closeProvider();
}

int Net::hostGame(char *sessionName, char *userName) {
	if (createSession(sessionName)) {
		if (addUser(userName, userName)) {
			_myUserId = _userNames.size();
			return 1;
		} else {
			_vm->displayMessage(0, "Error Adding User \"%s\" to Session \"%s\"", userName, sessionName);
			endSession();
			closeProvider();
		}
	} else {
		_vm->displayMessage(0, "Error creating session \"%s\"", userName );

		closeProvider();
	}

	return 0;
}

int Net::joinGame(Common::String IP, char *userName) {
	// This gets called when attempting to join with the --join-game command line param.
	debug(1, "Net::joinGame(\"%s\", \"%s\")", IP.c_str(), userName); // PN_JoinTCPIPGame
	int port = 0;
	// Parse and seperate the port from the IP address if any.
	int portPos = IP.findFirstOf(":");
	if (portPos > -1) {
		port = atoi(IP.substr(portPos + 1).c_str());
		IP = IP.substr(0, portPos);
	}

	bool isLocal = false;
	// TODO: 20-bit block address (172.16.0.0 – 172.31.255.255)
	if (IP == "127.0.0.1" || IP == "localhost" || IP == "255.255.255.255" ||
		IP.matchString("10.*.*.*") || IP.matchString("192.168.*.*")) {
		isLocal = true;
	}

	if (isLocal) {
		if (!port) {
			// Local connection with no port specified.  Send a session request to get port:
			startQuerySessions();
			if (!_broadcastSocket) {
				return 0;
			}

			_localSessions.clear();
			_broadcastSocket->send(IP.c_str(), 9130, "{\"cmd\": \"get_session\"}");
			
			uint tickCount = 0;
			while(!_localSessions.size()) {
				serviceBroadcast();
				// Wait for one minute for response before giving up
				tickCount += 5;
				g_system->delayMillis(5);
				if (tickCount >= 1000)
					break;
			}

			if (!_localSessions.size())
				return 0;

			if (IP == "255.255.255.255")
				IP = _localSessions[0].host;
			port = _localSessions[0].port;
			stopQuerySessions();
		}
		// We got our address and port, attempt connection:
		if (connectToSession(IP, port)) {
			// Connected, add our user.
			return addUser(userName, userName);
		}
	} else {
		warning("STUB: joinGame: Public IP connection %s", IP.c_str());
	}

	return 0;
}

bool Net::connectToSession(Common::String address, int port) {
	_sessionHost = _enet->connectToHost(address, port);
	if (!_sessionHost)
		return false;
	
	_isHost = false;
	return true;
}

int Net::addUser(char *shortName, char *longName) {
	debug(1, "Net::addUser(\"%s\", \"%s\")", shortName, longName); // PN_AddUser
	// TODO: What's the difference between shortName and longName?
	
	if (_isHost) {
		if (_userNames.size() > 4) {
			// We are full.
			return 0;
		}
		_userNames.push_back(longName);
		return 1;
	}

	// Client:
	Common::String addUser = Common::String::format(
		"{\"cmd\":\"add_user\",\"name\":\"%s\"}", longName);
	
	_sessionHost->send(addUser.c_str(), 0, 0, true);

	uint tickCount = 0;
	while(_myUserId == -1) {
		remoteReceiveData(12);
		// Wait for one minute for our user id before giving up
		tickCount += 5;
		g_system->delayMillis(5);
		if (tickCount >= 1000)
			break;
	}
	return (_myUserId > -1) ? 1 : 0;
}

int Net::removeUser() {
	debug(1, "Net::removeUser()"); // PN_RemoveUser

	if (_myUserId != -1)
		destroyPlayer(_myUserId);

	return 1;
}

int Net::whoSentThis() {
	debug(1, "Net::whoSentThis(): return %d", _fromUserId); // PN_WhoSentThis
	return _fromUserId;
}

int Net::whoAmI() {
	debug(1, "Net::whoAmI(): return %d", _myUserId); // PN_WhoAmI
	return _myUserId;
}

int Net::createSession(char *name) {
	debug(1, "Net::createSession(\"%s\")", name); // PN_CreateSession

	if (!_enet) {
		return 0;
	};

	_sessionid = -1;
	_sessionHost = _enet->createHost("0.0.0.0", 0, 3);

	// while(rq.state() == Networking::PROCESSING) {
	// 	g_system->delayMillis(5);
	// }

	if (!_sessionHost) {
		return 0;
	}
	
	_isHost = true;
	
	// TODO: Config to enable/disable LAN broadcasting.
	_broadcastSocket = _enet->createSocket("0.0.0.0", 9130);
	if (!_broadcastSocket) {
		warning("NETWORK: Unable to create broadcast socket, your game will not be broadcast over LAN");
		return 1;
	}

	_sessionName = name;

	return 1;
}

int Net::joinSession(int sessionIndex) {
	debug(1, "Net::joinSession(%d)", sessionIndex); // PN_JoinSession
	if (_localSessions.empty()) {
		warning("Net::joinSession(): no sessions");
		return 0;
	}

	if (sessionIndex >= (int)_localSessions.size()) {
		warning("Net::joinSession(): session number too big: %d >= %d", sessionIndex, _localSessions.size());
		return 0;
	}

	bool success = connectToSession(_localSessions[sessionIndex].host, _localSessions[sessionIndex].port);
	if (!success) {
		_vm->displayMessage(0, "Unable to join game session with address \"%s:%d\"", _localSessions[sessionIndex].host.c_str(), _localSessions[sessionIndex].port);
		return false;
	}

	return true;
}

int Net::endSession() {
	debug(1, "Net::endSession()"); // PN_EndSession

	if (_sessionHost) {
		delete _sessionHost;
		_sessionHost = nullptr;
	}
	if (_broadcastSocket) {
		delete _broadcastSocket;
		_broadcastSocket = nullptr;
	}
	
	_userNames.clear();	
	_sessionid = -1;
	_sessionName.clear();
	_myUserId = -1;
	_fromUserId = -1;

	return 0;
}

void Net::disableSessionJoining() {
	debug(1, "Net::disableSessionJoining()"); // PN_DisableSessionPlayerJoin
	warning("STUB: Net::disableSessionJoining()");
}

void Net::enableSessionJoining() {
	warning("STUB: Net::enableSessionJoining()"); // PN_EnableSessionPlayerJoin
}

void Net::setBotsCount(int botsCount) {
	warning("STUB: Net::setBotsCount(%d)", botsCount); // PN_SetAIPlayerCountKludge
}

int32 Net::setProviderByName(int32 parameter1, int32 parameter2) {
	char name[MAX_PROVIDER_NAME];
	char ipaddress[MAX_IP_SIZE];

	ipaddress[0] = '\0';

	_vm->getStringFromArray(parameter1, name, sizeof(name));
	if (parameter2)
		_vm->getStringFromArray(parameter2, ipaddress, sizeof(ipaddress));

	debug(1, "Net::setProviderByName(\"%s\", \"%s\")", name, ipaddress); // PN_SetProviderByName

	// Emulate that we found a TCP/IP provider

	// Create a new ENet instance and initalize the library.
	if (_enet) {
		warning("Net::setProviderByName: ENet instance already exists.");
		return 1;
	}
	_enet = new Networking::ENet();
	if (!_enet->initalize()) {
		_vm->displayMessage(0, "Unable to initalize ENet library.");
		Net::closeProvider();
		return 0;
	}
	return 1;
}

void Net::setFakeLatency(int time) {
	_latencyTime = time;
	debug("NETWORK: Setting Fake Latency to %d ms", _latencyTime);
	_fakeLatency = true;
}

bool Net::destroyPlayer(int32 playerDPID) {
	// bool PNETWIN_destroyplayer(DPID idPlayer)
	debug(1, "Net::destroyPlayer(%d)", playerDPID);
	warning("STUB: Net::destroyPlayer(%d)", playerDPID);

	return false;
}

int32 Net::startQuerySessions() {
	// warning("STUB: Net::startQuerySessions()");
	debug(1, "Net::startQuerySessions()");

	if (!_broadcastSocket) {
		_broadcastSocket = _enet->createSocket("0.0.0.0", 0);
	}
	// debug(1, "Net::startQuerySessions(): got %d", (int)_sessions->countChildren());
	return 0;
}

int32 Net::updateQuerySessions() {
	debug(1, "Net::updateQuerySessions()"); // UpdateQuerySessions

	if (_broadcastSocket) {
		// Send a session query to the broadcast address.
		_broadcastSocket->send("255.255.255.255", 9130, "{\"cmd\": \"get_session\"}");
	}
	
	uint32 tickCount = g_system->getMillis() + 100;
	while(g_system->getMillis() < tickCount) {
		serviceBroadcast();
	}

	for (Common::Array<_localSession>::iterator i = _localSessions.begin(); i != _localSessions.end();) {
		if (g_system->getMillis() - i->timestamp > 5000) {
			// It has been 5 seconds since we have last seen this session, remove it.
			i = _localSessions.erase(i);
		} else {
			i++;
		}
	}

	return _localSessions.size();
}

void Net::stopQuerySessions() {
	debug(1, "Net::stopQuerySessions()"); // StopQuerySessions

	if (_broadcastSocket) {
		delete _broadcastSocket;
		_broadcastSocket = nullptr;
	}
	
	_localSessions.clear();
	// No op
}

int Net::querySessions() {
	warning("STUB: Net::querySessions()"); // PN_QuerySessions
	return 0;
}

int Net::queryProviders() {
	debug(1, "Net::queryProviders()"); // PN_QueryProviders

	// Emulate that we have 1 provider, TCP/IP
	return 1;
}

int Net::setProvider(int providerIndex) {
	warning("STUB: Net::setProvider(%d)", providerIndex); // PN_SetProvider
	return 0;
}

int Net::closeProvider() {
	debug(1, "Net::closeProvider()"); // PN_CloseProvider
	if (_enet) {
		// Destroy all ENet instances and deinitalize.
		if (_sessionHost) {
			endSession();
		}
		delete _enet;
		_enet = nullptr;
	}

	return 1;
}

bool Net::initAll() {
	warning("STUB: Net::initAll()"); // PN_DoInitAll
	return false;
}

bool Net::initProvider() {
	warning("STUB: Net::initProvider()"); // PN_DoInitProvider
	return false;
}

bool Net::initSession() {
	warning("STUB: Net::initSession()"); // PN_DoInitSession
	return false;
}

bool Net::initUser() {
	warning("STUB: Net::initUser()"); // PN_DoInitUser
	return false;
}

void Net::remoteStartScript(int typeOfSend, int sendTypeParam, int priority, int argsCount, int32 *args) {
	Common::String res = "\"params\": [";

	if (argsCount > 2)
		for (int i = 0; i < argsCount - 1; i++)
			res += Common::String::format("%d, ", args[i]);

	if (argsCount > 1)
		res += Common::String::format("%d]", args[argsCount - 1]);
	else
		res += "]";

	debug(1, "Net::remoteStartScript(%d, %d, %d, %d, ...)", typeOfSend, sendTypeParam, priority, argsCount); // PN_RemoteStartScriptCommand

	remoteSendData(typeOfSend, sendTypeParam, PACKETTYPE_REMOTESTARTSCRIPT, res, priority);
}

int Net::remoteSendData(int typeOfSend, int sendTypeParam, int type, Common::String data, int priority, int defaultRes, bool wait, int callid) {
	if (!_enet || !_sessionHost || !_myUserId)
		return defaultRes;
	// Since I am lazy, instead of constructing the JSON object manually
	// I'd rather parse it
	Common::String res = Common::String::format(
		"{\"cmd\":\"game\",\"from\":%d,\"to\":%d,\"toparam\":%d,"
		"\"type\":%d, \"reliable\":%s, \"data\": { %s } }",
		_myUserId, typeOfSend, sendTypeParam, type,
		priority == PN_PRIORITY_HIGH ? "true" : "false", data.c_str());

	debug(1, "NETWORK: Sending data: %s", res.c_str());
	Common::JSONValue *str = Common::JSON::parse(res.c_str());
	if (_isHost)
		handleGameDataHost(str, sendTypeParam - 1);

	_sessionHost->send(res.c_str(), 0, 0, priority == PN_PRIORITY_HIGH);
	return defaultRes;
}

void Net::remoteSendArray(int typeOfSend, int sendTypeParam, int priority, int arrayIndex) {
	debug(1, "Net::remoteSendArray(%d, %d, %d, %d)", typeOfSend, sendTypeParam, priority, arrayIndex & ~0x33539000); // PN_RemoteSendArrayCommand

	ScummEngine_v100he::ArrayHeader *ah = (ScummEngine_v100he::ArrayHeader *)_vm->getResourceAddress(rtString, arrayIndex & ~0x33539000);

	Common::String jsonData = Common::String::format(
		"\"type\":%d, \"dim1start\":%d, \"dim1end\":%d, \"dim2start\":%d, \"dim2end\":%d, \"data\": [",
		ah->type, ah->dim1start, ah->dim1end, ah->dim2start, ah->dim2end);

	int32 size = (FROM_LE_32(ah->dim1end) - FROM_LE_32(ah->dim1start) + 1) *
		(FROM_LE_32(ah->dim2end) - FROM_LE_32(ah->dim2start) + 1);

	for (int i = 0; i < size; i++) {
		int32 data;

		switch (FROM_LE_32(ah->type)) {
		case ScummEngine_v100he::kByteArray:
		case ScummEngine_v100he::kStringArray:
			data = ah->data[i];
			break;

		case ScummEngine_v100he::kIntArray:
			data = (int16)READ_LE_UINT16(ah->data + i * 2);
			break;

		case ScummEngine_v100he::kDwordArray:
			data = (int32)READ_LE_UINT32(ah->data + i * 4);
			break;

		default:
			error("Net::remoteSendArray(): Unknown array type %d for array %d", FROM_LE_32(ah->type), arrayIndex);
		}

		jsonData += Common::String::format("%d", data);

		if (i < size - 1)
			jsonData += ", ";
		else
			jsonData += "]";
	}

	remoteSendData(typeOfSend, sendTypeParam, PACKETTYPE_REMOTESENDSCUMMARRAY, jsonData, priority);
}

int Net::remoteStartScriptFunction(int typeOfSend, int sendTypeParam, int priority, int defaultReturnValue, int argsCount, int32 *args) {
	warning("STUB: Net::remoteStartScriptFunction(%d, %d, %d, %d, %d, ...)", typeOfSend, sendTypeParam, priority, defaultReturnValue, argsCount);
	return 0;
	int callid = _vm->_rnd.getRandomNumber(1000000);

	Common::String res = Common::String::format("\"callid\":%d, \"params\": [", callid);

	if (argsCount > 2)
		for (int i = 0; i < argsCount - 1; i++)
			res += Common::String::format("%d, ", args[i]);

	if (argsCount > 1)
		res += Common::String::format("%d]", args[argsCount - 1]);
	else
		res += "]";

	debug(1, "Net::remoteStartScriptFunction(%d, %d, %d, %d, %d, ...)", typeOfSend, sendTypeParam, priority, defaultReturnValue, argsCount); // PN_RemoteStartScriptFunction

	return remoteSendData(typeOfSend, sendTypeParam, PACKETTYPE_REMOTESTARTSCRIPTRETURN, res, defaultReturnValue, true, callid);
}

bool Net::getHostName(char *hostname, int length) {
	warning("STUB: Net::getHostName(\"%s\", %d)", hostname, length); // PN_GetHostName
	return false;
}

bool Net::getIPfromName(char *ip, int ipLength, char *nameBuffer) {
	warning("STUB: Net::getIPfromName(\"%s\", %d, \"%s\")", ip, ipLength, nameBuffer); // PN_GetIPfromName
	return false;
}

void Net::getSessionName(int sessionNumber, char *buffer, int length) {
	debug(1, "Net::getSessionName(%d, ..., %d)", sessionNumber, length); // PN_GetSessionName

	if (_localSessions.empty()) {
		*buffer = '\0';
		warning("Net::getSessionName(): no sessions");
		return;
	}

	if (sessionNumber >= (int)_localSessions.size()) {
		*buffer = '\0';
		warning("Net::getSessionName(): session number too big: %d >= %d", sessionNumber, (int)_localSessions.size());
		return;
	}

	Common::strlcpy(buffer, _localSessions[sessionNumber].name.c_str(), length);
}

int Net::getSessionPlayerCount(int sessionNumber) {
	debug(1, "Net::getSessionPlayerCount(%d)", sessionNumber); // case GET_SESSION_PLAYER_COUNT_KLUDGE:

	if (_localSessions.empty()) {
		warning("Net::getSessionPlayerCount(): no sessions");
		return 0;
	}

	if (sessionNumber >= (int)_localSessions.size()) {
		warning("Net::getSessionPlayerCount(): session number too big: %d >= %d", sessionNumber, (int)_localSessions.size());
		return 0;
	}

	if (_localSessions[sessionNumber].players < 1) {
		warning("Net::getSessionPlayerCount(): no players in session");
		return 0;
	}

	return _localSessions[sessionNumber].players;
}

void Net::getProviderName(int providerIndex, char *buffer, int length) {
	warning("STUB: Net::getProviderName(%d, \"%s\", %d)", providerIndex, buffer, length); // PN_GetProviderName
}

bool Net::serviceBroadcast() {
	if (!_broadcastSocket)
		return false;

	if (!_broadcastSocket->receive())
		return false;
	
	handleBroadcastData(_broadcastSocket->getData(), _broadcastSocket->getHost(), _broadcastSocket->getPort());
	return true;
}

void Net::handleBroadcastData(Common::String data, Common::String host, int port) {
	debug(1, "NETWORK: Received data from broadcast socket.  Source: %s:%d  Data: %s", host.c_str(), port, data.c_str());

	Common::JSONValue *json = Common::JSON::parse(data.c_str());
	if (!json) {
		// Just about anything could come from the broadcast address, so do not warn.
		debug(1, "NETWORK: Not a JSON string, ignoring.");
		return;
	}
	if (!json->isObject()){
		warning("NETWORK: Received non JSON object from broadcast socket: \"%s\"", data.c_str());
		return;
	}

	Common::JSONObject root = json->asObject();
	if (root.contains("cmd") && root["cmd"]->isString()) {
		Common::String command = root["cmd"]->asString();

		if (command == "get_session") {
			// Session query.
			if (_sessionHost) {
				Common::String resp = Common::String::format(
					"{\"cmd\":\"session_resp\", \"name\":\"%s\", \"players\":%d}",
					_sessionName.c_str(), _userNames.size());
				
				// Send this through the session host instead of the broadcast socket
				// because that will send the correct port to connect to.
				// They'll still receive it though, that's the power of connection-less sockets.
				_sessionHost->sendRawData(host, port, resp.c_str());
			}
		} else if (command == "session_resp") {
			if (!_sessionHost && root.contains("name") && root.contains("players")) {
				Common::String name = root["name"]->asString();
				int players = root["players"]->asIntegerNumber();

				// Check if we already know about this session:
				for (Common::Array<_localSession>::iterator i = _localSessions.begin(); i != _localSessions.end(); i++) {
					if (i->host == host && i->port == port) {
						// Yes we do, Update the timestamp,
						i->timestamp = g_system->getMillis();
						return;
					}
				}
				// If we're here, assume that we had no clue about this session, store it.
				_localSession session;
				session.timestamp = g_system->getMillis();
				session.host = host;
				session.port = port;
				session.name = name;
				session.players = players;
				_localSessions.push_back(session);
			}
		}
	}
}

bool Net::remoteReceiveData(uint32 tickCount) {
	uint8 messageType = _sessionHost->service();
	switch (messageType) {
	case ENET_EVENT_TYPE_NONE:
		return true;
	case ENET_EVENT_TYPE_CONNECT:
		{
			debug(1, "NETWORK: New connection from %s:%d", _sessionHost->getHost().c_str(), _sessionHost->getPort());
			return true;
		}
		return true;
	case ENET_EVENT_TYPE_DISCONNECT:
		{
			debug(1, "NETWORK: Connection from %s:%d has disconnected.", _sessionHost->getHost().c_str(), _sessionHost->getPort());
			// TODO: Let the game know.
			return true;
		}
		return true;
	case ENET_EVENT_TYPE_RECEIVE:
		{
			Common::String host = _sessionHost->getHost();
			int port = _sessionHost->getPort();
			debug(1, "NETWORK: Got data from %s:%d", host.c_str(), port);
			
			int peerIndex = _sessionHost->getPeerIndexFromHost(host, port);
			if (peerIndex == -1) {
				warning("NETWORK: Unable to get peer index for host %s:%d", host.c_str(), port);
				_sessionHost->destroyPacket();
				return false;
			}

			Common::String data = _sessionHost->getPacketData();
			debug(1, "%s", data.c_str());
			Common::JSONValue *json = Common::JSON::parse(data.c_str());
			if (!json) {
				// Just about anything could come from the broadcast address, so do not warn.
				warning("NETWORK: Received non-JSON string.  Got: \"%s\"", data.c_str());
				_sessionHost->destroyPacket();
				return false;
			}
			if (!json->isObject()){
				warning("NETWORK: Received non JSON object from broadcast socket: \"%s\"", data.c_str());
				_sessionHost->destroyPacket();
				return false;
			}

			Common::JSONObject root = json->asObject();
			if (root.contains("cmd") && root["cmd"]->isString()) {
				Common::String command = root["cmd"]->asString();
				
				if (command == "add_user") {
					if (root.contains("name")) {
						Common::String name = root["name"]->asString();
						_userNames.push_back(name);

						Common::String resp = Common::String::format(
							"{\"cmd\":\"add_user_resp\",\"id\":%d}", _userNames.size());
						_sessionHost->send(resp.c_str(), peerIndex);
					}
				} else if (command == "add_user_resp") {
					if (root.contains("id")) {
						_myUserId = root["id"]->asIntegerNumber();
					}
				} else if (command == "game") {
					if (_isHost) 
						handleGameDataHost(json, peerIndex);
					else
						handleGameData(json, peerIndex);
				}
			}
			_sessionHost->destroyPacket();
		}
		return true;
		break;
	}
	return true;
}

void Net::doNetworkOnceAFrame(int msecs) {
	if (!_enet || !_sessionHost)
		return;

	remoteReceiveData(msecs);

	if (_broadcastSocket)
		serviceBroadcast();
}

void Net::handleGameData(Common::JSONValue *json, int peerIndex) {
	_fromUserId = json->child("from")->asIntegerNumber();
	uint type = json->child("type")->asIntegerNumber();

	uint32 *params;

	switch (type) {
	case PACKETTYPE_REMOTESTARTSCRIPT:
		{
			int datalen = json->child("data")->child("params")->asArray().size();
			params = (uint32 *)_tmpbuffer;

			for (int i = 0; i < datalen; i++) {
				*params = json->child("data")->child("params")->asArray()[i]->asIntegerNumber();
				params++;
			}

			_vm->runScript(_vm->VAR(_vm->VAR_REMOTE_START_SCRIPT), 1, 0, (int *)_tmpbuffer);
			// FIXME: We are supposed pop a value returned from START_SCRIPT out of the stack,
			// but when the host shoots something, it the script call gets nested, meaning it'll
			// pop twice, causing an assertion error.  It would be nice to get this figured out
			// in a case of a seriously very long game session or else, stack overflow...
			// _vm->pop();
		}
		break;

	case PACKETTYPE_REMOTESTARTSCRIPTRETURN:
		{
			int datalen = json->child("data")->child("params")->asArray().size();
			params = (uint32 *)_tmpbuffer;

			for (int i = 0; i < datalen; i++) {
				*params = json->child("data")->child("params")->asArray()[i]->asIntegerNumber();
				params++;
			}

			_vm->runScript(_vm->VAR(_vm->VAR_REMOTE_START_SCRIPT), 1, 0, (int *)_tmpbuffer);
			int result = _vm->pop();

			Common::String res = Common::String::format("\"result\": %d, \"callid\": %d", result,
					(int)json->child("data")->child("callid")->asIntegerNumber());

			remoteSendData(PN_SENDTYPE_INDIVIDUAL, _fromUserId, PACKETTYPE_REMOTESTARTSCRIPTRESULT, res, PN_PRIORITY_HIGH);
		}
		break;

	case PACKETTYPE_REMOTESTARTSCRIPTRESULT:
		//
		// Ignore it.
		//

		break;

	case PACKETTYPE_REMOTESENDSCUMMARRAY:
		{
			int newArray = 0;

			// Assume that the packet data contains a "SCUMM PACKAGE"
			// and unpack it into an scumm array :-)

			int dim1start = json->child("data")->child("dim1start")->asIntegerNumber();
			int dim1end   = json->child("data")->child("dim1end")->asIntegerNumber();
			int dim2start = json->child("data")->child("dim2start")->asIntegerNumber();
			int dim2end   = json->child("data")->child("dim2end")->asIntegerNumber();
			int atype     = json->child("data")->child("type")->asIntegerNumber();

			byte *data = _vm->defineArray(0, atype, dim2start, dim2end, dim1start, dim1end, true, &newArray);

			int32 size = (dim1end - dim1start + 1) * (dim2end - dim2start + 1);

			int32 value;

			for (int i = 0; i < size; i++) {
				value = json->child("data")->child("data")->asArray()[i]->asIntegerNumber();

				switch (atype) {
				case ScummEngine_v100he::kByteArray:
				case ScummEngine_v100he::kStringArray:
					data[i] = value;
					break;

				case ScummEngine_v100he::kIntArray:
					WRITE_LE_UINT16(data + i * 2, value);
					break;

				case ScummEngine_v100he::kDwordArray:
					WRITE_LE_UINT32(data + i * 4, value);
					break;

				default:
					error("Net::remoteReceiveData(): Unknown array type %d", atype);
				}
			}

			memset(_tmpbuffer, 0, 25 * 4);
			WRITE_UINT32(_tmpbuffer, newArray);

			// Quick start the script (1st param is the new array)
			_vm->runScript(_vm->VAR(_vm->VAR_NETWORK_RECEIVE_ARRAY_SCRIPT), 1, 0, (int *)_tmpbuffer);
		}
		break;

	default:
		warning("Moonbase: Received unknown network command %d", type);
	}

}

void Net::handleGameDataHost(Common::JSONValue *json, int peerIndex) {
	int to = json->child("to")->asIntegerNumber();
	int toparam = json->child("toparam")->asIntegerNumber();
	bool reliable = json->child("reliable")->asBool();

	switch(to) {
	case PN_SENDTYPE_INDIVIDUAL:
		{
			if (toparam == _myUserId) {
				// It's for us, handle it.
				handleGameData(json, peerIndex);
				return;
			}
			// It's for someone else, transfer it.
			if (_userNames.size() > (uint)toparam) {
				warning("NETWORK: Got individual message for %d, but we don't know this person!  Ignoring...", toparam);
				return;
			}
			if (toparam - 1 < (int)_userNames.size())
				debug(1, "NETWORK: Transfering message to %s (%d), peerIndex: %d", _userNames[toparam - 1].c_str(), toparam, toparam - 2);
			else
				debug(1, "NETWORK: Transfering message to %d, peerIndex: %d", toparam, toparam - 2);
			Common::String str = Common::JSON::stringify(json);
			_sessionHost->send(str.c_str(), toparam - 2, 0, reliable);
		}
		break;
	case PN_SENDTYPE_GROUP:
		warning("STUB: PN_SENDTYPE_GROUP");
		break;
	case PN_SENDTYPE_HOST:
		{
			// It's for us, handle it.
			handleGameData(json, peerIndex);
		}
		break;
	case PN_SENDTYPE_ALL:
		{
			// It's for all of us, including the host.
			if (_fromUserId != _myUserId)
				handleGameData(json, peerIndex);
			Common::String str = Common::JSON::stringify(json);
			for (uint i = 0; i < _userNames.size(); i++) {
				if (i != (uint)peerIndex)
					_sessionHost->send(str.c_str(), i, 0, reliable);
			}
		}
		break;
	default:
		warning("NETWORK: Unknown data type: %d", to);
	
	}
}

} // End of namespace Scumm
