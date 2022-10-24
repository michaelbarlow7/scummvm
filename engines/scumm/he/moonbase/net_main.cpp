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

	_packbuffer = (byte *)malloc(MAX_PACKET_SIZE + DATA_HEADER_SIZE);
	_tmpbuffer = (byte *)malloc(MAX_PACKET_SIZE);

	_enet = nullptr;

	_sessionHost = nullptr;
	_broadcastSocket = nullptr;

	_userNames = Common::Array<Common::String>();
	_myUserId = -1;
	_myPlayerKey = -1;
	_lastResult = 0;

	_sessionsBeingQueried = false;

	_sessionid = -1;
	_sessionName = Common::String();
	_localSessions = Common::Array<_localSession>();
	_sessions = nullptr;
	_packetdata = nullptr;

	_serverprefix = "http://localhost/moonbase";

}

Net::~Net() {
	free(_tmpbuffer);
	free(_packbuffer);

	delete _sessions;
	delete _packetdata;
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

int Net::joinGame(char *IP, char *userName) {
	warning("STUB: Net::joinGame(\"%s\", \"%s\")", IP, userName); // PN_JoinTCPIPGame
	return 0;
}

int Net::addUser(char *shortName, char *longName) {
	debug(1, "Net::addUser(\"%s\", \"%s\")", shortName, longName); // PN_AddUser

	// TODO: What's the difference between shortName and longName?
	if (_userNames.size() > 4) {
		// We are full.
		return 0;
	}
	_userNames.push_back(longName);
	return 1;
}

int Net::removeUser() {
	debug(1, "Net::removeUser()"); // PN_RemoveUser

	if (_myUserId != -1)
		destroyPlayer(_myUserId);

	return 1;
}

int Net::whoSentThis() {
	debug(1, "Net::whoSentThis()"); // PN_WhoSentThis
	return _packetdata->child("from")->asIntegerNumber();
}

int Net::whoAmI() {
	debug(1, "Net::whoAmI()"); // PN_WhoAmI

	return _myUserId;
}

int Net::createSession(char *name) {
	debug(1, "Net::createSession(\"%s\")", name); // PN_CreateSession

	if (!_enet) {
		return 0;
	};

	_sessionid = -1;
	_sessionHost = _enet->create_host("0.0.0.0", 0, 3);

	// while(rq.state() == Networking::PROCESSING) {
	// 	g_system->delayMillis(5);
	// }

	if (!_sessionHost) {
		return 0;
	}
	
	// TODO: Config to enable/disable LAN broadcasting.
	_broadcastSocket = _enet->create_socket("0.0.0.0", 9130);
	if (!_broadcastSocket) {
		warning("NETWORK: Unable to create broadcast socket, your game will not be broadcast over LAN");
		return 1;
	}

	_sessionName = name;

	return 1;
}

void Net::createSessionCallback(Common::JSONValue *response) {
	Common::JSONObject info = response->asObject();

	if (info.contains("sessionid")) {
		_sessionid = info["sessionid"]->asIntegerNumber();
	}
	debug(1, "createSessionCallback: got: '%s' as %d", response->stringify().c_str(), _sessionid);
}

int Net::joinSession(int sessionIndex) {
	debug(1, "Net::joinSession(%d)", sessionIndex); // PN_JoinSession

	if (!_sessions) {
		warning("Net::joinSession(): no sessions");
		return 0;
	}

	if (sessionIndex >= (int)_sessions->countChildren()) {
		warning("Net::joinSession(): session number too big: %d >= %d", sessionIndex, (int)_sessions->countChildren());
		return 0;
	}

	if (!_sessions->child(sessionIndex)->hasChild("sessionid")) {
		warning("Net::joinSession(): no sessionid in session");
		return 0;
	}

	_sessionid = _sessions->child(sessionIndex)->child("sessionid")->asIntegerNumber();

	return 1;
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
		_broadcastSocket = _enet->create_socket("0.0.0.0", 0);
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
		if (g_system->getMillis() - i->lastSeen > 5000) {
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

	_sessionsBeingQueried = false;
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

	remoteSendData(typeOfSend, sendTypeParam, PACKETTYPE_REMOTESTARTSCRIPT, res);
}

int Net::remoteSendData(int typeOfSend, int sendTypeParam, int type, Common::String data, int defaultRes, bool wait, int callid) {
	warning("STUB: Net::remoteSendData(%d, %d, %d, ...", typeOfSend, sendTypeParam, type);
	return defaultRes || 0;
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

	remoteSendData(typeOfSend, sendTypeParam, PACKETTYPE_REMOTESENDSCUMMARRAY, jsonData);
}

int Net::remoteStartScriptFunction(int typeOfSend, int sendTypeParam, int priority, int defaultReturnValue, int argsCount, int32 *args) {
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
	
	handleBroadcastData(_broadcastSocket->get_data(), _broadcastSocket->get_host(), _broadcastSocket->get_port());
	return true;
}

void Net::handleBroadcastData(Common::String data, Common::String host, int port) {
	debug(1, "NETWORK: Received data from broadcast socket.  Source: %s:%d  Data: %s", host.c_str(), port, data.c_str());

	Common::JSONValue *json = Common::JSON::parse(data.c_str());
	if (!json) {
		// Just about anything could come from the broadcast address, so do not warn.
		debug(1, "NETWORK: Not a JSON string, ignoring.");
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
				_broadcastSocket->send(host, port, resp.c_str());
			}
		} else if (command == "session_resp") {
			if (!_sessionHost && root.contains("name") && root.contains("players")) {
				Common::String name = root["name"]->asString();
				int players = root["players"]->asIntegerNumber();

				// Check if we already know about this session:
				for (Common::Array<_localSession>::iterator i = _localSessions.begin(); i != _localSessions.end(); i++) {
					if (i->host == host && i->port == port) {
						// Yes we do, Update the lastSeen timestamp,
						i->lastSeen = g_system->getMillis();
						return;
					}
				}
				// If we're here, assume that we had no clue about this session, store it.
				_localSession session;
				session.lastSeen = g_system->getMillis();
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
	// warning("STUB: Net::remoteReceiveData");
	return false;

	_packetdata = nullptr;

	if (!_packetdata || _packetdata->child("size")->asIntegerNumber() == 0)
		return false;

	uint from = _packetdata->child("from")->asIntegerNumber();
	uint type = _packetdata->child("type")->asIntegerNumber();

	uint32 *params;

	switch (type) {
	case PACKETTYPE_REMOTESTARTSCRIPT:
		{
			int datalen = _packetdata->child("data")->child("params")->asArray().size();
			params = (uint32 *)_tmpbuffer;

			for (int i = 0; i < datalen; i++) {
				*params = _packetdata->child("data")->child("params")->asArray()[i]->asIntegerNumber();
				params++;
			}

			_vm->runScript(_vm->VAR(_vm->VAR_REMOTE_START_SCRIPT), 1, 0, (int *)_tmpbuffer);
		}
		break;

	case PACKETTYPE_REMOTESTARTSCRIPTRETURN:
		{
			int datalen = _packetdata->child("data")->child("params")->asArray().size();
			params = (uint32 *)_tmpbuffer;

			for (int i = 0; i < datalen; i++) {
				*params = _packetdata->child("data")->child("params")->asArray()[i]->asIntegerNumber();
				params++;
			}

			_vm->runScript(_vm->VAR(_vm->VAR_REMOTE_START_SCRIPT), 1, 0, (int *)_tmpbuffer);
			int result = _vm->pop();

			Common::String res = Common::String::format("\"result\": %d, \"callid\": %d", result,
					(int)_packetdata->child("data")->child("callid")->asIntegerNumber());

			remoteSendData(PN_SENDTYPE_INDIVIDUAL, from, PACKETTYPE_REMOTESTARTSCRIPTRESULT, res);
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

			int dim1start = _packetdata->child("data")->child("dim1start")->asIntegerNumber();
			int dim1end   = _packetdata->child("data")->child("dim1end")->asIntegerNumber();
			int dim2start = _packetdata->child("data")->child("dim2start")->asIntegerNumber();
			int dim2end   = _packetdata->child("data")->child("dim2end")->asIntegerNumber();
			int atype     = _packetdata->child("data")->child("type")->asIntegerNumber();

			byte *data = _vm->defineArray(0, atype, dim2start, dim2end, dim1start, dim1end, true, &newArray);

			int32 size = (dim1end - dim1start + 1) * (dim2end - dim2start + 1);

			int32 value;

			for (int i = 0; i < size; i++) {
				value = _packetdata->child("data")->child("data")->asArray()[i]->asIntegerNumber();

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

	return true;
}

void Net::remoteReceiveDataCallback(Common::JSONValue *response) {
	_packetdata = new Common::JSONValue(*response);

	if (_packetdata->child("size")->asIntegerNumber() != 0)
		debug(1, "remoteReceiveData: Got: '%s'", response->stringify().c_str());
}

void Net::doNetworkOnceAFrame(int msecs) {
	if (!_enet || !_sessionHost || _myUserId == -1)
		return;

	remoteReceiveData(msecs);

	if (_broadcastSocket)
		serviceBroadcast();
}

} // End of namespace Scumm
