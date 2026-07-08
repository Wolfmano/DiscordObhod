#include <algorithm>
#include <chrono>
#include <cctype>
#include <climits>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <windivert.h>

enum class SplitMode {
    Fixed,
    Sni
};

struct Config {
    SplitMode splitMode = SplitMode::Sni;
    UINT splitAt = 1;
    UINT fakeTtl = 3;
    UINT fakeTtlMax = 6;
    bool verbose = false;
    bool help = false;
    bool debug = false;
    bool disorder = true;
    bool fake = true;
    std::string fakeHost = "www.microsoft.com";
};

struct TlsSniInfo {
    std::string host;
    UINT hostOffset = 0;
    UINT hostLength = 0;
};

struct ParsedPacket {
    PWINDIVERT_IPHDR ipHeader = nullptr;
    PWINDIVERT_IPV6HDR ipv6Header = nullptr;
    UINT8 protocol = 0;
    PWINDIVERT_TCPHDR tcpHeader = nullptr;
    PWINDIVERT_UDPHDR udpHeader = nullptr;
    PVOID payload = nullptr;
    UINT payloadLength = 0;
};

std::string getTimeString() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);

    std::tm localTime{};
    std::tm* tempTime = std::localtime(&time);

    if (tempTime != nullptr) {
        localTime = *tempTime;
    }

    std::ostringstream out;
    out << std::put_time(&localTime, "%Y-%m-%d %H:%M:%S");
    return out.str();
}

std::string ipv4ToString(UINT32 address) {
    char buffer[INET_ADDRSTRLEN]{};

    if (inet_ntop(AF_INET, &address, buffer, sizeof(buffer)) == nullptr) {
        return "unknown";
    }

    return buffer;
}

std::string ipv6ToString(const UINT32 address[4]) {
    char buffer[INET6_ADDRSTRLEN]{};

    if (inet_ntop(AF_INET6, address, buffer, sizeof(buffer)) == nullptr) {
        return "unknown";
    }

    return buffer;
}

void printUsage() {
    std::cout
        << "DiscordObhod\n\n"
        << "Usage:\n"
        << "  DiscordMiniBypass.exe\n"
        << "  DiscordMiniBypass.exe --debug\n\n"
        << "Options:\n"
        << "  --debug       Print detailed packet/desync logs\n"
        << "  --help        Show this help\n";
}

bool parseArgs(int argc, char* argv[], Config& config) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            config.help = true;
            return false;
        }

        if (arg == "--debug" || arg == "--verbose" || arg == "-v") {
            config.debug = true;
            config.verbose = true;
            continue;
        }

        std::cerr << "Unknown option: " << arg << "\n";
        printUsage();
        return false;
    }

    return true;
}

bool parsePacket(char* packet, UINT packetLength, ParsedPacket& parsed) {
    PWINDIVERT_ICMPHDR icmpHeader = nullptr;
    PWINDIVERT_ICMPV6HDR icmpv6Header = nullptr;

    return WinDivertHelperParsePacket(
        packet,
        packetLength,
        &parsed.ipHeader,
        &parsed.ipv6Header,
        &parsed.protocol,
        &icmpHeader,
        &icmpv6Header,
        &parsed.tcpHeader,
        &parsed.udpHeader,
        &parsed.payload,
        &parsed.payloadLength,
        nullptr,
        nullptr
    ) != FALSE;
}

bool isTlsClientHello(const ParsedPacket& parsed) {
    if (parsed.tcpHeader == nullptr || parsed.payload == nullptr || parsed.payloadLength < 6) {
        return false;
    }

    const auto* data = static_cast<const uint8_t*>(parsed.payload);
    const uint16_t tlsLength = static_cast<uint16_t>((data[3] << 8) | data[4]);

    return data[0] == 0x16 &&
           data[1] == 0x03 &&
           data[5] == 0x01 &&
           static_cast<UINT>(tlsLength) + 5 <= parsed.payloadLength;
}

std::string toLowerAscii(std::string value) {
    for (char& ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return value;
}

bool parseTlsSniInfo(const ParsedPacket& parsed, TlsSniInfo& info) {
    if (!isTlsClientHello(parsed)) {
        return false;
    }

    const auto* data = static_cast<const uint8_t*>(parsed.payload);
    const UINT len = parsed.payloadLength;
    UINT offset = 9;

    if (offset + 2 + 32 + 1 > len) {
        return false;
    }

    offset += 2;   // client_version
    offset += 32;  // random

    const UINT sessionIdLength = data[offset++];
    if (offset + sessionIdLength + 2 > len) {
        return false;
    }
    offset += sessionIdLength;

    const UINT cipherSuitesLength = static_cast<UINT>((data[offset] << 8) | data[offset + 1]);
    offset += 2;
    if (offset + cipherSuitesLength + 1 > len) {
        return false;
    }
    offset += cipherSuitesLength;

    const UINT compressionMethodsLength = data[offset++];
    if (offset + compressionMethodsLength + 2 > len) {
        return false;
    }
    offset += compressionMethodsLength;

    const UINT extensionsLength = static_cast<UINT>((data[offset] << 8) | data[offset + 1]);
    offset += 2;
    if (offset + extensionsLength > len) {
        return false;
    }

    const UINT extensionsEnd = offset + extensionsLength;
    while (offset + 4 <= extensionsEnd) {
        const UINT extensionType = static_cast<UINT>((data[offset] << 8) | data[offset + 1]);
        const UINT extensionLength = static_cast<UINT>((data[offset + 2] << 8) | data[offset + 3]);
        offset += 4;

        if (offset + extensionLength > extensionsEnd) {
            return false;
        }

        if (extensionType == 0x0000) {
            UINT nameOffset = offset;
            if (nameOffset + 2 > offset + extensionLength) {
                return false;
            }

            const UINT serverNameListLength = static_cast<UINT>((data[nameOffset] << 8) | data[nameOffset + 1]);
            nameOffset += 2;
            const UINT serverNameListEnd = nameOffset + serverNameListLength;

            if (serverNameListEnd > offset + extensionLength) {
                return false;
            }

            while (nameOffset + 3 <= serverNameListEnd) {
                const UINT nameType = data[nameOffset++];
                const UINT hostLength = static_cast<UINT>((data[nameOffset] << 8) | data[nameOffset + 1]);
                nameOffset += 2;

                if (nameOffset + hostLength > serverNameListEnd) {
                    return false;
                }

                if (nameType == 0 && hostLength > 0) {
                    info.host.assign(
                        reinterpret_cast<const char*>(data + nameOffset),
                        reinterpret_cast<const char*>(data + nameOffset + hostLength)
                    );
                    info.host = toLowerAscii(info.host);
                    info.hostOffset = nameOffset;
                    info.hostLength = hostLength;
                    return true;
                }

                nameOffset += hostLength;
            }
        }

        offset += extensionLength;
    }

    return false;
}

bool parseTlsSni(const ParsedPacket& parsed, std::string& sni) {
    TlsSniInfo info{};
    if (!parseTlsSniInfo(parsed, info)) {
        return false;
    }

    sni = info.host;
    return true;
}

bool isDiscordHost(const std::string& host) {
    const std::string lowerHost = toLowerAscii(host);
    const char* domains[] = {
        "discord.com",
        "discord.gg",
        "discord.media",
        "discordapp.com",
        "discordapp.net",
        "discordcdn.com"
    };

    for (const char* domain : domains) {
        const std::string suffix = domain;
        if (lowerHost == suffix) {
            return true;
        }
        if (lowerHost.length() > suffix.length() &&
            lowerHost.compare(lowerHost.length() - suffix.length(), suffix.length(), suffix) == 0 &&
            lowerHost[lowerHost.length() - suffix.length() - 1] == '.') {
            return true;
        }
    }

    return false;
}

bool shouldSplitClientHello(const ParsedPacket& parsed, const Config& config, std::string& sni, UINT& splitAt) {
    if (!isTlsClientHello(parsed)) {
        return false;
    }

    TlsSniInfo info{};
    const bool hasSni = parseTlsSniInfo(parsed, info);
    if (hasSni) {
        sni = info.host;
    }

    if (!hasSni || !isDiscordHost(info.host)) {
        return false;
    }

    splitAt = config.splitAt;
    if (config.splitMode == SplitMode::Sni) {
        if (!hasSni || info.hostLength < 2) {
            return false;
        }

        splitAt = info.hostOffset + std::max<UINT>(1, info.hostLength / 2);
    }

    if (splitAt == 0 || parsed.payloadLength <= splitAt) {
        return false;
    }

    return true;
}

void updateLengths(char* packet, UINT packetLength) {
    ParsedPacket parsed{};
    if (!parsePacket(packet, packetLength, parsed)) {
        return;
    }

    if (parsed.ipHeader != nullptr) {
        parsed.ipHeader->Length = htons(static_cast<uint16_t>(packetLength));
        parsed.ipHeader->Checksum = 0;
    }

    if (parsed.ipv6Header != nullptr) {
        parsed.ipv6Header->Length = htons(static_cast<uint16_t>(packetLength - sizeof(WINDIVERT_IPV6HDR)));
    }

    if (parsed.tcpHeader != nullptr) {
        parsed.tcpHeader->Checksum = 0;
    }
}

bool sendPacket(HANDLE handle, char* packet, UINT packetLength, WINDIVERT_ADDRESS& address) {
    updateLengths(packet, packetLength);
    WinDivertHelperCalcChecksums(packet, packetLength, &address, 0);

    UINT sendLength = 0;
    return WinDivertSend(handle, packet, packetLength, &sendLength, &address) != FALSE &&
           sendLength == packetLength;
}

bool prepareTcpSegment(
    char* packet,
    UINT packetLength,
    UINT ipOffset,
    UINT ipv6Offset,
    UINT tcpOffset
) {
    if (tcpOffset + sizeof(WINDIVERT_TCPHDR) > packetLength) {
        return false;
    }

    if (ipOffset != UINT_MAX) {
        if (ipOffset + sizeof(WINDIVERT_IPHDR) > packetLength) {
            return false;
        }

        auto* ipHeader = reinterpret_cast<PWINDIVERT_IPHDR>(packet + ipOffset);
        ipHeader->Length = htons(static_cast<uint16_t>(packetLength - ipOffset));
        ipHeader->Checksum = 0;
    }

    if (ipv6Offset != UINT_MAX) {
        if (ipv6Offset + sizeof(WINDIVERT_IPV6HDR) > packetLength) {
            return false;
        }

        auto* ipv6Header = reinterpret_cast<PWINDIVERT_IPV6HDR>(packet + ipv6Offset);
        ipv6Header->Length = htons(static_cast<uint16_t>(packetLength - ipv6Offset - sizeof(WINDIVERT_IPV6HDR)));
    }

    auto* tcpHeader = reinterpret_cast<PWINDIVERT_TCPHDR>(packet + tcpOffset);
    tcpHeader->Checksum = 0;

    return true;
}

bool sendPreparedTcpSegment(
    HANDLE handle,
    char* packet,
    UINT packetLength,
    WINDIVERT_ADDRESS& address,
    UINT ipOffset,
    UINT ipv6Offset,
    UINT tcpOffset
) {
    if (!prepareTcpSegment(packet, packetLength, ipOffset, ipv6Offset, tcpOffset)) {
        return false;
    }

    WinDivertHelperCalcChecksums(packet, packetLength, &address, 0);

    UINT sendLength = 0;
    return WinDivertSend(handle, packet, packetLength, &sendLength, &address) != FALSE &&
           sendLength == packetLength;
}

std::string fitHostToLength(const std::string& host, UINT length) {
    std::string value = toLowerAscii(host);
    if (value.empty()) {
        value = "www.microsoft.com";
    }

    if (value.length() > length) {
        value.resize(length);
    }

    while (value.length() < length) {
        value.push_back('a');
    }

    return value;
}

bool overwriteTlsSniHost(char* packet, UINT packetLength, const std::string& host) {
    ParsedPacket parsed{};
    if (!parsePacket(packet, packetLength, parsed)) {
        return false;
    }

    TlsSniInfo info{};
    if (!parseTlsSniInfo(parsed, info) || info.hostLength == 0) {
        return false;
    }

    const std::string replacement = fitHostToLength(host, info.hostLength);
    auto* payload = static_cast<char*>(parsed.payload);
    std::memcpy(payload + info.hostOffset, replacement.data(), info.hostLength);
    return true;
}

bool sendFakeClientHello(
    HANDLE handle,
    char* packet,
    UINT packetLength,
    WINDIVERT_ADDRESS& address,
    const std::string& fakeHost,
    UINT fakeTtl
) {
    std::vector<char> fake(packet, packet + packetLength);

    if (!overwriteTlsSniHost(fake.data(), packetLength, fakeHost)) {
        return false;
    }

    ParsedPacket fakeParsed{};
    if (!parsePacket(fake.data(), packetLength, fakeParsed)) {
        return false;
    }

    if (fakeParsed.ipHeader != nullptr) {
        fakeParsed.ipHeader->TTL = static_cast<UINT8>(fakeTtl);
    }
    if (fakeParsed.ipv6Header != nullptr) {
        fakeParsed.ipv6Header->HopLimit = static_cast<UINT8>(fakeTtl);
    }

    updateLengths(fake.data(), packetLength);
    WinDivertHelperCalcChecksums(fake.data(), packetLength, &address, 0);

    ParsedPacket checksumParsed{};
    if (!parsePacket(fake.data(), packetLength, checksumParsed) || checksumParsed.tcpHeader == nullptr) {
        return false;
    }

    checksumParsed.tcpHeader->Checksum ^= 0xFFFF;

    UINT sendLength = 0;
    return WinDivertSend(handle, fake.data(), packetLength, &sendLength, &address) != FALSE &&
           sendLength == packetLength;
}

bool sendFakeClientHelloRange(
    HANDLE handle,
    char* packet,
    UINT packetLength,
    WINDIVERT_ADDRESS& address,
    const Config& config
) {
    bool sentAny = false;

    for (UINT ttl = config.fakeTtl; ttl <= config.fakeTtlMax; ++ttl) {
        if (sendFakeClientHello(handle, packet, packetLength, address, config.fakeHost, ttl)) {
            sentAny = true;
            if (config.verbose) {
                std::cout << "FAKE ttl=" << ttl << " host=" << config.fakeHost << " badsum=1\n";
            }
        } else if (config.verbose) {
            std::cout << "FAKE_FAILED ttl=" << ttl << "\n";
        }
    }

    return sentAny;
}

void logPacket(
    std::ofstream& logFile,
    const WINDIVERT_ADDRESS& address,
    const ParsedPacket& parsed,
    const std::string& action
) {
    std::string direction = address.Outbound ? "OUT" : "IN";
    std::string protocol = "UNKNOWN";
    std::string sourceIp;
    std::string destinationIp;

    if (parsed.ipHeader != nullptr) {
        sourceIp = ipv4ToString(parsed.ipHeader->SrcAddr);
        destinationIp = ipv4ToString(parsed.ipHeader->DstAddr);
    } else if (parsed.ipv6Header != nullptr) {
        sourceIp = ipv6ToString(parsed.ipv6Header->SrcAddr);
        destinationIp = ipv6ToString(parsed.ipv6Header->DstAddr);
    } else {
        return;
    }

    UINT16 sourcePort = 0;
    UINT16 destinationPort = 0;

    if (parsed.tcpHeader != nullptr) {
        protocol = "TCP";
        sourcePort = ntohs(parsed.tcpHeader->SrcPort);
        destinationPort = ntohs(parsed.tcpHeader->DstPort);
    } else if (parsed.udpHeader != nullptr) {
        protocol = "UDP";
        sourcePort = ntohs(parsed.udpHeader->SrcPort);
        destinationPort = ntohs(parsed.udpHeader->DstPort);
    } else {
        return;
    }

    const std::string time = getTimeString();

    std::cout
        << "[" << time << "] "
        << action << " "
        << direction << " "
        << protocol << " "
        << sourceIp << ":" << sourcePort
        << " -> "
        << destinationIp << ":" << destinationPort
        << " payload=" << parsed.payloadLength
        << "\n";

    if (logFile.is_open()) {
        logFile
            << time << ","
            << action << ","
            << direction << ","
            << protocol << ","
            << sourceIp << ","
            << sourcePort << ","
            << destinationIp << ","
            << destinationPort << ","
            << parsed.payloadLength
            << "\n";
    }
}

bool splitTcpPayload(
    HANDLE handle,
    char* packet,
    UINT /* packetLength */,
    WINDIVERT_ADDRESS& address,
    const ParsedPacket& parsed,
    UINT splitAt,
    bool disorder
) {
    if (parsed.payload == nullptr || parsed.tcpHeader == nullptr || parsed.payloadLength <= splitAt) {
        return false;
    }

    const auto payloadOffset = static_cast<UINT>(
        static_cast<char*>(parsed.payload) - packet
    );
    const UINT tcpOffset = static_cast<UINT>(
        reinterpret_cast<char*>(parsed.tcpHeader) - packet
    );
    const UINT ipOffset = parsed.ipHeader != nullptr
        ? static_cast<UINT>(reinterpret_cast<char*>(parsed.ipHeader) - packet)
        : UINT_MAX;
    const UINT ipv6Offset = parsed.ipv6Header != nullptr
        ? static_cast<UINT>(reinterpret_cast<char*>(parsed.ipv6Header) - packet)
        : UINT_MAX;

    const UINT firstLength = payloadOffset + splitAt;
    const UINT secondPayloadLength = parsed.payloadLength - splitAt;
    const UINT secondLength = payloadOffset + secondPayloadLength;

    std::vector<char> first(packet, packet + firstLength);
    std::vector<char> second(packet, packet + payloadOffset);
    second.resize(secondLength);
    std::memcpy(second.data() + payloadOffset, static_cast<char*>(parsed.payload) + splitAt, secondPayloadLength);

    if (tcpOffset + sizeof(WINDIVERT_TCPHDR) > secondLength) {
        return false;
    }

    const UINT32 originalSeq = ntohl(parsed.tcpHeader->SeqNum);
    auto* secondTcpHeader = reinterpret_cast<PWINDIVERT_TCPHDR>(second.data() + tcpOffset);
    secondTcpHeader->SeqNum = htonl(originalSeq + splitAt);

    if (disorder) {
        if (!sendPreparedTcpSegment(handle, second.data(), secondLength, address, ipOffset, ipv6Offset, tcpOffset)) {
            return false;
        }

        if (!sendPreparedTcpSegment(handle, first.data(), firstLength, address, ipOffset, ipv6Offset, tcpOffset)) {
            std::cerr << "First split segment failed after disorder send; TCP connection may need retry\n";
        }

        return true;
    }

    if (!sendPreparedTcpSegment(handle, first.data(), firstLength, address, ipOffset, ipv6Offset, tcpOffset)) {
        return false;
    }

    if (!sendPreparedTcpSegment(handle, second.data(), secondLength, address, ipOffset, ipv6Offset, tcpOffset)) {
        std::cerr << "Second split segment failed; TCP connection may need retry\n";
        return true;
    }

    return true;
}

int runLogMode() {
    const char* filter =
        "(ip or ipv6) and "
        "("
        "  (tcp and (tcp.SrcPort == 443 or tcp.DstPort == 443)) or "
        "  (udp and (udp.SrcPort == 443 or udp.DstPort == 443)) or "
        "  (udp and (udp.SrcPort >= 50000 and udp.SrcPort <= 65535)) or "
        "  (udp and (udp.DstPort >= 50000 and udp.DstPort <= 65535))"
        ")";

    HANDLE handle = WinDivertOpen(
        filter,
        WINDIVERT_LAYER_NETWORK,
        0,
        WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY
    );

    if (handle == INVALID_HANDLE_VALUE) {
        std::cerr << "WinDivertOpen failed. Error code: " << GetLastError() << "\n";
        std::cerr << "Run as Administrator and check WinDivert files.\n";
        return 1;
    }

    std::ofstream logFile("packets.csv", std::ios::app);
    if (logFile.is_open()) {
        logFile << "time,action,direction,protocol,source_ip,source_port,destination_ip,destination_port,payload_length\n";
    }

    std::cout << "DiscordMiniBypass started in log mode\n";
    std::cout << "Packets are NOT modified. Press Ctrl+C to stop.\n\n";

    char packet[0xFFFF];

    while (true) {
        WINDIVERT_ADDRESS address{};
        UINT packetLength = 0;

        if (!WinDivertRecv(handle, packet, sizeof(packet), &packetLength, &address)) {
            std::cerr << "WinDivertRecv failed. Error code: " << GetLastError() << "\n";
            continue;
        }

        ParsedPacket parsed{};
        if (parsePacket(packet, packetLength, parsed)) {
            logPacket(logFile, address, parsed, "LOG");
        }
    }
}

int runBypassMode(const Config& config) {
    const char* filter =
        "outbound and !impostor and (ip or ipv6) and tcp and tcp.DstPort == 443";

    HANDLE handle = WinDivertOpen(
        filter,
        WINDIVERT_LAYER_NETWORK,
        0,
        0
    );

    if (handle == INVALID_HANDLE_VALUE) {
        std::cerr << "WinDivertOpen failed. Error code: " << GetLastError() << "\n";
        std::cerr << "Run as Administrator and check WinDivert files.\n";
        return 1;
    }

    WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LENGTH, 8192);
    WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, 2048);

    std::ofstream logFile;
    if (config.debug) {
        logFile.open("packets.csv", std::ios::app);
    }
    if (logFile.is_open()) {
        logFile << "time,action,direction,protocol,source_ip,source_port,destination_ip,destination_port,payload_length\n";
    }

    std::cout << "DiscordObhod started\n";
    std::cout << "Profile: auto Discord HTTPS desync\n";
    std::cout << "Desync: fake badsum ClientHello ttl=" << config.fakeTtl
              << ".." << config.fakeTtlMax
              << ", disorder split inside SNI\n";
    if (config.debug) {
        std::cout << "Debug: enabled, logs are written to packets.csv\n";
    }
    std::cout << "Press Ctrl+C to stop.\n\n";

    char packet[0xFFFF];
    std::string lastSni;
    UINT sameSniRetries = 0;
    bool warnedAboutRetries = false;

    while (true) {
        WINDIVERT_ADDRESS address{};
        UINT packetLength = 0;

        if (!WinDivertRecv(handle, packet, sizeof(packet), &packetLength, &address)) {
            std::cerr << "WinDivertRecv failed. Error code: " << GetLastError() << "\n";
            continue;
        }

        ParsedPacket parsed{};
        if (!parsePacket(packet, packetLength, parsed)) {
            continue;
        }

        std::string sni;
        UINT splitAt = config.splitAt;
        const bool shouldSplit = shouldSplitClientHello(parsed, config, sni, splitAt);
        if (shouldSplit && config.fake) {
            sendFakeClientHelloRange(handle, packet, packetLength, address, config);
        }

        if (shouldSplit && splitTcpPayload(handle, packet, packetLength, address, parsed, splitAt, config.disorder)) {
            if (config.verbose) {
                if (!sni.empty()) {
                    std::cout << "SNI: " << sni << " splitAt=" << splitAt << "\n";
                }
                logPacket(logFile, address, parsed, config.disorder ? "DISORDER_SPLIT" : "SPLIT");
            }

            if (!sni.empty()) {
                if (sni == lastSni) {
                    ++sameSniRetries;
                } else {
                    lastSni = sni;
                    sameSniRetries = 1;
                    warnedAboutRetries = false;
                }

                if (!warnedAboutRetries && sameSniRetries >= 8) {
                    std::cout
                        << "Warning: repeated retries for " << sni << ". "
                        << "Desync is being applied, but the connection still does not complete. "
                        << "This usually means IP/DNS/server-side blocking, not just SNI DPI.\n";
                    warnedAboutRetries = true;
                }
            }

            continue;
        }

        if (config.verbose && shouldSplit) {
            logPacket(logFile, address, parsed, "SPLIT_FAILED_PASS");
        }

        if (!sendPacket(handle, packet, packetLength, address)) {
            std::cerr << "WinDivertSend failed. Error code: " << GetLastError() << "\n";
        } else if (config.verbose) {
            logPacket(logFile, address, parsed, "PASS");
        }
    }
}

int main(int argc, char* argv[]) {
    Config config{};
    if (!parseArgs(argc, argv, config)) {
        if (config.help) {
            printUsage();
            return 0;
        }
        return 1;
    }

    WSADATA wsaData{};
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }

    const int result = runBypassMode(config);

    WSACleanup();
    return result;
}
