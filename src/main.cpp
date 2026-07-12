#include <algorithm>
#include <chrono>
#include <cctype>
#include <climits>
#include <cwchar>
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
    UINT fakeTtlMax = 10;
    bool verbose = false;
    bool help = false;
    bool debug = false;
    bool launchDiscord = true;
    bool dropHttpsResets = true;
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

struct ProtectedFlow {
    bool ipv6 = false;
    UINT32 localAddr[4]{};
    UINT32 remoteAddr[4]{};
    UINT16 localPort = 0;
    UINT16 remotePort = 0;
    std::string sni;
    std::chrono::steady_clock::time_point expiresAt{};
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
        << "  --no-launch   Do not auto-launch installed Discord.exe\n"
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

        if (arg == "--no-launch") {
            config.launchDiscord = false;
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

void copyAddress(const ParsedPacket& parsed, bool local, bool outbound, UINT32 out[4]) {
    out[0] = 0;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;

    if (parsed.ipHeader != nullptr) {
        if (outbound) {
            out[0] = local ? parsed.ipHeader->SrcAddr : parsed.ipHeader->DstAddr;
        } else {
            out[0] = local ? parsed.ipHeader->DstAddr : parsed.ipHeader->SrcAddr;
        }
        return;
    }

    if (parsed.ipv6Header != nullptr) {
        const UINT32* source = nullptr;
        if (outbound) {
            source = local ? parsed.ipv6Header->SrcAddr : parsed.ipv6Header->DstAddr;
        } else {
            source = local ? parsed.ipv6Header->DstAddr : parsed.ipv6Header->SrcAddr;
        }

        if (source != nullptr) {
            std::memcpy(out, source, sizeof(UINT32) * 4);
        }
    }
}

bool sameAddress(const UINT32 left[4], const UINT32 right[4]) {
    return std::memcmp(left, right, sizeof(UINT32) * 4) == 0;
}

void pruneProtectedFlows(std::vector<ProtectedFlow>& flows) {
    const auto now = std::chrono::steady_clock::now();
    flows.erase(
        std::remove_if(
            flows.begin(),
            flows.end(),
            [now](const ProtectedFlow& flow) {
                return flow.expiresAt <= now;
            }
        ),
        flows.end()
    );
}

void rememberProtectedFlow(
    std::vector<ProtectedFlow>& flows,
    const ParsedPacket& parsed,
    const std::string& sni
) {
    if (parsed.tcpHeader == nullptr || (parsed.ipHeader == nullptr && parsed.ipv6Header == nullptr)) {
        return;
    }

    ProtectedFlow flow{};
    flow.ipv6 = parsed.ipv6Header != nullptr;
    copyAddress(parsed, true, true, flow.localAddr);
    copyAddress(parsed, false, true, flow.remoteAddr);
    flow.localPort = ntohs(parsed.tcpHeader->SrcPort);
    flow.remotePort = ntohs(parsed.tcpHeader->DstPort);
    flow.sni = sni;
    flow.expiresAt = std::chrono::steady_clock::now() + std::chrono::minutes(3);

    for (ProtectedFlow& existing : flows) {
        if (existing.ipv6 == flow.ipv6 &&
            existing.localPort == flow.localPort &&
            existing.remotePort == flow.remotePort &&
            sameAddress(existing.localAddr, flow.localAddr) &&
            sameAddress(existing.remoteAddr, flow.remoteAddr)) {
            existing.expiresAt = flow.expiresAt;
            existing.sni = flow.sni;
            return;
        }
    }

    flows.push_back(flow);
}

bool isProtectedInboundReset(
    const std::vector<ProtectedFlow>& flows,
    const ParsedPacket& parsed,
    std::string& sni
) {
    if (parsed.tcpHeader == nullptr ||
        parsed.tcpHeader->Rst == 0 ||
        (parsed.ipHeader == nullptr && parsed.ipv6Header == nullptr)) {
        return false;
    }

    const bool ipv6 = parsed.ipv6Header != nullptr;
    UINT32 localAddr[4]{};
    UINT32 remoteAddr[4]{};
    copyAddress(parsed, true, false, localAddr);
    copyAddress(parsed, false, false, remoteAddr);

    const UINT16 localPort = ntohs(parsed.tcpHeader->DstPort);
    const UINT16 remotePort = ntohs(parsed.tcpHeader->SrcPort);

    for (const ProtectedFlow& flow : flows) {
        if (flow.ipv6 == ipv6 &&
            flow.localPort == localPort &&
            flow.remotePort == remotePort &&
            sameAddress(flow.localAddr, localAddr) &&
            sameAddress(flow.remoteAddr, remoteAddr)) {
            sni = flow.sni;
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

bool sendFakeClientHelloVariant(
    HANDLE handle,
    char* packet,
    UINT packetLength,
    WINDIVERT_ADDRESS& address,
    const std::string& fakeHost,
    UINT fakeTtl,
    bool badChecksum,
    INT32 seqDelta
) {
    std::vector<char> fake(packet, packet + packetLength);

    if (!overwriteTlsSniHost(fake.data(), packetLength, fakeHost)) {
        return false;
    }

    ParsedPacket fakeParsed{};
    if (!parsePacket(fake.data(), packetLength, fakeParsed)) {
        return false;
    }

    if (fakeParsed.tcpHeader == nullptr) {
        return false;
    }

    if (fakeParsed.ipHeader != nullptr) {
        fakeParsed.ipHeader->TTL = static_cast<UINT8>(fakeTtl);
    }
    if (fakeParsed.ipv6Header != nullptr) {
        fakeParsed.ipv6Header->HopLimit = static_cast<UINT8>(fakeTtl);
    }

    if (seqDelta != 0) {
        const UINT32 originalSeq = ntohl(fakeParsed.tcpHeader->SeqNum);
        fakeParsed.tcpHeader->SeqNum = htonl(static_cast<UINT32>(originalSeq + seqDelta));
    }

    updateLengths(fake.data(), packetLength);
    WinDivertHelperCalcChecksums(fake.data(), packetLength, &address, 0);

    if (badChecksum) {
        ParsedPacket checksumParsed{};
        if (!parsePacket(fake.data(), packetLength, checksumParsed) || checksumParsed.tcpHeader == nullptr) {
            return false;
        }

        checksumParsed.tcpHeader->Checksum ^= 0xFFFF;
    }

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
        if (sendFakeClientHelloVariant(handle, packet, packetLength, address, config.fakeHost, ttl, false, 0)) {
            sentAny = true;
            if (config.verbose) {
                std::cout << "FAKE_TTL ttl=" << ttl << " host=" << config.fakeHost << "\n";
            }
        } else if (config.verbose) {
            std::cout << "FAKE_TTL_FAILED ttl=" << ttl << "\n";
        }
    }

    if (sendFakeClientHelloVariant(handle, packet, packetLength, address, config.fakeHost, 64, true, 0)) {
        sentAny = true;
        if (config.verbose) {
            std::cout << "FAKE_BADSUM ttl=64 host=" << config.fakeHost << "\n";
        }
    } else if (config.verbose) {
        std::cout << "FAKE_BADSUM_FAILED\n";
    }

    if (sendFakeClientHelloVariant(handle, packet, packetLength, address, config.fakeHost, 64, false, -10000)) {
        sentAny = true;
        if (config.verbose) {
            std::cout << "FAKE_BADSEQ ttl=64 delta=-10000 host=" << config.fakeHost << "\n";
        }
    } else if (config.verbose) {
        std::cout << "FAKE_BADSEQ_FAILED\n";
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

bool fileExists(const std::wstring& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
           (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

std::wstring getEnvVar(const wchar_t* name) {
    const DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
    if (size == 0) {
        return L"";
    }

    std::wstring value(size, L'\0');
    const DWORD written = GetEnvironmentVariableW(name, &value[0], size);
    if (written == 0 || written >= size) {
        return L"";
    }

    value.resize(written);
    return value;
}

std::wstring findLatestDiscordExeIn(const std::wstring& root) {
    const std::wstring searchPattern = root + L"\\app-*";
    WIN32_FIND_DATAW findData{};
    HANDLE findHandle = FindFirstFileW(searchPattern.c_str(), &findData);

    if (findHandle == INVALID_HANDLE_VALUE) {
        return L"";
    }

    std::wstring bestPath;
    FILETIME bestWriteTime{};

    do {
        if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            continue;
        }

        if (std::wcscmp(findData.cFileName, L".") == 0 ||
            std::wcscmp(findData.cFileName, L"..") == 0) {
            continue;
        }

        const std::wstring candidate = root + L"\\" + findData.cFileName + L"\\Discord.exe";
        if (!fileExists(candidate)) {
            continue;
        }

        if (bestPath.empty() || CompareFileTime(&findData.ftLastWriteTime, &bestWriteTime) > 0) {
            bestPath = candidate;
            bestWriteTime = findData.ftLastWriteTime;
        }
    } while (FindNextFileW(findHandle, &findData) != FALSE);

    FindClose(findHandle);
    return bestPath;
}

std::wstring findInstalledDiscordExe() {
    const std::wstring localAppData = getEnvVar(L"LOCALAPPDATA");
    if (localAppData.empty()) {
        return L"";
    }

    const wchar_t* roots[] = {
        L"Discord",
        L"DiscordCanary",
        L"DiscordPTB"
    };

    for (const wchar_t* root : roots) {
        const std::wstring exe = findLatestDiscordExeIn(localAppData + L"\\" + root);
        if (!exe.empty()) {
            return exe;
        }
    }

    return L"";
}

bool launchProcess(const std::wstring& exePath) {
    if (exePath.empty()) {
        return false;
    }

    const size_t separator = exePath.find_last_of(L"\\/");
    const std::wstring workDir = separator == std::wstring::npos
        ? L""
        : exePath.substr(0, separator);
    std::wstring commandLine = L"\"" + exePath + L"\"";

    STARTUPINFOW startupInfo{};
    startupInfo.cb = sizeof(startupInfo);
    PROCESS_INFORMATION processInfo{};

    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');

    const BOOL created = CreateProcessW(
        exePath.c_str(),
        mutableCommandLine.data(),
        nullptr,
        nullptr,
        FALSE,
        0,
        nullptr,
        workDir.empty() ? nullptr : workDir.c_str(),
        &startupInfo,
        &processInfo
    );

    if (!created) {
        return false;
    }

    CloseHandle(processInfo.hThread);
    CloseHandle(processInfo.hProcess);
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
        "(ip or ipv6) and tcp and !impostor and "
        "("
        "  (outbound and tcp.DstPort == 443) or "
        "  (inbound and tcp.SrcPort == 443 and tcp.Rst)"
        ")";

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
    std::cout << "Desync: fake ClientHello ttl=" << config.fakeTtl
              << ".." << config.fakeTtlMax
              << ", badsum, badseq, disorder split inside SNI\n";
    std::cout << "RST guard: dropping inbound TCP resets from HTTPS servers\n";
    if (config.debug) {
        std::cout << "Debug: enabled, logs are written to packets.csv\n";
    }
    std::cout << "Press Ctrl+C to stop.\n\n";

    if (config.launchDiscord) {
        const std::wstring discordExe = findInstalledDiscordExe();
        if (!discordExe.empty()) {
            if (launchProcess(discordExe)) {
                std::wcout << L"Started Discord directly: " << discordExe << L"\n";
            } else {
                std::wcout << L"Could not start Discord directly: " << discordExe << L"\n";
                std::cout << "You can start Discord manually while this window is open.\n";
            }
        } else {
            std::cout << "Discord installation was not found in LocalAppData. Start Discord manually while this window is open.\n";
        }
    }

    char packet[0xFFFF];
    std::string lastSni;
    UINT sameSniRetries = 0;
    bool warnedAboutRetries = false;
    std::vector<ProtectedFlow> protectedFlows;
    UINT droppedResets = 0;

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

        pruneProtectedFlows(protectedFlows);

        if (!address.Outbound && parsed.tcpHeader != nullptr && parsed.tcpHeader->Rst != 0) {
            std::string resetSni;
            const bool protectedReset = isProtectedInboundReset(protectedFlows, parsed, resetSni);
            const bool httpsReset = ntohs(parsed.tcpHeader->SrcPort) == 443;

            if (protectedReset || (config.dropHttpsResets && httpsReset)) {
                ++droppedResets;
                if (config.verbose) {
                    std::cout << "DROP_RST"
                              << (protectedReset ? " protected=1" : " protected=0");
                    if (!resetSni.empty()) {
                        std::cout << " sni=" << resetSni;
                    }
                    std::cout << " count=" << droppedResets << "\n";
                    logPacket(logFile, address, parsed, "DROP_RST");
                } else if (droppedResets == 1) {
                    std::cout << "Dropping injected TCP resets for Discord flows\n";
                }
                continue;
            }

            if (config.verbose && httpsReset) {
                std::cout << "PASS_RST protected=0\n";
            }

            if (!sendPacket(handle, packet, packetLength, address)) {
                std::cerr << "WinDivertSend failed for inbound RST. Error code: " << GetLastError() << "\n";
            } else if (config.verbose) {
                logPacket(logFile, address, parsed, "PASS_RST");
            }
            continue;
        }

        std::string sni;
        UINT splitAt = config.splitAt;
        const bool shouldSplit = shouldSplitClientHello(parsed, config, sni, splitAt);
        if (shouldSplit && config.fake) {
            sendFakeClientHelloRange(handle, packet, packetLength, address, config);
        }

        if (shouldSplit && splitTcpPayload(handle, packet, packetLength, address, parsed, splitAt, config.disorder)) {
            rememberProtectedFlow(protectedFlows, parsed, sni);

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
