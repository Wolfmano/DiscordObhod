#include <algorithm>
#include <chrono>
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

enum class Mode {
    Bypass,
    Log
};

struct Config {
    Mode mode = Mode::Bypass;
    UINT splitAt = 1;
    bool verbose = false;
    bool help = false;
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
        << "DiscordMiniBypass\n\n"
        << "Usage:\n"
        << "  DiscordMiniBypass.exe [--mode bypass|log] [--split N] [--verbose]\n\n"
        << "Options:\n"
        << "  --mode bypass   Intercept outbound TCP/443 and split TLS ClientHello (default)\n"
        << "  --mode log      Sniff Discord-like TCP/UDP traffic without changing packets\n"
        << "  --split N       TCP payload split point for ClientHello, 1..512 (default: 1)\n"
        << "  --verbose       Print passed and split packets\n";
}

bool parseArgs(int argc, char* argv[], Config& config) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            config.help = true;
            return false;
        }

        if (arg == "--verbose" || arg == "-v") {
            config.verbose = true;
            continue;
        }

        if (arg == "--mode" && i + 1 < argc) {
            std::string value = argv[++i];
            if (value == "bypass") {
                config.mode = Mode::Bypass;
            } else if (value == "log") {
                config.mode = Mode::Log;
            } else {
                std::cerr << "Unknown mode: " << value << "\n";
                return false;
            }
            continue;
        }

        if (arg == "--split" && i + 1 < argc) {
            int value = std::atoi(argv[++i]);
            if (value < 1 || value > 512) {
                std::cerr << "--split must be in range 1..512\n";
                return false;
            }
            config.splitAt = static_cast<UINT>(value);
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
    UINT splitAt
) {
    if (parsed.payload == nullptr || parsed.tcpHeader == nullptr || parsed.payloadLength <= splitAt) {
        return false;
    }

    const auto payloadOffset = static_cast<UINT>(
        static_cast<char*>(parsed.payload) - packet
    );
    const UINT firstLength = payloadOffset + splitAt;
    const UINT secondPayloadLength = parsed.payloadLength - splitAt;
    const UINT secondLength = payloadOffset + secondPayloadLength;

    std::vector<char> first(packet, packet + firstLength);
    std::vector<char> second(packet, packet + payloadOffset);
    second.resize(secondLength);
    std::memcpy(second.data() + payloadOffset, static_cast<char*>(parsed.payload) + splitAt, secondPayloadLength);

    ParsedPacket secondParsed{};
    if (!parsePacket(second.data(), secondLength, secondParsed) || secondParsed.tcpHeader == nullptr) {
        return false;
    }

    const UINT32 originalSeq = ntohl(parsed.tcpHeader->SeqNum);
    secondParsed.tcpHeader->SeqNum = htonl(originalSeq + splitAt);

    return sendPacket(handle, first.data(), firstLength, address) &&
           sendPacket(handle, second.data(), secondLength, address);
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

    std::ofstream logFile("packets.csv", std::ios::app);
    if (logFile.is_open()) {
        logFile << "time,action,direction,protocol,source_ip,source_port,destination_ip,destination_port,payload_length\n";
    }

    std::cout << "DiscordMiniBypass started in bypass mode\n";
    std::cout << "Strategy: split outbound TLS ClientHello on TCP/443 at byte " << config.splitAt << "\n";
    std::cout << "Press Ctrl+C to stop.\n\n";

    char packet[0xFFFF];

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

        const bool shouldSplit = isTlsClientHello(parsed) && parsed.payloadLength > config.splitAt;
        if (shouldSplit && splitTcpPayload(handle, packet, packetLength, address, parsed, config.splitAt)) {
            if (config.verbose) {
                logPacket(logFile, address, parsed, "SPLIT");
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

    const int result = config.mode == Mode::Log
        ? runLogMode()
        : runBypassMode(config);

    WSACleanup();
    return result;
}
