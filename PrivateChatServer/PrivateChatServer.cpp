// PrivateChatServer.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS


/*#include <windows.h>
#include<winsock2.h>
#include <iphlpapi.h>
#include <iostream>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <rpc.h>
#include <ntdsapi.h>
#include <tchar.h>*/
#include <iostream>
#include <windows.h>
#include <winsock2.h>
#include <mstcpip.h>
#include <ws2tcpip.h>
#include <rpc.h>
#include <ntdsapi.h>
#include <stdio.h>
#include <tchar.h>
#include <map>
#include <time.h>
#include <Wincrypt.h>
#include<list>
#include <algorithm>
#include<mutex>

#define RECV_DATA_BUF_SIZE 20000
#define CURRENT_VERSION "0.0.3"
#define SSN_STR_LEN 12

#pragma comment(lib,"Ws2_32.lib")
// link with fwpuclnt.lib for Winsock secure socket extensions
#pragma comment(lib, "fwpuclnt.lib")

// link with ntdsapi.lib for DsMakeSpn function
#pragma comment(lib, "ntdsapi.lib")

#pragma comment(lib,"Crypt32.lib")
using namespace std;
/*int
SecureTcpConnect(IN const struct sockaddr* serverAddr,
    IN ULONG serverAddrLen,
    IN const wchar_t* serverSPN,
    IN const SOCKET_SECURITY_SETTINGS* securitySettings,
    IN ULONG settingsLen)
    /**
    Routine Description:

        This routine creates a TCP client socket, securely connects to the
        specified server, sends & receives data from the server, and then closes
        the socket

    Arguments:

        serverAddr - a pointer to the sockaddr structure for the server.

        serverAddrLen - length of serverAddr in bytes

        serverSPN - a NULL-terminated string representing the SPN
                   (service principal name) of the server host computer

        securitySettings - pointer to the socket security settings that should be
                           applied to the connection

        settingsLen - length of securitySettings in bytes

    Return Value:

        Winsock error code indicating the status of the operation, or NO_ERROR if
        the operation succeeded.

    -
{
    int iResult = 0;
    int sockErr = 0;
    SOCKET sock = INVALID_SOCKET;

    WSABUF wsaBuf = { 0 };
    const char* dataBuf = "12345678";
    DWORD bytesSent = 0;
    char recvBuf[RECV_DATA_BUF_SIZE] = { 0 };

    DWORD bytesRecvd = 0;
    DWORD flags = 0;
    SOCKET_PEER_TARGET_NAME* peerTargetName = NULL;
    DWORD serverSpnStringLen = (DWORD)wcslen(serverSPN);
    DWORD peerTargetNameLen = sizeof(SOCKET_PEER_TARGET_NAME) +
        (serverSpnStringLen * sizeof(wchar_t));

    //-----------------------------------------
    // Create a TCP socket
    sock = WSASocket(serverAddr->sa_family,
        SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (sock == INVALID_SOCKET) {
        iResult = WSAGetLastError();
        wprintf(L"WSASocket returned error %ld\n", iResult);
        goto cleanup;
    }
    //-----------------------------------------
    // Turn on security for the socket.
    sockErr = WSASetSocketSecurity(sock,
        securitySettings, settingsLen, NULL, NULL);
    if (sockErr == SOCKET_ERROR) {
        iResult = WSAGetLastError();
        wprintf(L"WSASetSocketSecurity returned error %ld\n", iResult);
        goto cleanup;
    }
    //-----------------------------------------
    // Specify the server SPN
    peerTargetName = (SOCKET_PEER_TARGET_NAME*)HeapAlloc(GetProcessHeap(),
        HEAP_ZERO_MEMORY, peerTargetNameLen);
    if (!peerTargetName) {
        iResult = ERROR_NOT_ENOUGH_MEMORY;
        wprintf(L"Out of memory\n");
        goto cleanup;
    }
    // Use the security protocol as specified by the settings
    peerTargetName->SecurityProtocol = securitySettings->SecurityProtocol;
    // Specify the server SPN 
    peerTargetName->PeerTargetNameStringLen = serverSpnStringLen;
    RtlCopyMemory((BYTE*)peerTargetName->AllStrings,
        (BYTE*)serverSPN, serverSpnStringLen * sizeof(wchar_t)
    );

    sockErr = WSASetSocketPeerTargetName(sock,
        peerTargetName,
        peerTargetNameLen, NULL, NULL);
    if (sockErr == SOCKET_ERROR) {
        iResult = WSAGetLastError();
        wprintf(L"WSASetSocketPeerTargetName returned error %ld\n", iResult);
        goto cleanup;
    }
    //-----------------------------------------
    // Connect to the server
    sockErr = WSAConnect(sock,
        serverAddr, serverAddrLen, NULL, NULL, NULL, NULL);
    if (sockErr == SOCKET_ERROR) {
        iResult = WSAGetLastError();
        wprintf(L"WSAConnect returned error %ld\n", iResult);
        goto cleanup;
    }
    // At this point a secure connection must have been established.
    wprintf(L"Secure connection established to the server\n");

    //-----------------------------------------
    // Send some data securely
    wsaBuf.len = (ULONG)strlen(dataBuf);
    strcpy_s(wsaBuf.buf , sizeof(wsaBuf.buf),dataBuf);
    sockErr = WSASend(sock, &wsaBuf, 1, &bytesSent, 0, NULL, NULL);
    if (sockErr == SOCKET_ERROR) {
        iResult = WSAGetLastError();
        wprintf(L"WSASend returned error %ld\n", iResult);
        goto cleanup;
    }
    wprintf(L"Sent %d bytes of data to the server\n", bytesSent);

    //-----------------------------------------
    // Receive server's response securely
    wsaBuf.len = RECV_DATA_BUF_SIZE;
    wsaBuf.buf = recvBuf;
    sockErr = WSARecv(sock, &wsaBuf, 1, &bytesRecvd, &flags, NULL, NULL);
    if (sockErr == SOCKET_ERROR) {
        iResult = WSAGetLastError();
        wprintf(L"WSARecv returned error %ld\n", iResult);
        goto cleanup;
    }
    wprintf(L"Received %d bytes of data from the server\n", bytesRecvd);

cleanup:
    if (sock != INVALID_SOCKET) {
        //This will trigger the cleanup of all IPsec filters and policies that
        //were added for this socket. The cleanup will happen only after all
        //outstanding data has been sent out on the wire.
        closesocket(sock);
    }
    if (peerTargetName) {
        HeapFree(GetProcessHeap(), 0, peerTargetName);
    }
    return iResult;
}*/
string PORT = "27065";
bool judge(string a, string b) {
    if (a == b)
        return true;
    else {
        if (a.length() == b.length() && (a.length() / 2 != 0)) {
            string a1 = a.substr(0, a.size() / 2);
            string a2 = a.substr(a.size() / 2, a.size() / 2);
            string b1 = b.substr(0, b.size() / 2);
            string b2 = b.substr(b.size() / 2, b.size() / 2);
            return (judge(a1, b1) && judge(a2, b2)) || (judge(a1, b2) && judge(a2, b1));
        }
        else {
            return false;
        }
    }
}
HRESULT ProtectData(void** data) {
    HRESULT hr = S_OK;
    LPWSTR pSensitiveText = NULL;
    DWORD cbSensitiveText = 0;
    DWORD cbPlainText = sizeof(*data);
    DWORD dwMod = 0;

    //  Memory to encrypt must be a multiple of CRYPTPROTECTMEMORY_BLOCK_SIZE.
    if (dwMod = cbPlainText % CRYPTPROTECTMEMORY_BLOCK_SIZE)
        cbSensitiveText = cbPlainText +
        (CRYPTPROTECTMEMORY_BLOCK_SIZE - dwMod);
    else
        cbSensitiveText = cbPlainText;

    pSensitiveText = (LPWSTR)LocalAlloc(LPTR, cbSensitiveText);
    if (NULL == pSensitiveText)
    {
        //wprintf(L"Memory allocation failed.\n");
        return E_OUTOFMEMORY;
    }

    //  Place sensitive string to encrypt in pSensitiveText.
    memcpy(pSensitiveText, *data, cbSensitiveText);
    if (!CryptProtectMemory(pSensitiveText, cbSensitiveText,
        CRYPTPROTECTMEMORY_SAME_PROCESS))
    {
        SecureZeroMemory(pSensitiveText, cbSensitiveText);
        LocalFree(pSensitiveText);
        pSensitiveText = NULL;
        return E_FAIL;
    }

    //  Call CryptUnprotectMemory to decrypt and use the memory.
    memcpy(*data, pSensitiveText, cbSensitiveText);

    SecureZeroMemory(pSensitiveText, cbSensitiveText);
    LocalFree(pSensitiveText);
    pSensitiveText = NULL;

    return hr;
}
HRESULT UnProtectData(void** data) {
    HRESULT hr = S_OK;
    LPWSTR pSensitiveText = NULL;
    DWORD cbSensitiveText = 0;
    DWORD cbPlainText = sizeof(*data);
    DWORD dwMod = 0;

    //  Memory to encrypt must be a multiple of CRYPTPROTECTMEMORY_BLOCK_SIZE.
    /*if (dwMod = cbPlainText % CRYPTPROTECTMEMORY_BLOCK_SIZE)
        cbSensitiveText = cbPlainText +
        (CRYPTPROTECTMEMORY_BLOCK_SIZE - dwMod);
    else*/
        cbSensitiveText = cbPlainText;

    pSensitiveText = (LPWSTR)LocalAlloc(LPTR, cbSensitiveText);
    if (NULL == pSensitiveText)
    {
        //wprintf(L"Memory allocation failed.\n");
        return E_OUTOFMEMORY;
    }

    //  Place sensitive string to encrypt in pSensitiveText.
    memcpy(pSensitiveText, *data, sizeof(*data));
    if (!CryptUnprotectMemory(pSensitiveText, cbSensitiveText,
        CRYPTPROTECTMEMORY_SAME_PROCESS))
    {
        SecureZeroMemory(pSensitiveText, cbSensitiveText);
        LocalFree(pSensitiveText);
        pSensitiveText = NULL;
        return E_FAIL;
    }

    //  Call CryptUnprotectMemory to decrypt and use the memory.
    memcpy(*data, pSensitiveText, cbSensitiveText);

    SecureZeroMemory(pSensitiveText, cbSensitiveText);
    LocalFree(pSensitiveText);
    pSensitiveText = NULL;

    return hr;
}
void trim(string& s)
{
    int index = 0;
    if (!s.empty())
    {
        while ((index = s.find(' ', index)) != string::npos)
        {
            s.erase(index, 1);
        }
    }
}
std::string& trimHE(std::string& s)
{
    if (!s.empty())
    {
        s.erase(0, s.find_first_not_of(" "));
        s.erase(s.find_last_not_of(" ") + 1);
    }
    return s;
}
std::list<char*> OnlineList;
UINT_PTR timerid = 0;
mutex m;
void CALLBACK CheckOnline(
    HWND unnamedParam1,
    UINT unnamedParam2,
    UINT_PTR unnamedParam3,
    DWORD unnamedParam4
) {
    if (unnamedParam3 == timerid) {
        m.lock();
        OnlineList.clear();
        m.unlock();
    }
        
}
DWORD CALLBACK Thread(PVOID pvoid)
{
    MSG msg;
    BOOL bRet;
    

    PeekMessage(&msg, NULL, WM_USER, WM_USER, PM_NOREMOVE);
    timerid = SetTimer(NULL, 0, 3000, CheckOnline);

    while ((bRet = GetMessage(&msg, NULL, 0, 0)) != 0)
    {
        if (bRet == -1)
        {
            printf("Error:the thread will quit,error id is %d\n", GetLastError());
            break;
        }
        else
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    KillTimer(NULL, timerid);
    printf("thread end here\n");
    return 0;
}

int main()
{
    std::cout << "Welcome to Private Chat Server "<< CURRENT_VERSION<<"!\n";
    cout << "Initalize Winsock2...\n";
    BOOL ifShowIP = FALSE,ifShowTime=FALSE,ifUseSecure=FALSE,ifAllowMulti=FALSE,ifUseToken=FALSE, ifDenyCapture=FALSE,ifUseEE2E=FALSE;
    int a,b,d,e,f,g,h;
    string c;
    cout << "Do you want to use E2EE to prevent your chat data secret from being viewed by Network Provider?Input \"1\" and Enter to do that.\n";
    cin >> h;
    if (h == 1) ifUseEE2E = TRUE;
    if (h == 1) cout << "Note that the message texts will be processed by clients,so a false client could break it.\n";
    cout << "Do you want to show Client IP?Input \"1\" and Enter to do that.\n";
    cin >> a;
    if (a == 1) ifShowIP = TRUE;
    cout << "Do you want to show request time?Input \"1\" and Enter to do that.\n";
    cin >> b;
    if (b == 1) ifShowTime = TRUE;
    cout << "Do you want to use secure socket?Input \"1\" and Enter to do that.\n";
    cin >> d;
    if (d == 1) ifUseSecure = TRUE;
    cout << "Do you want to allow single IP to login as different users?Input \"1\" and Enter to do that.\n";
    cin >> e;
    if (e == 1) ifAllowMulti = TRUE;
    cout << "Do you want to require token when clients connect?Input \"1\" and Enter to do that.\n";
    cin >> f;
    string token;
    if (f == 1) { 
        ifUseToken = TRUE;
        cout << "Input token text:";
        cin >> token;
    }
    cout << "Do you want to force client to deny screenshot?Input \"1\" and Enter to do that.\n";
    cin >> g;
    if (g == 1) ifDenyCapture = TRUE;
    int j = 0;
    cout << "Do you want to hide configs above?Input \"1\" and Enter to do that.\n";
    cin >> j;
    if (j == 1) system("cls");
    cout << "Please input the opening port(zero means default port):";
    cin >> c;
    if (c != "0") PORT = c; else PORT = "27065";
    cout << (a?"Show IP." : "Not to show IP.")<<"\n";
    cout << (b ? "Show Time." : "Not to show time.") << "\n";
    WSADATA wsaData;
    int iResult;
    string* Content=new string("");
    if (!ifUseEE2E) {
        *Content="PrivateChat0.0.3 New Conversation\n";
        Content->append((ifShowIP ? "The server will show your Ip in console.\n" : "The server won't show your Ip in console.\n"));
    }
    //ProtectData((void**) & Content);
    // Initialize Winsock
    std::map<char*, char*> UserIpMap;
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed: %d\n", iResult);
        return 1;
    }

    struct addrinfo* result = NULL, * ptr = NULL, hints;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the local address and port to be used by the server
    iResult = getaddrinfo(NULL, PORT.data(), &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    cout << "Try creating socket...\n";
    SOCKET ListenSocket = INVALID_SOCKET;
    // Create a SOCKET for the server to listen for client connections

    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        printf("Error at socket(): %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }
    
    // Setup the TCP listening socket
    BOOL val = TRUE;
    setsockopt(ListenSocket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&val, sizeof(val));
    int nNetTimeout = 2000; //2秒
    //发送时限
    setsockopt(ListenSocket, SOL_SOCKET, SO_SNDTIMEO, (char*)&nNetTimeout, sizeof(int));
    //接收时限
    setsockopt(ListenSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&nNetTimeout, sizeof(int));
    if (ifUseSecure) {
        cout << "Making sure socket is secure...\n";
        iResult = WSASetSocketSecurity(ListenSocket,
            NULL, 0, NULL, NULL);
        if (iResult == SOCKET_ERROR) {
            printf("WSASetSocketSecurity failed with error: %d\n", WSAGetLastError());
            freeaddrinfo(result);
            closesocket(ListenSocket);
            WSACleanup();
            return 1;
        }
        SOCKET_PEER_TARGET_NAME* peerTargetName = NULL;
        DWORD serverSpnStringLen = (DWORD)wcslen(L"PrivateChat");
        DWORD peerTargetNameLen = sizeof(SOCKET_PEER_TARGET_NAME) +
            (serverSpnStringLen * sizeof(wchar_t));
        peerTargetName = (SOCKET_PEER_TARGET_NAME*)HeapAlloc(GetProcessHeap(),
            HEAP_ZERO_MEMORY, peerTargetNameLen);
        if (!peerTargetName) {
            iResult = ERROR_NOT_ENOUGH_MEMORY;
            wprintf(L"Out of memory\n");
            freeaddrinfo(result);
            closesocket(ListenSocket);
            WSACleanup();
            return 1;
        }
        peerTargetName->SecurityProtocol = SOCKET_SECURITY_PROTOCOL_IPSEC;
        // Specify the server SPN 
        peerTargetName->PeerTargetNameStringLen = serverSpnStringLen;
        RtlCopyMemory((BYTE*)peerTargetName->AllStrings,
            (BYTE*)L"PrivateChat", serverSpnStringLen * sizeof(wchar_t)
        );
        iResult = WSASetSocketPeerTargetName(ListenSocket,
            peerTargetName,
            peerTargetNameLen, NULL, NULL);
        if (iResult == SOCKET_ERROR) {
            iResult = WSAGetLastError();
            wprintf(L"WSASetSocketPeerTargetName returned error %ld\n", iResult);
            freeaddrinfo(result);
            closesocket(ListenSocket);
            WSACleanup();
            return 1;
        }
    }
    cout << "Try binding socket...\n";
    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }
    freeaddrinfo(result);
    printf("Start listening socket:Port%s\n",PORT.data());
    if (listen(ListenSocket, SOMAXCONN) == SOCKET_ERROR) {
        printf("Listen failed with error: %ld\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }
    time_t timep;
    char timeBuf[50] = { 0 };
    CreateThread(NULL, 0, Thread, NULL, 0, NULL);
    while (TRUE) {
        cout << "----------------------------------------\n";
        SOCKET ClientSocket;
        ClientSocket = INVALID_SOCKET;
        if (Content->length() >= 256000&&!ifUseEE2E) {
            //UnProtectData((void**)&Content);
            Content->clear();
            Content = new string("PrivateChat0.0.1 New Conversation\n");
            Content->append((ifShowIP ? "The server will show your Ip in console.\n" : "The server won't show your Ip in console.\n"));
            Content->append("Cleared Text because the text were too long.\n");
           // ProtectData((void**)&Content);
        }
        else if(Content->length()>236000&&!ifUseEE2E){
            //UnProtectData((void**)&Content);
            Content->append("Tip:the texts are too long,so please save information and then restart the server.\n");
            //ProtectData((void**)&Content);
        }
        // Accept a client socket
        struct sockaddr_in skaddr2;
        int addrlen = sizeof(skaddr2);
        ClientSocket = WSAAccept(ListenSocket,(sockaddr*)&skaddr2, &addrlen ,NULL, NULL);
        if (ClientSocket == INVALID_SOCKET) {
            printf("accept failed: %d\n", WSAGetLastError());
            closesocket(ListenSocket);
            //WSACleanup();
            continue;

        }
        

        time(&timep); //获取从1970至今过了多少秒，存入time_t类型的timep
        ctime_s(timeBuf, 50, &timep);
        cout << "Received a connect request when " << (!ifShowTime ? "no time." : timeBuf) << endl;
        if (ifShowIP) {
            printf("Target IP address:%s\n", inet_ntoa(skaddr2.sin_addr));
        }
        char recvbuf[512] = { 0 };
        int aResult, iSendResult=0;
        int recvbuflen = 512;
        
        // Receive until the peer shuts down the connection
        do {

            aResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
            if (aResult > 0) {
                int nSendBuf = 0; //设置为0
                setsockopt(ClientSocket, SOL_SOCKET, SO_SNDBUF, (const char*)&nSendBuf, sizeof(int));
                printf("Bytes received: %d\n", aResult);
                printf("Request Content: %s\n", recvbuf);
                if (_strnicmp(recvbuf, "Account:", 8) == 0) {
                    string str = recvbuf;
                    string AccountName;
                    AccountName = str.substr(8, 11);
                    if (_strnicmp(str.substr(19, 8).c_str(), "Message:", 8) == 0 && strlen(recvbuf) == 200) {
                        auto it = UserIpMap.find(inet_ntoa(skaddr2.sin_addr));
                        if (!ifAllowMulti) {
                            if (it != UserIpMap.end() && strcmp(it->second, trimHE(AccountName).data()) != 0) {
                                cout << "Login failed!Ip matches failed.\n";
                                goto Invalid;
                            }
                            if (it == UserIpMap.end()) {
                                cout << "Login failed!\n";
                                goto Invalid;
                            }
                        }
                        if (!ifUseEE2E) {
                            string MessageText = str.substr(27);
                            trim(AccountName);
                            //UnProtectData((void**)&Content);
                            Content->append(AccountName.data());
                            Content->append(":");
                            Content->append(trimHE(MessageText).data());
                            Content->append("\n");
                        }
                        else {
                            cout << "Connect without EE2E!\n";
                            goto Invalid;
                        }
                        //ProtectData((void**)&Content);
                    }else if (_strnicmp(str.substr(19, 12).c_str(), "MessageEE2E:", 12) == 0) {
                        auto it = UserIpMap.find(inet_ntoa(skaddr2.sin_addr));
                        if (!ifAllowMulti) {
                            if (it != UserIpMap.end() && strcmp(it->second, trimHE(AccountName).data()) != 0) {
                                cout << "Login failed!Ip matches failed.\n";
                                goto Invalid;
                            }
                            if (it == UserIpMap.end()) {
                                cout << "Login failed!\n";
                                goto Invalid;
                            }
                        }
                        if (ifUseEE2E) {
                            string MessageText = str.substr(31);
                            *Content = MessageText;
                        }
                        //ProtectData((void**)&Content);
                    }
                }
                else if (_strnicmp(recvbuf, "Get:", 4) == 0) {
                    printf("Getting message content...\n");
                    string tmp = recvbuf;
                    char* tmpchr = (char*)malloc(30);
                    memset(tmpchr, 0, 30);
                    strcpy_s(tmpchr, 30, tmp.substr(4).data());
                    list<char*>::iterator it2; //声明一个迭代器
                    bool isExist = false;
                    for (it2 = OnlineList.begin(); it2 != OnlineList.end(); it2++) {
                        if (_stricmp(*it2, tmpchr) == 0) {
                            isExist = true;
                            break;
                        }
                    }
                    if (!isExist) {
                        m.lock();
                        OnlineList.push_back(tmpchr);
                        m.unlock();
                    }
                    else {
                        free(tmpchr);
                    }
                    auto it = UserIpMap.find(inet_ntoa(skaddr2.sin_addr));
                    if (!ifAllowMulti) {
                        if (it != UserIpMap.end() && strcmp(it->second, tmpchr) != 0) {
                            cout << "Login failed!Ip matches failed.\n";
                            goto Invalid;
                        }
                        if (it == UserIpMap.end()) {
                            cout << "Login failed!\n";
                            goto Invalid;
                        }
                    }
                    //UnProtectData((void**)&Content);
                    LONG remainLength = Content->length();
                    string SendContent(Content->data());
                    //ProtectData((void**)&Content);
                    if (Content->length() > 20000) {
                        do {
                            SendContent = SendContent.substr(0, 20000);
                            remainLength -= SendContent.length();
                            iSendResult += send(ClientSocket, SendContent.data(), SendContent.length(), 0);
                            if (iSendResult == SOCKET_ERROR) {
                                printf("send failed: %d\n", WSAGetLastError());
                                closesocket(ClientSocket);
                                WSACleanup();
                                continue;

                            }
                        } while (remainLength > 0);
                    }
                    else {
                        iSendResult += send(ClientSocket, SendContent.data(), SendContent.length(), 0);
                        if (iSendResult == SOCKET_ERROR) {
                            printf("send failed: %d\n", WSAGetLastError());
                            closesocket(ClientSocket);
                            //WSACleanup();
                            continue;

                        }
                    }
                    SecureZeroMemory((void*)&SendContent,sizeof(SendContent));
                    
                }
                else if (_stricmp(recvbuf, "QueryVersion") == 0) {
                    iSendResult = send(ClientSocket, CURRENT_VERSION, strlen(CURRENT_VERSION) + 1, 0);
                    if (iSendResult == SOCKET_ERROR) {
                        printf("send failed: %d\n", WSAGetLastError());
                        closesocket(ClientSocket);
                        //WSACleanup();
                        continue;

                    }
                }
                else if (_stricmp(recvbuf, "QueryOnline") == 0) {
                    string sendContent;
                    list<char*>::iterator it2; //声明一个迭代器
                    m.lock();
                    for (it2 = OnlineList.begin(); it2 != OnlineList.end(); it2++) {
                        sendContent += *it2;
                        sendContent += "\n";
                    }
                    m.unlock();
                    iSendResult = send(ClientSocket, sendContent.c_str(), strlen(sendContent.c_str()) + 1, 0);
                    if (iSendResult == SOCKET_ERROR) {
                        printf("send failed: %d\n", WSAGetLastError());
                        closesocket(ClientSocket);
                        //WSACleanup();
                        continue;

                    }
                }
                else if (_strnicmp(recvbuf,"Login:",6)==0) {
                    if (strlen(recvbuf) < 20&& strlen(recvbuf)>=9) {

                        string tmp = recvbuf;
                        char tmpchr[30] = { 0 };
                        strcpy_s(tmpchr,30,tmp.substr(6).data());
                        auto it = UserIpMap.find(inet_ntoa(skaddr2.sin_addr));
                        if (!ifAllowMulti) {
                            if (it != UserIpMap.end() && strcmp(it->second, tmpchr) != 0) {
                                iSendResult += send(ClientSocket, "Current Ip have already logined as another user.", sizeof("Current Ip have already logined as another user.") + 1, 0);
                                goto Invalid;
                            }
                            if (it != UserIpMap.end()) {
                                for (const auto& pair : UserIpMap) {
                                    //std::cout << "键: " << pair.first << ", 值: " << pair.second << std::endl;
                                    if (strcmp(pair.second, tmpchr) == 0 && strcmp(pair.first, inet_ntoa(skaddr2.sin_addr)) != 0) {
                                        goto Invalid;
                                    }
                                }
                            }
                        }
                        if (it == UserIpMap.end()) {
                            if (ifUseToken) {
                                iSendResult += send(ClientSocket, "NeedToken", sizeof("NeedToken") + 1, 0);
                            }
                            else {
                                char* tmpUsername = (char*)malloc(30);
                                memcpy(tmpUsername, tmpchr, 30);
                                UserIpMap.insert(pair<char*, char*>(inet_ntoa(skaddr2.sin_addr), tmpUsername));
                                //UnProtectData((void**)&Content);
                                if (!ifUseEE2E) {
                                    Content->append("IP ");
                                    Content->append(inet_ntoa(skaddr2.sin_addr));
                                    Content->append(" tried logining as ");
                                    Content->append(tmpchr);
                                    Content->append("\n");
                                    if (ifDenyCapture) {
                                        iSendResult += send(ClientSocket, "DenyCapture", sizeof("DenyCapture") + 1, 0);

                                    }
                                }
                            }
                        }
                        //ProtectData((void**)&Content);
                    }
                }
                else if (_strnicmp(recvbuf, "LoginWithToken:", 15) == 0) {
                    if (strlen(recvbuf) < 130 && strlen(recvbuf) >= 20) {

                        string tmp = recvbuf;
                        char tmpchr[130] = { 0 };
                        string temp = tmp.substr(15, 15);
                        strcpy_s(tmpchr, 130, trimHE(temp).data());
                        auto it = UserIpMap.find(inet_ntoa(skaddr2.sin_addr));
                        string inputToken = tmp.substr(31);
                        if (inputToken.compare(token) != 0) {
                            goto Invalid;
                        }
                        if (!ifAllowMulti) {
                            if (it != UserIpMap.end() && strcmp(it->second, tmpchr) != 0) {
                                iSendResult += send(ClientSocket, "Current Ip have already logined as another user.", sizeof("Current Ip have already logined as another user.") + 1, 0);
                                goto Invalid;
                            }
                            if (it != UserIpMap.end()) {
                                for (const auto& pair : UserIpMap) {
                                    //std::cout << "键: " << pair.first << ", 值: " << pair.second << std::endl;
                                    if (strcmp(pair.second, tmpchr) == 0 && strcmp(pair.first, inet_ntoa(skaddr2.sin_addr)) != 0) {
                                        goto Invalid;
                                    }
                                }
                            }
                        }
                        if (it == UserIpMap.end()) {
                                char* tmpUsername = (char*)malloc(30);
                                memcpy(tmpUsername, tmpchr, 30);
                                UserIpMap.insert(pair<char*, char*>(inet_ntoa(skaddr2.sin_addr), tmpUsername));
                                //UnProtectData((void**)&Content);
                                if (!ifUseEE2E) {
                                    Content->append("IP ");
                                    Content->append(inet_ntoa(skaddr2.sin_addr));
                                    Content->append(" tried logining as ");
                                    Content->append(tmpchr);
                                    Content->append("\n");
                                    if (ifDenyCapture) {
                                        iSendResult += send(ClientSocket, "DenyCapture", sizeof("DenyCapture") + 1, 0);

                                    }
                                }
                        }
                        //ProtectData((void**)&Content);
                    }
                    else {
                        goto Invalid;
                    }
                }
                else {
Invalid:
                    iSendResult += send(ClientSocket, "Invalid Request", sizeof("Invalid Request")+1, 0);
                    //iResult = shutdown(ClientSocket, SD_SEND);

                }

                Sleep(10);
                iSendResult += send(ClientSocket, "End", sizeof("End"), 0);
                nSendBuf = 8688; //设置为0
                setsockopt(ClientSocket, SOL_SOCKET, SO_SNDBUF, (const char*)&nSendBuf, sizeof(int));
                if (iSendResult == SOCKET_ERROR) {
                    printf("send failed: %d\n", WSAGetLastError());
                    closesocket(ClientSocket);
                    //WSACleanup();
                    continue;

                }
                else {
                    iResult = shutdown(ClientSocket, SD_SEND);
                    if (iResult == SOCKET_ERROR) {
                        printf("shutdown failed: %d\n", WSAGetLastError());
                        closesocket(ClientSocket);
                        //WSACleanup();
                        continue;

                    }
                    //break;
                }

                printf("Bytes sent: %d\n" ,iSendResult);
            }
            else if (aResult == 0)
                printf("Connection closing...\n");
            else {
                printf("recv failed: %d\n", WSAGetLastError());
                closesocket(ClientSocket);
                //WSACleanup();
                continue;
            }

        } while (aResult > 0);
        iResult = shutdown(ClientSocket, SD_SEND);
        if (iResult == SOCKET_ERROR) {
            printf("shutdown failed: %d\n", WSAGetLastError());
            closesocket(ClientSocket);
           // WSACleanup();
            continue;

        }
    }

}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
