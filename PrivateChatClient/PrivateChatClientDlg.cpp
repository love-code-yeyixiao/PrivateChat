
// PrivateChatClientDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "PrivateChatClient.h"
#include "PrivateChatClientDlg.h"
#include "afxdialogex.h"
#include <string>
#include <cstring>
#include <list>
#include <vector>
#include <string>
#include"CInputDialog.h"

using namespace std;
bool ifUseSecure = false;

void splitStr(std::string src, std::string pattern,
    std::vector<std::string>& sList) {
    int pos2 = 0;
    for (int i = 0; i < src.size();) {
        pos2 = src.find('\n', i);
        //cout << "pos2        " << pos2;
        if (pos2 != std::string::npos) {
            std::string strT = src.substr(i, pos2 - i);
            //cout << "    strT        " << strT << endl;
            sList.push_back(strT);
            i = pos2 + 1;
            continue;

        }
        else {
            sList.push_back(src.substr(i, src.size() - 1));
        }
        break;
    }
}


#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CPrivateChatClientDlg 对话框



CPrivateChatClientDlg::CPrivateChatClientDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_PRIVATECHATCLIENT_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CPrivateChatClientDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_IPADDRESS1, m_IPAddress);
    DDX_Control(pDX, IDC_LIST1, m_MessageList);
}

BEGIN_MESSAGE_MAP(CPrivateChatClientDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_CONNECT, &CPrivateChatClientDlg::OnBnClickedConnect)
    ON_BN_CLICKED(IDOK, &CPrivateChatClientDlg::OnBnClickedOk)
    ON_BN_CLICKED(IDC_REFRESH, &CPrivateChatClientDlg::OnBnClickedRefresh)
    ON_BN_CLICKED(IDC_BUTTON1, &CPrivateChatClientDlg::OnBnClickedButton1)
    ON_BN_CLICKED(IDC_BUTTON2, &CPrivateChatClientDlg::OnBnClickedButton2)
    ON_WM_TIMER()
    ON_BN_CLICKED(IDC_BUTTON3, &CPrivateChatClientDlg::OnBnClickedButton3)
END_MESSAGE_MAP()


// CPrivateChatClientDlg 消息处理程序
bool DenyCapture = false;
BOOL CPrivateChatClientDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	GetDlgItem(IDOK)->EnableWindow(0);
	GetDlgItem(IDC_REFRESH)->EnableWindow(0);
    GetDlgItem(IDC_EDITPORT)->SetWindowTextW(L"27065");
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CPrivateChatClientDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CPrivateChatClientDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


int
SecureTcpConnect(IN const struct sockaddr* serverAddr,
    IN ULONG serverAddrLen,
    IN const wchar_t* serverSPN,
    IN const SOCKET_SECURITY_SETTINGS* securitySettings,
    IN ULONG settingsLen,
    IN const char* dataBuf,
    OUT char* recvBuf)
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

    -*/
{
    int iResult = 0;
    int sockErr = 0;
    SOCKET sock = INVALID_SOCKET;
    string stri;

    WSABUF *wsaBuf = (WSABUF*)malloc(sizeof(WSABUF));
    char* wsabuf = (char*)malloc(20020);
    memset(wsaBuf, 0, sizeof(wsaBuf));
    memset(wsabuf, 0, sizeof(wsabuf));
    wsaBuf->buf = wsabuf;
    //const char* dataBuf = "12345678";
    DWORD bytesSent = 0;
    CStringA recvbuf = "";
    //char recvBuf[RECV_DATA_BUF_SIZE] = { 0 };

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
    if (ifUseSecure) {
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
        peerTargetName->SecurityProtocol = SOCKET_SECURITY_PROTOCOL_IPSEC;
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
    int nSendBuf = 0; //设置为0
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const char*)&nSendBuf, sizeof(int));
    int nNetTimeout = 10000; //2秒
    //发送时限
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&nNetTimeout, sizeof(int));
    //接收时限
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&nNetTimeout, sizeof(int));

    //-----------------------------------------
    // Send some data securely
    wsaBuf->len = (ULONG)strlen(dataBuf);
   // LPSTR tmpBuf[256] = { 0 };
    //strcpy_s(tmpBuf,sizeof(dataBuf), dataBuf);
    if(sizeof(dataBuf)<20000)
        strcpy_s(wsaBuf->buf , 20000,dataBuf);
    sockErr = WSASend(sock, wsaBuf, 1, &bytesSent, 0, NULL, NULL);
    if (sockErr == SOCKET_ERROR) {
        iResult = WSAGetLastError();
        wprintf(L"WSASend returned error %ld\n", iResult);
        goto cleanup;
    }
    wprintf(L"Sent %d bytes of data to the server\n", bytesSent);

    //-----------------------------------------
    // Receive server's response securely
    wsaBuf->len = RECV_DATA_BUF_SIZE;
    wsaBuf->buf = recvBuf;
    
    do {
        memset(recvBuf, 0, sizeof(recvBuf));
        sockErr = WSARecv(sock, wsaBuf, 1, &bytesRecvd, &flags, NULL, NULL);
        if (sockErr == SOCKET_ERROR) {
            iResult = WSAGetLastError();
            wprintf(L"WSARecv returned error %ld\n", iResult);
            goto cleanup;
        }
        recvbuf += recvBuf;
        stri = recvbuf;
    } while (_stricmp(recvBuf,"End") != 0&& stri.substr(stri.length() - 3, 3).compare("End")!=0);
    recvbuf.Delete(recvbuf.GetLength()-3, 3);
    strcpy_s(recvBuf,recvbuf.GetLength()+1, recvbuf.GetString());
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
    free(wsaBuf);
    free(wsabuf);
    return iResult;
}
void CPrivateChatClientDlg::OnBnClickedConnect()
{
	// TODO: 在此添加控件通知处理程序代码
    m_MessageList.ResetContent();
    struct addrinfo* result = NULL, hints;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    WCHAR IP[15] = L"127.0.0.1";
    m_IPAddress.GetWindowTextW(IP, 15);
    USES_CONVERSION;
    CString port;
    GetDlgItem(IDC_EDITPORT)->GetWindowTextW(port);
    getaddrinfo(W2A(IP), W2A(port.GetString()), &hints, &result);
    if (result == nullptr) {
        MessageBox(L"地址错误或无法解析地址！");
        KillTimer(1003);
        return;
    }
    char recvBuf[256000] = { 0 };
    if (SecureTcpConnect(result->ai_addr, result->ai_addrlen, L"PrivateChat", NULL, 0, "QueryVersion\0", recvBuf) == 0) {
        if (_stricmp(recvBuf, "0.0.1") != 0) {
            MessageBox(L"版本校验失败！服务端版本不匹配！");
            MessageBoxA(m_hWnd, recvBuf, "客户端版本:0.0.1", MB_OK);
            GetDlgItem(IDC_REFRESH)->EnableWindow(0);
            GetDlgItem(IDOK)->EnableWindow(0);
            KillTimer(1003);
            return;
        }
    }
    else {
        MessageBox(L"无法连接到去中心化服务器或连接过程中发生错误",L"版本查询");
        GetDlgItem(IDC_REFRESH)->EnableWindow(0);
        GetDlgItem(IDOK)->EnableWindow(0);
        KillTimer(1003);
        return;
    }
    CString loginText = L"Login:",username;
    GetDlgItem(IDC_EDITUSER)->GetWindowTextW(username);
    if (username.GetLength() >= 15|| username.GetLength()<3) {
        MessageBox(L"用户名过长或太短！");
        KillTimer(1003);
        return;
    }
    loginText.Append(username);
    if (SecureTcpConnect(result->ai_addr, result->ai_addrlen, L"PrivateChat", NULL, 0, W2A(loginText.GetString()), recvBuf) == 0) {
        if (_stricmp(recvBuf, "NeedToken") == 0) {
            MessageBox(L"服务端请求Token，请在随后弹出窗口中输入");
            CInputDialog dlg(this);
            dlg.DoModal();
            if (dlg.token.IsEmpty()) {
                MessageBox(L"用户取消了令牌输入，登录操作取消");
                return;
            }
            else {
                CString token = dlg.token,loginText2;
                loginText2.Format(L"LoginWithToken:%-15s:%s", username,token);
                if (SecureTcpConnect(result->ai_addr, result->ai_addrlen, L"PrivateChat", NULL, 0, W2A(loginText2.GetString()), recvBuf) == 0) {
                    if (_stricmp(recvBuf, "DenyCapture") == 0) {
                        SetWindowDisplayAffinity(m_hWnd, WDA_EXCLUDEFROMCAPTURE);
                        GetDlgItem(IDC_BUTTON1)->SetWindowTextW(L"允许截图");
                        DenyCapture = TRUE;
                        GetDlgItem(IDC_BUTTON1)->EnableWindow(FALSE);
                    }
                    else if (_stricmp(recvBuf, "") != 0) {
                        MessageBox(L"登录失败！令牌错误！");
                        GetDlgItem(IDC_REFRESH)->EnableWindow(0);
                        GetDlgItem(IDOK)->EnableWindow(0);
                        KillTimer(1003);
                        return;
                    }
                    else if (DenyCapture) {
                        GetDlgItem(IDC_BUTTON1)->EnableWindow();
                    }
                }
                else {
                    MessageBox(L"无法连接到去中心化服务器或连接过程中发生错误", L"登录");
                    GetDlgItem(IDC_REFRESH)->EnableWindow(0);
                    GetDlgItem(IDOK)->EnableWindow(0);
                    KillTimer(1003);
                    return;
                }
            }
        }
        else if (_stricmp(recvBuf, "DenyCapture") == 0) {
            SetWindowDisplayAffinity(m_hWnd, WDA_EXCLUDEFROMCAPTURE);
            GetDlgItem(IDC_BUTTON1)->SetWindowTextW(L"允许截图");
            DenyCapture = TRUE;
            GetDlgItem(IDC_BUTTON1)->EnableWindow(FALSE);
        }
        else if (_stricmp(recvBuf, "") != 0) {
            MessageBox(L"登录失败！用户名不合规！");
            GetDlgItem(IDC_REFRESH)->EnableWindow(0);
            GetDlgItem(IDOK)->EnableWindow(0);
            KillTimer(1003);
            return;
        }
        else if(DenyCapture){
            GetDlgItem(IDC_BUTTON1)->EnableWindow();
        }
    }
    else {
        MessageBox(L"无法连接到去中心化服务器或连接过程中发生错误",L"登录");
        GetDlgItem(IDC_REFRESH)->EnableWindow(0);
        GetDlgItem(IDOK)->EnableWindow(0);
        KillTimer(1003);
        return;
    }
    CString GetText = L"Get:";
    GetText.Append(username);
    if (SecureTcpConnect(result->ai_addr, result->ai_addrlen, L"PrivateChat", NULL, 0, W2A(GetText.GetString()), recvBuf) == 0) {
       // MessageBox(L"连接成功");
        std::vector<std::string> sList;
        splitStr(recvBuf, "\n", sList);
        int index = 0;
        for each (std::string var in sList)
        {
            m_MessageList.InsertString(index,A2W(var.data()));
            index++;
        }
        GetDlgItem(IDC_REFRESH)->EnableWindow();
        GetDlgItem(IDOK)->EnableWindow();
        SetTimer(1003, 2000, NULL);
    }
    else {
        MessageBox(L"无法连接到去中心化服务器或连接过程中发生错误",L"消息检索");
        GetDlgItem(IDC_REFRESH)->EnableWindow(0);
        GetDlgItem(IDOK)->EnableWindow(0);
        KillTimer(1003);
        return;
    }
}


void CPrivateChatClientDlg::OnBnClickedOk()
{
    // TODO: 在此添加控件通知处理程序代码
    m_MessageList.ResetContent();
    struct addrinfo* result = NULL, hints;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    WCHAR IP[15] = L"127.0.0.1";
    m_IPAddress.GetWindowTextW(IP, 15);
    USES_CONVERSION;
    CString port;
    GetDlgItem(IDC_EDITPORT)->GetWindowTextW(port);
    getaddrinfo(W2A(IP), W2A(port.GetString()), &hints, &result);
    if (result == nullptr) {
        MessageBox(L"地址错误或无法解析地址！");
        KillTimer(1003);
        return;
    }
    char recvBuf[256000] = { 0 };
    CString username;
    GetDlgItem(IDC_EDITUSER)->GetWindowTextW(username);
    if (username.GetLength() >= 15 || username.GetLength() < 3) {
        MessageBox(L"用户名过长或太短！");
        KillTimer(1003);
        return;
    }
    CStringA SendText;
    char MessageText[160] = { 0 };
    ::GetWindowTextA(::GetDlgItem(m_hWnd,IDC_EDITTEXT),MessageText,160);
    if (strlen(MessageText) >= 160 || strlen(MessageText) < 1) {
        MessageBox(L"消息过长或太短！");
        return;
    }
    SendText.Format("Account:%-11sMessage:%-173s", W2A(username.GetString()), MessageText);
    if (SecureTcpConnect(result->ai_addr, result->ai_addrlen, L"PrivateChat", NULL, 0, SendText.GetString(), recvBuf) == 0) {
        // MessageBox(L"连接成功");
        GetDlgItem(IDC_EDITTEXT)->SetWindowTextW(L"");
        OnBnClickedRefresh();
    }
    else {
        MessageBox(L"无法连接到去中心化服务器或连接过程中发生错误", L"消息检索");
        GetDlgItem(IDC_REFRESH)->EnableWindow(0);
        GetDlgItem(IDOK)->EnableWindow(0);
        KillTimer(1003);
        return;
    }
}


void CPrivateChatClientDlg::OnBnClickedRefresh()
{
    // TODO: 在此添加控件通知处理程序代码
    m_MessageList.ResetContent();
    struct addrinfo* result = NULL, hints;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    WCHAR IP[15] = L"127.0.0.1";
    m_IPAddress.GetWindowTextW(IP, 15);
    USES_CONVERSION;
    CString port;
    GetDlgItem(IDC_EDITPORT)->GetWindowTextW(port);
    getaddrinfo(W2A(IP), W2A(port.GetString()), &hints, &result);
    if (result == nullptr) {
        MessageBox(L"地址错误或无法解析地址！");
        KillTimer(1003);
        return;
    }
    char recvBuf[256000] = { 0 };
    CString loginText = L"Login:", username;
    GetDlgItem(IDC_EDITUSER)->GetWindowTextW(username);
    if (username.GetLength() >= 15 || username.GetLength() < 3) {
        MessageBox(L"用户名过长或太短！");
        return;
    }
    loginText.Append(username);
    CString GetText = L"Get:";
    GetText.Append(username);
    if (SecureTcpConnect(result->ai_addr, result->ai_addrlen, L"PrivateChat", NULL, 0, W2A(GetText.GetString()), recvBuf) == 0) {
        // MessageBox(L"连接成功");
        std::vector<std::string> sList;
        splitStr(recvBuf, "\n", sList);
        int index = 0;
        for each (std::string var in sList)
        {
            m_MessageList.InsertString(index, A2W(var.data()));
            index++;
        }
        GetDlgItem(IDC_REFRESH)->EnableWindow();
        GetDlgItem(IDOK)->EnableWindow();
    }
    else {
        MessageBox(L"无法连接到去中心化服务器或连接过程中发生错误", L"消息检索");
        GetDlgItem(IDC_REFRESH)->EnableWindow(0);
        GetDlgItem(IDOK)->EnableWindow(0);
        KillTimer(1003);
        return;
    }
}


void CPrivateChatClientDlg::OnBnClickedButton1()
{
    // TODO: 在此添加控件通知处理程序代码
    if (DenyCapture) {
        SetWindowDisplayAffinity(m_hWnd, WDA_NONE);
        GetDlgItem(IDC_BUTTON1)->SetWindowTextW(L"禁止截图");
        DenyCapture = FALSE;
    }
    else {
        SetWindowDisplayAffinity(m_hWnd, WDA_EXCLUDEFROMCAPTURE);
        GetDlgItem(IDC_BUTTON1)->SetWindowTextW(L"允许截图");
        DenyCapture = TRUE;
    }
}


void CPrivateChatClientDlg::OnBnClickedButton2()
{
    // TODO: 在此添加控件通知处理程序代码
    if (ifUseSecure) {
        GetDlgItem(IDC_BUTTON2)->SetWindowTextW(L"使用安全套件");
        ifUseSecure = FALSE;
    }
    else {
        GetDlgItem(IDC_BUTTON2)->SetWindowTextW(L"不使用安全套件");
        ifUseSecure = TRUE;
    }
}


void CPrivateChatClientDlg::OnTimer(UINT_PTR nIDEvent)
{
    // TODO: 在此添加消息处理程序代码和/或调用默认值
    if (nIDEvent == 1003) {
        if (GetDlgItem(IDC_BUTTON1)->IsWindowEnabled()) {
            this->OnBnClickedRefresh();
        }
    }
    CDialogEx::OnTimer(nIDEvent);
}


void CPrivateChatClientDlg::OnBnClickedButton3()
{
    // TODO: 在此添加控件通知处理程序代码
    struct addrinfo* result = NULL, hints;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    WCHAR IP[15] = L"127.0.0.1";
    m_IPAddress.GetWindowTextW(IP, 15);
    USES_CONVERSION;
    CString port;
    GetDlgItem(IDC_EDITPORT)->GetWindowTextW(port);
    getaddrinfo(W2A(IP), W2A(port.GetString()), &hints, &result);
    if (result == nullptr) {
        MessageBox(L"地址错误或无法解析地址！");
        KillTimer(1003);
        return;
    }
    char recvBuf[256000] = { 0 };
    if (SecureTcpConnect(result->ai_addr, result->ai_addrlen, L"PrivateChat", NULL, 0, "QueryOnline\0", recvBuf) == 0) {
        MessageBox(A2W(recvBuf));
    }
    else {
        MessageBox(L"无法连接到去中心化服务器或连接过程中发生错误", L"版本查询");
        GetDlgItem(IDC_REFRESH)->EnableWindow(0);
        GetDlgItem(IDOK)->EnableWindow(0);
        KillTimer(1003);
        return;
    }
}
