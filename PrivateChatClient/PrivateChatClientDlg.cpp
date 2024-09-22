
// PrivateChatClientDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "PrivateChatClient.h"
#include "PrivateChatClientDlg.h"
#include "CInputDialog.h"
#include "afxdialogex.h"
#include <string>
#include <cstring>
#include <list>
#include <vector>
#include <string>
#include <tchar.h>
//#define MESSAGE_MAX_LENGTH 256000
DWORD MESSAGE_MAX_LENGTH = 256000;

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
inline std::string byteToHexStr(unsigned char* byte_arr, int arr_len)
{
    std::string hexstr;
    //
    for (int i = 0; nullptr != byte_arr && i < arr_len; ++i)
    {
        char hex1;
        char hex2;

        /*借助C++支持的unsigned和int的强制转换，把unsigned char赋值给int的值，那么系统就会自动完成强制转换*/
        int value = byte_arr[i];
        int S = value / 16;
        int Y = value % 16;

        //将C++中unsigned char和int的强制转换得到的商转成字母
        if (S >= 0 && S <= 9)
        {
            hex1 = (char)(48 + S);
        }
        else
        {
            hex1 = (char)(55 + S);
        }

        //将C++中unsigned char和int的强制转换得到的余数转成字母
        if (Y >= 0 && Y <= 9)
        {
            hex2 = (char)(48 + Y);
        }
        else
        {
            hex2 = (char)(55 + Y);
        }

        //最后一步的代码实现，将所得到的两个字母连接成字符串达到目的
        hexstr = hexstr + hex1 + hex2;
    }

    return hexstr;
}
inline std::string hexStrToByte(const char* hexstr, int len)
{
    std::string byteString;
    unsigned char bits;
    for (int i = 0; nullptr != hexstr && i < len; i += 2)
    {
        if (hexstr[i] >= 'A' && hexstr[i] <= 'F')
        {
            bits = hexstr[i] - 'A' + 10;
        }
        else
        {
            bits = hexstr[i] - '0';
        }
        //
        if (hexstr[i + 1] >= 'A' && hexstr[i + 1] <= 'F')
        {
            bits = (bits << 4) | (hexstr[i + 1] - 'A' + 10);
        }
        else
        {
            bits = (bits << 4) | (hexstr[i + 1] - '0');
        }
        //
        byteString.push_back(bits);
    }

    return byteString;
}

void MyHandleError(LPTSTR psz, int nErrorNumber)
{
    MessageBox(NULL,TEXT("An error occurred in the program. \n"),NULL,MB_OK);
    _ftprintf(stderr, TEXT("%s\n"), psz);
    _ftprintf(stderr, TEXT("Error number %x.\n"), nErrorNumber);
}
BYTE* Append(BYTE* first,BYTE* second) {

    int m = sizeof(first) / sizeof(*first);
    int n = sizeof(second) / sizeof(*second);

    BYTE *result = (BYTE*)malloc(m + n);
    memset(result, 0, m + n);
    std::copy(first, first + m, result);
    std::copy(second, second + n, result + m);

    return result;
}
bool EncryptText(
    BYTE* pszSourceText,
    BYTE* pszDestinationText,
    CString pszPassword)
{
    //---------------------------------------------------------------
    // Declare and initialize local variables.
    bool fReturn = false;

    HCRYPTPROV hCryptProv = NULL;
    HCRYPTKEY hKey = NULL;
    HCRYPTKEY hXchgKey = NULL;
    HCRYPTHASH hHash = NULL;

    PBYTE pbKeyBlob = NULL;
   // DWORD dwKeyBlobLen;

    PBYTE pbBuffer = NULL;
    DWORD dwBlockLen;
    DWORD dwBufferLen;
    //DWORD dwCount;
    //CStringA falseFile = reinterpret_cast<char*>(pszSourceText);
    BYTE* falseFile = pszSourceText;
    //---------------------------------------------------------------
    // Get the handle to the default provider. 
    if (CryptAcquireContext(
        &hCryptProv,
        NULL,
        MS_ENHANCED_PROV,
        PROV_RSA_FULL,
        0))
    {
        _tprintf(
            TEXT("A cryptographic provider has been acquired. \n"));
    }
    else
    {
        MyHandleError(
            TEXT("Error during CryptAcquireContext!\n"),
            GetLastError());
        goto Exit_MyEncryptFile;
    }

    //---------------------------------------------------------------
    // Create the session key.
    if (pszPassword.IsEmpty() || !pszPassword.GetString()[0])
    {
        return false;
    }
    else
    {

        //-----------------------------------------------------------
        // The file will be encrypted with a session key derived 
        // from a password.
        // The session key will be recreated when the file is 
        // decrypted only if the password used to create the key is 
        // available. 

        //-----------------------------------------------------------
        // Create a hash object. 
        if (CryptCreateHash(
            hCryptProv,
            CALG_MD5,
            0,
            0,
            &hHash))
        {
            _tprintf(TEXT("A hash object has been created. \n"));
        }
        else
        {
            MyHandleError(
                TEXT("Error during CryptCreateHash!\n"),
                GetLastError());
            goto Exit_MyEncryptFile;
        }

        //-----------------------------------------------------------
        // Hash the password. 
        USES_CONVERSION;
        if (CryptHashData(
            hHash,
            (BYTE*)W2A(pszPassword.GetString()),
            strlen(W2A(pszPassword.GetString())),
            0))
        {
            _tprintf(
                TEXT("The password has been added to the hash. \n"));
        }
        else
        {
            MyHandleError(
                TEXT("Error during CryptHashData. \n"),
                GetLastError());
            goto Exit_MyEncryptFile;
        }

        //-----------------------------------------------------------
        // Derive a session key from the hash object. 
        if (CryptDeriveKey(
            hCryptProv,
            ENCRYPT_ALGORITHM,
            hHash,
            KEYLENGTH,
            &hKey))
        {
            _tprintf(
                TEXT("An encryption key is derived from the ")
                TEXT("password hash. \n"));
        }
        else
        {
            MyHandleError(
                TEXT("Error during CryptDeriveKey!\n"),
                GetLastError());
            goto Exit_MyEncryptFile;
        }
    }

    //---------------------------------------------------------------
    // The session key is now ready. If it is not a key derived from 
    // a  password, the session key encrypted with the private key 
    // has been written to the destination file.

    //---------------------------------------------------------------
    // Determine the number of bytes to encrypt at a time. 
    // This must be a multiple of ENCRYPT_BLOCK_SIZE.
    // ENCRYPT_BLOCK_SIZE is set by a #define statement.
    dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;

    //---------------------------------------------------------------
    // Determine the block size. If a block cipher is used, 
    // it must have room for an extra block. 
    if (ENCRYPT_BLOCK_SIZE > 1)
    {
        dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE;
    }
    else
    {
        dwBufferLen = dwBlockLen;
    }

    //---------------------------------------------------------------
    // Allocate memory. 
    if (pbBuffer = (BYTE*)malloc(dwBufferLen))
    {
        _tprintf(
            TEXT("Memory has been allocated for the buffer. \n"));
    }
    else
    {
        MyHandleError(TEXT("Out of memory. \n"), E_OUTOFMEMORY);
        goto Exit_MyEncryptFile;
    }
    memset(pbBuffer, 0, dwBufferLen);

    bool fEOF = FALSE;
    long index = 0;
    do
    {

        //CStringA tmp = falseFile.Left(dwBlockLen);
       // BYTE* tmp = (BYTE*)malloc(dwBlockLen);
       // memset(tmp, 0, dwBlockLen);
       // memcpy_s(tmp,dwBlockLen,)
        USES_CONVERSION;
        //pbBuffer = (BYTE*)W2A(tmp);
        DWORD length = strlen(reinterpret_cast<char*>(pszSourceText));
        if (sizeof(pszSourceText) <= dwBlockLen) {
            memcpy_s(pbBuffer, dwBufferLen, pszSourceText, length);
        }
        else {
            memcpy_s(pbBuffer, dwBufferLen, pszSourceText, dwBlockLen);
        }
        //memcpy_s(pbBuffer, (long long)dwBufferLen, pszSourceText, ((long long)sizeof(pszSourceText)/sizeof(pszSourceText[0]) >= (long long)dwBlockLen) ? (long long)dwBlockLen : (long long)sizeof(pszSourceText));
        //memcpy_s(pbBuffer,dwBufferLen, tmp.GetString(), (tmp.GetLength() >= dwBlockLen) ? dwBlockLen : tmp.GetLength());
        if ((long long)sizeof(pszSourceText) < (long long)dwBlockLen)
        {
            fEOF = TRUE;
        }
        else {
            //falseFile = falseFile.Right(falseFile.GetLength() - dwBlockLen);
            //memcpy_s(falseFile, sizeof(falseFile), falseFile + dwBlockLen, sizeof(falseFile) - dwBlockLen);
            BYTE* temp = (BYTE*)malloc(MESSAGE_MAX_LENGTH);
            memset(temp, 0, MESSAGE_MAX_LENGTH);
            memcpy_s(temp, MESSAGE_MAX_LENGTH, falseFile, MESSAGE_MAX_LENGTH);
            memset(falseFile, 0, MESSAGE_MAX_LENGTH);
            memcpy_s(falseFile, sizeof(falseFile), temp + (long long)dwBlockLen, (long long)sizeof(temp) - (long long)dwBlockLen);
            free(temp);
        }
        //-----------------------------------------------------------
        // Encrypt data. 
        //DWORD len = tmp.GetLength();
        if (!CryptEncrypt(
            hKey,
            NULL,
            fEOF,
            0,
            pbBuffer,
            &length,
            dwBufferLen))
        {
            MyHandleError(
                TEXT("Error during CryptEncrypt. \n"),
                GetLastError());
            goto Exit_MyEncryptFile;
        }

        //-----------------------------------------------------------
        // Write the encrypted data to the destination file. 
       // wchar_t* tmpbuf = (wchar_t*)malloc(dwBufferLen);
       // memset(tmpbuf, 0, dwBufferLen);
       // memcpy_s(tmpbuf, dwBufferLen, pbBuffer,sizeof(pbBuffer));
       // 
        //pszDestinationText.Append(reinterpret_cast<char*>(pbBuffer));
        //memcpy_s(pszDestinationText + sizeof(pszDestinationText)/sizeof(BYTE), MESSAGE_MAX_LENGTH - sizeof(pszDestinationText)/sizeof(BYTE), pbBuffer, dwBufferLen);
        memcpy_s(pszDestinationText, MESSAGE_MAX_LENGTH, pbBuffer, dwBufferLen);
       // free(tmp);
        // free(tmpbuf);
        //-----------------------------------------------------------
        // End the do loop when the last block of the source file 
        // has been read, encrypted, and written to the destination 
        // file.
    } while (!fEOF);

    fReturn = true;

Exit_MyEncryptFile:

    //---------------------------------------------------------------
    // Free memory. 
    if (pbBuffer)
    {
        free(pbBuffer);
    }
    // Free memory.
    free(pbKeyBlob);

    //-----------------------------------------------------------
    // Release the hash object. 
    if (hHash)
    {
        if (!(CryptDestroyHash(hHash)))
        {
            MyHandleError(
                TEXT("Error during CryptDestroyHash.\n"),
                GetLastError());
        }

        hHash = NULL;
    }

    //---------------------------------------------------------------
    // Release the session key. 
    if (hKey)
    {
        if (!(CryptDestroyKey(hKey)))
        {
            MyHandleError(
                TEXT("Error during CryptDestroyKey!\n"),
                GetLastError());
        }
    }

    //---------------------------------------------------------------
    // Release the provider handle. 
    if (hCryptProv)
    {
        if (!(CryptReleaseContext(hCryptProv, 0)))
        {
            MyHandleError(
                TEXT("Error during CryptReleaseContext!\n"),
                GetLastError());
        }
    }

    return fReturn;
} // End EncryptText.
bool DecryptText(
    BYTE* pszSourceText,
    BYTE* pszDestinationText,
    CString pszPassword)
{
    //---------------------------------------------------------------
    // Declare and initialize local variables.
    bool fReturn = false;
    HCRYPTKEY hKey = NULL;
    HCRYPTHASH hHash = NULL;

    HCRYPTPROV hCryptProv = NULL;

    PBYTE pbBuffer = NULL;
    DWORD dwBlockLen;
    DWORD dwBufferLen;
    BYTE* tmpBuf;

    //---------------------------------------------------------------
    // Get the handle to the default provider. 
    if (CryptAcquireContext(
        &hCryptProv,
        NULL,
        MS_ENHANCED_PROV,
        PROV_RSA_FULL,
        0))
    {
        _tprintf(
            TEXT("A cryptographic provider has been acquired. \n"));
    }
    else
    {
        MyHandleError(
            TEXT("Error during CryptAcquireContext!\n"),
            GetLastError());
        goto Exit_MyDecryptFile;
    }

    //---------------------------------------------------------------
    // Create the session key.
    DWORD dwKeyBlobLen=0;
    if (pszPassword.IsEmpty() || !pszPassword.GetString()[0])
    {
        return false;
    }
    else
    {
        //-----------------------------------------------------------
        // Decrypt the file with a session key derived from a 
        // password. 

        //-----------------------------------------------------------
        // Create a hash object. 
        if (!CryptCreateHash(
            hCryptProv,
            CALG_MD5,
            0,
            0,
            &hHash))
        {
            MyHandleError(
                TEXT("Error during CryptCreateHash!\n"),
                GetLastError());
            goto Exit_MyDecryptFile;
        }

        //-----------------------------------------------------------
        // Hash in the password data. 
        USES_CONVERSION;
        if (!CryptHashData(
            hHash,
            (BYTE*)W2A(pszPassword.GetString()),
            strlen(W2A(pszPassword.GetString())),
            0))
        {
            MyHandleError(
                TEXT("Error during CryptHashData!\n"),
                GetLastError());
            goto Exit_MyDecryptFile;
        }

        //-----------------------------------------------------------
        // Derive a session key from the hash object. 
        if (!CryptDeriveKey(
            hCryptProv,
            ENCRYPT_ALGORITHM,
            hHash,
            KEYLENGTH,
            &hKey))
        {
            MyHandleError(
                TEXT("Error during CryptDeriveKey!\n"),
                GetLastError());
            goto Exit_MyDecryptFile;
        }
    }

    //---------------------------------------------------------------
    // The decryption key is now available, either having been 
    // imported from a BLOB read in from the source file or having 
    // been created by using the password. This point in the program 
    // is not reached if the decryption key is not available.

    //---------------------------------------------------------------
    // Determine the number of bytes to decrypt at a time. 
    // This must be a multiple of ENCRYPT_BLOCK_SIZE. 

    dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;
    dwBufferLen = dwBlockLen;

    //---------------------------------------------------------------
    // Allocate memory for the file read buffer. 
    if (!(pbBuffer = (PBYTE)malloc(dwBufferLen)))
    {
        MyHandleError(TEXT("Out of memory!\n"), E_OUTOFMEMORY);
        goto Exit_MyDecryptFile;
    }
    memset(pbBuffer, 0, dwBufferLen);

    //---------------------------------------------------------------
    // Decrypt the source file, and write to the destination file. 
    bool fEOF = false;
    tmpBuf = pszSourceText;

    do
    {
        //-----------------------------------------------------------
        // Read up to dwBlockLen bytes from the source file. 
       // pbBuffer = (BYTE*)tmpBuf.Left(dwBlockLen).GetString();
        USES_CONVERSION;
        DWORD length = strlen(reinterpret_cast<char*>(pszSourceText));
        if (sizeof(pszSourceText) <= dwBlockLen) {
            memcpy_s(pbBuffer, dwBufferLen, pszSourceText, length);
        }
        else {
            memcpy_s(pbBuffer, dwBufferLen, pszSourceText, dwBlockLen);
        }
        //pbBuffer = (BYTE*)W2A(tmpBuf.Left(dwBlockLen));

        if ((long long)sizeof(pbBuffer) < (long long)dwBlockLen)
        {
            fEOF = TRUE;
        }
        else {
            //tmpBuf = tmpBuf.Right(tmpBuf.GetLength() - dwBlockLen);
            BYTE* temp = (BYTE*)malloc(MESSAGE_MAX_LENGTH);
            memset(temp, 0, MESSAGE_MAX_LENGTH);
            memcpy_s(temp, MESSAGE_MAX_LENGTH, tmpBuf, MESSAGE_MAX_LENGTH);
            memset(tmpBuf, 0, MESSAGE_MAX_LENGTH);
            memcpy_s(tmpBuf, sizeof(tmpBuf), temp + dwBlockLen, sizeof(temp) - dwBlockLen);
            free(temp);
        }
        
        //-----------------------------------------------------------
        // Decrypt the block of data. 
        DWORD len = sizeof(pbBuffer);
        if (!CryptDecrypt(
            hKey,
            0,
            fEOF,
            0,
            pbBuffer,
            &length))
        {
            MyHandleError(
                TEXT("Error during CryptDecrypt!\n"),
                GetLastError());
            goto Exit_MyDecryptFile;
        }

        //-----------------------------------------------------------
        // Write the decrypted data to the destination text. 
        //char* tmpbuf = (char*)malloc(dwBufferLen);
       // memset(tmpbuf, 0, dwBufferLen);
       // memcpy_s(tmpbuf, dwBufferLen, pbBuffer, sizeof(pbBuffer));
        //pszDestinationText.Append((reinterpret_cast<char*>(pbBuffer)));
        memcpy_s(pszDestinationText, MESSAGE_MAX_LENGTH, pbBuffer, MESSAGE_MAX_LENGTH);


        //-----------------------------------------------------------
        // End the do loop when the last block of the source file 
        // has been read, encrypted, and written to the destination 
        // file.
    } while (!fEOF);

    fReturn = true;

Exit_MyDecryptFile:

    //---------------------------------------------------------------
    // Free the file read buffer.
    if (pbBuffer)
    {
        free(pbBuffer);
    }


    //-----------------------------------------------------------
    // Release the hash object. 
    if (hHash)
    {
        if (!(CryptDestroyHash(hHash)))
        {
            MyHandleError(
                TEXT("Error during CryptDestroyHash.\n"),
                GetLastError());
        }

        hHash = NULL;
    }

    //---------------------------------------------------------------
    // Release the session key. 
    if (hKey)
    {
        if (!(CryptDestroyKey(hKey)))
        {
            MyHandleError(
                TEXT("Error during CryptDestroyKey!\n"),
                GetLastError());
        }
    }

    //---------------------------------------------------------------
    // Release the provider handle. 
    if (hCryptProv)
    {
        if (!(CryptReleaseContext(hCryptProv, 0)))
        {
            MyHandleError(
                TEXT("Error during CryptReleaseContext!\n"),
                GetLastError());
        }
    }

    return fReturn;
}//End DecryptText

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
    DDX_Control(pDX, IDC_EDIT4, m_EE2EToken);
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
        if (_stricmp(recvBuf, "0.0.3") != 0) {
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
        CString token2;
        m_EE2EToken.GetWindowTextW(token2);
        if (!token2.IsEmpty()) {
            if (_stricmp("", recvBuf) != 0) {
                MESSAGE_MAX_LENGTH = sizeof(recvBuf) + 1008;
                BYTE* source = (BYTE*)malloc(MESSAGE_MAX_LENGTH), * des = (BYTE*)malloc(MESSAGE_MAX_LENGTH);
                memset(des, 0, MESSAGE_MAX_LENGTH);
                memset(source, 0, MESSAGE_MAX_LENGTH);
                memcpy_s(source, MESSAGE_MAX_LENGTH, recvBuf, strlen(recvBuf));
                DecryptText(source, des, token2);
                memcpy_s(recvBuf, strlen(recvBuf), des, strlen(recvBuf));
                free(source);
                free(des);
            }
            else {
                strcat_s(recvBuf, "PrivateChat0.0.3 New EE2E Conversation\nYour information won't show in the network level\n");
            }
            
        }
        std::vector<std::string> sList;
        splitStr(recvBuf, "\n", sList);
        int index = 0;
        for each (std::string var in sList)
        {
            m_MessageList.InsertString(index,A2W(var.data()));
            index++;
        }
        int count = 0;
        count = m_MessageList.GetCount();

        m_MessageList.SetCurSel(count - 1);
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
    CString token;
    m_EE2EToken.GetWindowTextW(token);
    if (token.IsEmpty()) {
        SendText.Format("Account:%-11sMessage:%s", W2A(username.GetString()), MessageText);
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
    else {
        CString GetText = L"Get:";
        GetText.Append(username);
        if (SecureTcpConnect(result->ai_addr, result->ai_addrlen, L"PrivateChat", NULL, 0, W2A(GetText.GetString()), recvBuf) == 0) {
            // MessageBox(L"连接成功");
            MESSAGE_MAX_LENGTH = sizeof(recvBuf) + 1008;
            BYTE* source = (BYTE*)malloc(MESSAGE_MAX_LENGTH+10), * des = (BYTE*)malloc(MESSAGE_MAX_LENGTH+10);
            if (_stricmp("", recvBuf) == 0) {
                strcat_s(recvBuf, "PrivateChat0.0.3 New EE2E Conversation\nYour information won't show in the network level\n");
            }
            else {
                
                memset(des, 0, MESSAGE_MAX_LENGTH);
                memset(source, 0, MESSAGE_MAX_LENGTH);
                memcpy_s(source, MESSAGE_MAX_LENGTH, recvBuf, strlen(recvBuf));
                DecryptText(source, des, token);
                memcpy_s(recvBuf, strlen(recvBuf), des, strlen(recvBuf));
            }

            CStringA message;
            message.Format("%s%s:%s\n", recvBuf, W2A(username.GetString()), MessageText);
            memset(des, 0, MESSAGE_MAX_LENGTH+10);
            memset(source, 0, MESSAGE_MAX_LENGTH+10);
            memcpy_s(source, MESSAGE_MAX_LENGTH+10, message.GetString(), strlen(message.GetString()));
            EncryptText(source, des, token);
            char *sendBuf = (char*)malloc(MESSAGE_MAX_LENGTH+10);
            memcpy_s(sendBuf, MESSAGE_MAX_LENGTH + 10, des, MESSAGE_MAX_LENGTH+10);
            free(source);
            free(des);
            SendText.Format("Account:%-11sMessageEE2E:%s", W2A(username.GetString()), sendBuf);
            free(sendBuf);
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
        CString token2;
        m_EE2EToken.GetWindowTextW(token2);
        if (!token2.IsEmpty()) {
            if (_stricmp("", recvBuf) != 0) {
                MESSAGE_MAX_LENGTH = sizeof(recvBuf) + 1008;
                BYTE* source = (BYTE*)malloc(MESSAGE_MAX_LENGTH), * des = (BYTE*)malloc(MESSAGE_MAX_LENGTH);
                memset(des, 0, MESSAGE_MAX_LENGTH);
                memset(source, 0, MESSAGE_MAX_LENGTH);
                memcpy_s(source, MESSAGE_MAX_LENGTH, recvBuf, strlen(recvBuf));
                DecryptText(source, des, token2);
                memcpy_s(recvBuf, strlen(recvBuf), des, strlen(recvBuf));
                free(source);
                free(des);
            }
            else {
                strcat_s(recvBuf, "PrivateChat0.0.3 New EE2E Conversation\nYour information won't show in the network level\n");
            }
        }

        std::vector<std::string> sList;
        splitStr(recvBuf, "\n", sList);
        int index = 0;
        for each (std::string var in sList)
        {
            m_MessageList.InsertString(index, A2W(var.data()));
            index++;
        }
        int count = 0;
        count = m_MessageList.GetCount();

        m_MessageList.SetCurSel(count - 1);
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
/*
    MESSAGE_MAX_LENGTH = 0+1008;
    BYTE *source = (BYTE*)malloc(MESSAGE_MAX_LENGTH), * des = (BYTE*)malloc(MESSAGE_MAX_LENGTH);
    memset(des, 0, MESSAGE_MAX_LENGTH);
    memcpy_s(source, MESSAGE_MAX_LENGTH, "1.We rise together as our destniy unfolds~", sizeof("1.We rise together as our destniy unfolds~"));
    EncryptText(source, des, L"消灭人类暴政，世界属于三体qwq");
    memset(source, 0, MESSAGE_MAX_LENGTH);
    DecryptText(des, source, L"消灭人类暴政，世界属于三体qwq");

    USES_CONVERSION;
    char pszTemp[25600] = { 0 };
    memcpy_s(pszTemp, 25600, source, MESSAGE_MAX_LENGTH);
    free(source);
    free(des);
    MessageBoxA(NULL,pszTemp,"",MB_OK);
*/

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
