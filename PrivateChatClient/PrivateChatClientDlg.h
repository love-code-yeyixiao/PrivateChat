
// PrivateChatClientDlg.h: 头文件
//

#pragma once


// CPrivateChatClientDlg 对话框
class CPrivateChatClientDlg : public CDialogEx
{
// 构造
public:
	CPrivateChatClientDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_PRIVATECHATCLIENT_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedConnect();
	CIPAddressCtrl m_IPAddress;
	CListBox m_MessageList;
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedRefresh();
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton2();
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	afx_msg void OnBnClickedButton3();
	CEdit m_EE2EToken;
};
