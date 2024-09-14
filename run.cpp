#include <windows.h>
#include <iostream>
#include <shellapi.h>
#include <fstream>
#include <TlHelp32.h>

#define TRAY_ICON_MESSAGE (WM_USER + 1)

// Global Variables for Tray Icon
NOTIFYICONDATA trayIcon;
HMENU hMenu;
bool isStartup = false;
bool runningInTray = true;

void LogEvent(const std::string& message) {
    std::ofstream logFile("security_alerts.log", std::ios_base::app);
    logFile << message << std::endl;
    logFile.close();
}

bool DetectSuspiciousProcess(const std::string& processName) {
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(hProcessSnap, &processEntry)) {
        do {
            if (strcmp(processEntry.szExeFile, processName.c_str()) == 0) {
                CloseHandle(hProcessSnap);
                return true;
            }
        } while (Process32Next(hProcessSnap, &processEntry));
    }

    CloseHandle(hProcessSnap);
    return false;
}

void MonitorUSBDevices() {
    // Monitor for USB device insertion (simplified)
    DEV_BROADCAST_HDR broadcastHeader;
    PDEV_BROADCAST_DEVICEINTERFACE broadcastInterface;
    if (broadcastHeader.dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE) {
        broadcastInterface = (PDEV_BROADCAST_DEVICEINTERFACE)&broadcastHeader;
        LogEvent("USB Device Inserted: " + std::string(broadcastInterface->dbcc_name));
    }
}

void CheckForLaZagne() {
    if (DetectSuspiciousProcess("LaZagne.exe")) {
        MessageBox(NULL, "Suspicious Process Detected: LaZagne", "Security Alert", MB_ICONWARNING);
        LogEvent("LaZagne attack detected.");
    }
}

void ShowTrayMenu(HWND hwnd) {
    POINT p;
    GetCursorPos(&p);
    SetForegroundWindow(hwnd);
    TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, p.x, p.y, 0, hwnd, NULL);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case TRAY_ICON_MESSAGE:
            if (lParam == WM_RBUTTONUP) {
                ShowTrayMenu(hwnd);
            }
            break;
        case WM_COMMAND:
            if (LOWORD(wParam) == 1) {
                DestroyWindow(hwnd);
            }
            break;
        case WM_DESTROY:
            Shell_NotifyIcon(NIM_DELETE, &trayIcon);
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

void AddTrayIcon(HWND hwnd) {
    trayIcon.cbSize = sizeof(NOTIFYICONDATA);
    trayIcon.hWnd = hwnd;
    trayIcon.uID = 1;
    trayIcon.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    trayIcon.uCallbackMessage = TRAY_ICON_MESSAGE;
    trayIcon.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    strcpy_s(trayIcon.szTip, "Security Monitor");

    Shell_NotifyIcon(NIM_ADD, &trayIcon);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    HWND hwnd;
    MSG msg;
    WNDCLASS wc = { 0 };

    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "SecurityMonitor";
    RegisterClass(&wc);

    hwnd = CreateWindowEx(0, "SecurityMonitor", "Security Monitor", 0, CW_USEDEFAULT, CW_USEDEFAULT, 300, 200, NULL, NULL, hInstance, NULL);
    AddTrayIcon(hwnd);

    hMenu = CreatePopupMenu();
    AppendMenu(hMenu, MF_STRING, 1, "Exit");

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);

        // Continuous monitoring
        MonitorUSBDevices();
        CheckForLaZagne();
    }

    return msg.wParam;
}
