#include <Windows.h>
#include <bcrypt.h>
#include <intrin.h>

#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")

namespace {

std::string ReadMachineGuid() {
    HKEY key = nullptr;
    const REGSAM accessModes[] = {
        KEY_READ | KEY_WOW64_64KEY,
        KEY_READ | KEY_WOW64_32KEY,
        KEY_READ,
    };

    for (const REGSAM access : accessModes) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Cryptography", 0, access, &key) != ERROR_SUCCESS) {
            continue;
        }

        DWORD type = 0;
        DWORD size = 0;
        const LONG queryResult = RegQueryValueExA(key, "MachineGuid", nullptr, &type,
            nullptr, &size);
        if (queryResult == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ) &&
            size > 0 && size <= 512) {
            std::string value(size, '\0');
            if (RegQueryValueExA(key, "MachineGuid", nullptr, &type,
                reinterpret_cast<LPBYTE>(value.data()), &size) == ERROR_SUCCESS) {
                RegCloseKey(key);
                while (!value.empty() && value.back() == '\0') value.pop_back();
                return value;
            }
        }
        RegCloseKey(key);
    }
    return {};
}

std::string CpuMaterial() {
    int registers[4] = { 0, 0, 0, 0 };
    std::ostringstream output;

    __cpuid(registers, 0);
    const unsigned int highestBasicLeaf = static_cast<unsigned int>(registers[0]);
    output << std::hex << std::uppercase;
    if (highestBasicLeaf >= 1) {
        __cpuid(registers, 1);
        output << registers[0] << ':' << registers[2] << ':' << registers[3];
    }

    __cpuid(registers, 0x80000000);
    const unsigned int highestExtendedLeaf = static_cast<unsigned int>(registers[0]);
    if (highestExtendedLeaf >= 0x80000004) {
        for (unsigned int leaf = 0x80000002; leaf <= 0x80000004; ++leaf) {
            __cpuid(registers, static_cast<int>(leaf));
            output << ':' << registers[0] << ':' << registers[1]
                << ':' << registers[2] << ':' << registers[3];
        }
    }
    return output.str();
}

std::string SystemDriveRoot() {
    char windowsDirectory[MAX_PATH] = { 0 };
    const UINT length = GetWindowsDirectoryA(windowsDirectory, MAX_PATH);
    if (length >= 3 && windowsDirectory[1] == ':') {
        return std::string(windowsDirectory, windowsDirectory + 3);
    }
    return "C:\\";
}

std::string StableHwidMaterial() {
    std::ostringstream material;
    material << "id7mgh-hwid-v2|";

    const std::string machineGuid = ReadMachineGuid();
    if (!machineGuid.empty()) material << "machine=" << machineGuid << '|';

    char computerName[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
    DWORD computerNameLength = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameA(computerName, &computerNameLength)) {
        material << "computer=" << computerName << '|';
    }

    DWORD volumeSerial = 0;
    const std::string driveRoot = SystemDriveRoot();
    if (GetVolumeInformationA(driveRoot.c_str(), nullptr, 0, &volumeSerial,
        nullptr, nullptr, nullptr, 0)) {
        material << "volume=" << std::hex << volumeSerial << '|';
    }

    material << "cpu=" << CpuMaterial();
    return material.str();
}

std::string Sha256Hex(const std::string& input) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectLength = 0;
    DWORD hashLength = 0;
    DWORD resultLength = 0;
    std::string result;

    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM,
        nullptr, 0) != 0) return {};
    if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &resultLength, 0) != 0 ||
        BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
        reinterpret_cast<PUCHAR>(&hashLength), sizeof(hashLength), &resultLength, 0) != 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return {};
    }

    std::vector<BYTE> hashObject(objectLength);
    std::vector<BYTE> digest(hashLength);
    if (BCryptCreateHash(algorithm, &hash, hashObject.data(), objectLength,
        nullptr, 0, 0) == 0 &&
        BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),
        static_cast<ULONG>(input.size()), 0) == 0 &&
        BCryptFinishHash(hash, digest.data(), hashLength, 0) == 0) {
        std::ostringstream output;
        output << std::hex;
        for (const BYTE byte : digest) {
            output.width(2);
            output.fill('0');
            output << static_cast<unsigned int>(byte);
        }
        result = output.str();
    }

    if (hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return result;
}

std::uint64_t FallbackDigest(const std::string& value) {
    std::uint64_t digest = 14695981039346656037ull;
    for (const unsigned char character : value) {
        digest ^= character;
        digest *= 1099511628211ull;
    }
    return digest;
}

std::uint64_t DigestPrefixToInteger(const std::string& digest,
    const std::string& material) {
    std::uint64_t value = 0;
    size_t digits = 0;
    for (const char character : digest) {
        unsigned int nibble = 0;
        if (character >= '0' && character <= '9') nibble = character - '0';
        else if (character >= 'a' && character <= 'f') nibble = character - 'a' + 10;
        else if (character >= 'A' && character <= 'F') nibble = character - 'A' + 10;
        else continue;
        value = (value << 4) | nibble;
        if (++digits == 16) return value;
    }
    return FallbackDigest(material);
}

std::string GenerateShortHwid() {
    const std::string material = StableHwidMaterial();
    std::uint64_t value = DigestPrefixToInteger(Sha256Hex(material), material);
    static constexpr char alphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::string shortHwid(7, alphabet[0]);
    for (int index = static_cast<int>(shortHwid.size()) - 1; index >= 0; --index) {
        shortHwid[static_cast<size_t>(index)] = alphabet[value % 36];
        value /= 36;
    }
    return shortHwid;
}

bool CopyUnicodeText(const std::wstring& value) {
    if (!OpenClipboard(nullptr)) return false;
    EmptyClipboard();

    const SIZE_T bytes = (value.size() + 1) * sizeof(wchar_t);
    HGLOBAL clipboardBuffer = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!clipboardBuffer) {
        CloseClipboard();
        return false;
    }

    void* destination = GlobalLock(clipboardBuffer);
    if (!destination) {
        GlobalFree(clipboardBuffer);
        CloseClipboard();
        return false;
    }
    CopyMemory(destination, value.c_str(), bytes);
    GlobalUnlock(clipboardBuffer);

    if (!SetClipboardData(CF_UNICODETEXT, clipboardBuffer)) {
        GlobalFree(clipboardBuffer);
        CloseClipboard();
        return false;
    }
    CloseClipboard();
    return true;
}

enum PopupControlId : int {
    kPopupOkButton = 1001,
};

struct PopupState {
    bool copied = false;
    HWND okButton = nullptr;
};

HBRUSH PopupBackgroundBrush() {
    static HBRUSH brush = CreateSolidBrush(RGB(15, 18, 26));
    return brush;
}

HBRUSH PopupButtonBrush() {
    static HBRUSH brush = CreateSolidBrush(RGB(0, 102, 204));
    return brush;
}

HFONT PopupFont(int height, bool bold) {
    return CreateFontW(height, 0, 0, 0, bold ? FW_SEMIBOLD : FW_NORMAL,
        FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE,
        L"Segoe UI");
}

void DrawPopupText(HDC deviceContext, const wchar_t* text, RECT rect,
    HFONT font, COLORREF color, UINT format) {
    const HGDIOBJ oldFont = SelectObject(deviceContext, font);
    SetBkMode(deviceContext, TRANSPARENT);
    SetTextColor(deviceContext, color);
    DrawTextW(deviceContext, text, -1, &rect, format);
    SelectObject(deviceContext, oldFont);
}

LRESULT CALLBACK PopupWndProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<PopupState*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
        state = static_cast<PopupState*>(create->lpCreateParams);
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
    }

    switch (message) {
    case WM_CREATE:
        if (!state) return -1;
        state->okButton = CreateWindowExW(0, L"BUTTON", L"OK",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW | WS_TABSTOP,
            0, 0, 0, 0, window,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(kPopupOkButton)),
            GetModuleHandleW(nullptr), nullptr);
        return 0;

    case WM_ERASEBKGND:
        return 1;

    case WM_SIZE:
        if (state && state->okButton) {
            const int width = LOWORD(lParam);
            const int height = HIWORD(lParam);
            MoveWindow(state->okButton, width - 102, height - 46, 78, 30, TRUE);
        }
        return 0;

    case WM_CTLCOLORBTN:
        SetTextColor(reinterpret_cast<HDC>(wParam), RGB(255, 255, 255));
        SetBkColor(reinterpret_cast<HDC>(wParam), RGB(0, 102, 204));
        return reinterpret_cast<LRESULT>(PopupButtonBrush());

    case WM_DRAWITEM: {
        const auto* draw = reinterpret_cast<const DRAWITEMSTRUCT*>(lParam);
        if (!draw || draw->CtlID != kPopupOkButton) break;
        FillRect(draw->hDC, &draw->rcItem, PopupButtonBrush());
        RECT textRect = draw->rcItem;
        DrawPopupText(draw->hDC, L"OK", textRect, PopupFont(-14, true),
            RGB(255, 255, 255), DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        return TRUE;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == kPopupOkButton && HIWORD(wParam) == BN_CLICKED) {
            DestroyWindow(window);
            return 0;
        }
        break;

    case WM_LBUTTONDOWN:
        if (HIWORD(lParam) < 38) {
            ReleaseCapture();
            SendMessageW(window, WM_NCLBUTTONDOWN, HTCAPTION, 0);
            return 0;
        }
        break;

    case WM_PAINT: {
        PAINTSTRUCT paint{};
        HDC deviceContext = BeginPaint(window, &paint);
        RECT client{};
        GetClientRect(window, &client);
        FillRect(deviceContext, &client, PopupBackgroundBrush());

        RECT title = { 18, 8, client.right - 18, 32 };
        DrawPopupText(deviceContext, L"id7mgh client", title, PopupFont(-17, true),
            RGB(235, 241, 250), DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        RECT accent = { 18, 38, client.right - 18, 40 };
        FillRect(deviceContext, &accent, PopupButtonBrush());

        RECT messageRect = { 18, 61, client.right - 18, 105 };
        DrawPopupText(deviceContext,
            state && state->copied ? L"Your HWID is copied" : L"Could not copy your HWID",
            messageRect, PopupFont(-19, false),
            state && state->copied ? RGB(235, 241, 250) : RGB(255, 130, 130),
            DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        EndPaint(window, &paint);
        return 0;
    }

    case WM_CLOSE:
        DestroyWindow(window);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window, message, wParam, lParam);
}

int ShowPopup(bool copied) {
    static constexpr wchar_t kWindowClass[] = L"Id7mghHwidCheckerPopup";
    HINSTANCE instance = GetModuleHandleW(nullptr);
    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.hInstance = instance;
    windowClass.lpfnWndProc = PopupWndProc;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = PopupBackgroundBrush();
    windowClass.lpszClassName = kWindowClass;
    if (!RegisterClassExW(&windowClass) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return 1;
    }

    PopupState state;
    state.copied = copied;
    HWND window = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_DLGMODALFRAME,
        kWindowClass, L"id7mgh client", WS_POPUP | WS_BORDER,
        CW_USEDEFAULT, CW_USEDEFAULT, 420, 170,
        nullptr, nullptr, instance, &state);
    if (!window) return 1;

    RECT workArea{};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &workArea, 0);
    const int width = 420;
    const int height = 170;
    const int x = workArea.left + ((workArea.right - workArea.left) - width) / 2;
    const int y = workArea.top + ((workArea.bottom - workArea.top) - height) / 2;
    SetWindowPos(window, HWND_TOP, x, y, width, height, SWP_SHOWWINDOW);
    UpdateWindow(window);
    if (state.okButton) SetFocus(state.okButton);

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return copied ? 0 : 1;
}

} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    std::string shortHwid;
    try {
        shortHwid = GenerateShortHwid();
    }
    catch (...) {
        shortHwid.clear();
    }

    const bool copied = !shortHwid.empty() &&
        CopyUnicodeText(std::wstring(shortHwid.begin(), shortHwid.end()));
    return ShowPopup(copied);
}
