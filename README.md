# Simple HWID Checker

This is a small public Windows utility. It calculates a stable seven-character HWID locally, copies the value to the clipboard, and shows a confirmation popup.

The checker does not open a console window or display a hardware report. The generated value is an opaque identifier such as `y8t3whd`.

Download the latest `HWIDChecker.exe` from [Releases](https://github.com/id7mgh/Simple-HWID-Checker/releases/latest), or build it from `main.cpp` with Visual Studio 2022 and the Windows SDK.

The source is available under the MIT license. Review it before running any executable.

## Build

Open a **x64 Native Tools Command Prompt for VS 2022** and run:

```text
cl /nologo /std:c++20 /O2 /EHsc /DUNICODE /D_UNICODE /DWIN32 /D_WINDOWS main.cpp /link /SUBSYSTEM:WINDOWS comsuppw.lib
```

## License

This project is licensed under the [MIT License](LICENSE).
