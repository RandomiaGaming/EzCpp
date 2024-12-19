// Approved 11/14/2024

#include "EzCore.h"
#include <Windows.h>
#include <comdef.h>
#include <sstream>
#include <iomanip>

LPWSTR EzError::ConstructMessage(LPCWSTR text, LPCWSTR source, LPCSTR file, UINT32 line) noexcept {
	// Try here incase memory allocations from ostringstream fail
	try {
		std::wostringstream messageStream = { };

		// Append file name
		try {
			if (file == NULL) {
				throw NULL;
			}
			int fileLength = lstrlenA(file);
			LPCSTR fileNameOnly = file + fileLength;
			while (fileNameOnly >= file && *fileNameOnly != '\\' && *fileNameOnly != '/') {
				fileNameOnly--;
			}
			messageStream << L"ERROR in " << (fileNameOnly + 1);
		}
		catch (...) {
			messageStream << L"ERROR in UnknownFile";
		}

		// Append line number
		if (line == 0xFFFFFFFF) {
			messageStream << L" at UnknownLine";
		}
		else {
			messageStream << L" at line " << line;
		}

		// Append current time
		SYSTEMTIME timeNow = { };
		GetLocalTime(&timeNow);
		if (timeNow.wHour == 0) {
			messageStream << L" at 12:" << timeNow.wMinute << L":" << timeNow.wSecond << L"am";
		}
		else if (timeNow.wHour < 12) {
			messageStream << L" at " << (timeNow.wHour % 12) << L":" << timeNow.wMinute << L":" << timeNow.wSecond << L"am";
		}
		else {
			messageStream << L" at " << (timeNow.wHour % 12) << L":" << timeNow.wMinute << L":" << timeNow.wSecond << L"pm";
		}
		messageStream << L" on " << timeNow.wMonth << L"/" << timeNow.wDay << L"/" << timeNow.wYear;

		// Append error source
		try {
			if (source == NULL) {
				throw NULL;
			}
			messageStream << L" from " << source;
		}
		catch (...) {}

		// Append error message
		try {
			if (text == NULL) {
				throw NULL;
			}
			messageStream << L": " << text;
			int textLength = lstrlenW(text);
			if (textLength >= 2) {
				LPCWSTR lastTwoChars = text + (textLength - 2);
				if (lastTwoChars[0] != L'\r' || lastTwoChars[1] != L'\n') {
					messageStream << L"\r\n";
				}
			}
		}
		catch (...) {
			messageStream << L": UnknownMessage\r\n";
		}

		// Copy string and return
		std::wstring messageString = messageStream.str();
		LPWSTR output = EzAllocArray<WCHAR>(messageString.size() + 1);
		if (output == NULL) {
			throw NULL;
		}
		lstrcpyW(output, messageString.c_str());
		return output;
	}
	catch (...) {
		return NULL;
	}
}
void EzError::PrintToConsole(LPCWSTR message) noexcept {
	if (message == NULL) {
		return;
	}
	int messageLength = 0;
	try {
		messageLength = lstrlenW(message);
	}
	catch (...) {
		return;
	}

	HANDLE stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	if (stdoutHandle == INVALID_HANDLE_VALUE) {
		return;
	}

	BOOL restoreAttributes = TRUE;
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo = { };
	if (!GetConsoleScreenBufferInfo(stdoutHandle, &consoleInfo)) {
		restoreAttributes = FALSE;
	}

	if (!SetConsoleTextAttribute(stdoutHandle, static_cast<WORD>(FOREGROUND_RED | FOREGROUND_INTENSITY))) {
		restoreAttributes = FALSE;
	}

	DWORD CharsWritten = 0;
	WriteConsoleW(stdoutHandle, message, messageLength, &CharsWritten, NULL);

	if (!restoreAttributes) {
		SetConsoleTextAttribute(stdoutHandle, consoleInfo.wAttributes);
	}
}
void EzError::PrintToLogFile(LPCWSTR message) noexcept {
	if (message == NULL) {
		return;
	}
	int messageLength = 0;
	try {
		messageLength = lstrlenW(message);
	}
	catch (...) {
		return;
	}

	HANDLE logFile = CreateFileW(EzError::ErrorLogFilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (logFile == INVALID_HANDLE_VALUE) {
		logFile = CreateFileW(ErrorLogFilePath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	}
	if (logFile == INVALID_HANDLE_VALUE) {
		return;
	}

	LONGLONG fileSize = 0;
	BYTE* fileContents = NULL;
	try {
		if (!GetFileSizeEx(logFile, reinterpret_cast<PLARGE_INTEGER>(&fileSize))) {
			throw NULL;
		}

		fileContents = EzAllocArray<BYTE>(fileSize);

		DWORD bytesRead = 0;
		if (!ReadFile(logFile, fileContents, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
			throw NULL;
		}
	}
	catch (...) {
		fileSize = 0;
		EzFree(&fileContents);
	}

	SetFilePointer(logFile, 0, NULL, FILE_BEGIN);

	DWORD bytesWrittenMessage = 0;
	WriteFile(logFile, message, messageLength * sizeof(WCHAR), &bytesWrittenMessage, NULL);

	if (fileContents != NULL) {
		DWORD bytesWrittenFileContents = 0;
		WriteFile(logFile, fileContents, fileSize, &bytesWrittenFileContents, NULL);
	}

	CloseHandle(logFile);

	EzFree(&fileContents);
}

EzError::EzError(LPWSTR message, DWORD code, HRESULT hr, NTSTATUS nt, DWORD se) noexcept {
	_message = message;
	_code = code;
	_hr = hr;
	_nt = nt;
	_se = se;
}
EzError::~EzError() noexcept {
	EzFree(&_message);

	_code = 0;
	_hr = 0;
	_nt = 0;
	_se = 0;
}
EzError::EzError(const EzError& other) noexcept {
	try {
		if (other._message == NULL) {
			throw NULL;
		}
		int messageLength = lstrlenW(other._message) + 1;
		_message = EzAllocArray<WCHAR>(messageLength);
		if (_message == NULL) {
			throw NULL;
		}
		lstrcpyW(_message, other._message);
	}
	catch (...) {
		_message = NULL;
	}

	_code = other._code;
	_hr = other._hr;
	_nt = other._nt;
	_se = other._se;
}
EzError& EzError::operator=(const EzError& other) noexcept {
	if (this == &other) {
		return *this;
	}

	EzFree(&_message);

	try {
		if (other._message == NULL) {
			throw NULL;
		}
		int messageLength = lstrlenW(other._message) + 1;
		_message = EzAllocArray<WCHAR>(messageLength);
		if (_message == NULL) {
			throw NULL;
		}
		lstrcpyW(_message, other._message);
	}
	catch (...) {
		_message = NULL;
	}

	_code = other._code;
	_hr = other._hr;
	_nt = other._nt;
	_se = other._se;

	return *this;
}

void EzError::Print() const noexcept {
	PrintToConsole(_message);
	PrintToLogFile(_message);
}
LPCWSTR EzError::What() const noexcept {
	return _message;
}
DWORD EzError::GetCode() const noexcept {
	return _code;
}
HRESULT EzError::GetHR() const noexcept {
	return _hr;
}
NTSTATUS EzError::GetNT() const noexcept {
	return _nt;
}
DWORD EzError::GetSE() const noexcept {
	return _se;
}

EzError EzError::FromCode(DWORD code, LPCSTR file, UINT32 line) noexcept {
	LPWSTR systemMessage = NULL;
	if (FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER, NULL, code, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), reinterpret_cast<LPWSTR>(&systemMessage), 0, NULL) == 0) {
		systemMessage = NULL;
	}

	LPWSTR source = NULL;
	try {
		std::wostringstream sourceStream = { };
		sourceStream << L"error code 0x" << std::hex << std::setw(sizeof(DWORD) * sizeof(WCHAR)) << std::setfill(L'0') << code << std::setfill(L' ') << std::setw(0) << std::dec;
		std::wstring sourceString = sourceStream.str();
		source = EzAllocArray<WCHAR>(sourceString.size() + 1);
		if (source == NULL) {
			throw NULL;
		}
		lstrcpyW(source, sourceString.c_str());
	}
	catch (...) {
		source = NULL;
	}

	LPWSTR message = ConstructMessage(systemMessage, source, file, line);

	EzLocalFree(&systemMessage);
	EzFree(&source);

	return EzError::EzError(message, code, 0, 0, 0);
}
EzError EzError::FromHR(HRESULT hr, LPCSTR file, UINT32 line) noexcept {
	LPWSTR systemMessage = NULL;
	if (FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER, NULL, hr, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), reinterpret_cast<LPWSTR>(&systemMessage), 0, NULL) == 0) {
		systemMessage = NULL;
	}

	LPCWSTR comMessage = NULL;
	if (systemMessage == NULL) {
		_com_error comError(hr);
		comMessage = comError.ErrorMessage();
	}

	LPWSTR source = NULL;
	try {
		std::wostringstream sourceStream = { };
		sourceStream << L"HRESULT 0x" << std::hex << std::setw(sizeof(HRESULT) * sizeof(WCHAR)) << std::setfill(L'0') << hr << std::setfill(L' ') << std::setw(0) << std::dec;
		std::wstring sourceString = sourceStream.str();
		source = EzAllocArray<WCHAR>(sourceString.size() + 1);
		if (source == NULL) {
			throw NULL;
		}
		lstrcpyW(source, sourceString.c_str());
	}
	catch (...) {
		source = NULL;
	}

	LPWSTR message = NULL;
	if (systemMessage != NULL) {
		message = ConstructMessage(systemMessage, source, file, line);
	}
	else if (comMessage != NULL) {
		message = ConstructMessage(comMessage, source, file, line);
	}
	else {
		message = ConstructMessage(NULL, source, file, line);
	}

	EzLocalFree(&systemMessage);
	comMessage = NULL;
	EzFree(&source);

	return EzError::EzError(message, 0, hr, 0, 0);
}
EzError EzError::FromNT(NTSTATUS nt, LPCSTR file, UINT32 line) noexcept {
	LPWSTR systemMessage = NULL;
	if (FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER, NULL, HRESULT_FROM_NT(nt), MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), reinterpret_cast<LPWSTR>(&systemMessage), 0, NULL) == 0) {
		systemMessage = NULL;
	}

	LPWSTR source = NULL;
	try {
		std::wostringstream sourceStream = { };
		sourceStream << L"NTSTATUS 0x" << std::hex << std::setw(sizeof(NTSTATUS) * sizeof(WCHAR)) << std::setfill(L'0') << nt << std::setfill(L' ') << std::setw(0) << std::dec;
		std::wstring sourceString = sourceStream.str();
		source = EzAllocArray<WCHAR>(sourceString.size() + 1);
		if (source == NULL) {
			throw NULL;
		}
		lstrcpyW(source, sourceString.c_str());
	}
	catch (...) {
		source = NULL;
	}

	LPWSTR message = ConstructMessage(systemMessage, source, file, line);

	EzLocalFree(&systemMessage);
	EzFree(&source);

	return EzError::EzError(message, 0, 0, nt, 0);
}
EzError EzError::FromSE(DWORD se, LPCSTR file, UINT32 line) noexcept {
	LPCWSTR seMessage = NULL;
	switch (se) {
		case EXCEPTION_ACCESS_VIOLATION: seMessage = L"Access violation/Segmentation fault"; break;
		case EXCEPTION_DATATYPE_MISALIGNMENT: seMessage = L"Data type misalignment"; break;
		case EXCEPTION_BREAKPOINT: seMessage = L"Breakpoint"; break;
		case EXCEPTION_SINGLE_STEP: seMessage = L"Single step"; break;
		case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: seMessage = L"Array bounds exceeded"; break;
		case EXCEPTION_FLT_DENORMAL_OPERAND: seMessage = L"Float denormal operand"; break;
		case EXCEPTION_FLT_DIVIDE_BY_ZERO: seMessage = L"Float divide by zero"; break;
		case EXCEPTION_FLT_INEXACT_RESULT: seMessage = L"Float inexact result"; break;
		case EXCEPTION_FLT_INVALID_OPERATION: seMessage = L"Float invalid operation"; break;
		case EXCEPTION_FLT_OVERFLOW: seMessage = L"Float overflow"; break;
		case EXCEPTION_FLT_STACK_CHECK: seMessage = L"Float stack check"; break;
		case EXCEPTION_FLT_UNDERFLOW: seMessage = L"Float underflow"; break;
		case EXCEPTION_INT_DIVIDE_BY_ZERO: seMessage = L"Integer divide by zero"; break;
		case EXCEPTION_INT_OVERFLOW: seMessage = L"Integer overflow"; break;
		case EXCEPTION_PRIV_INSTRUCTION: seMessage = L"Priv instruction"; break;
		case EXCEPTION_IN_PAGE_ERROR: seMessage = L"In page error"; break;
		case EXCEPTION_ILLEGAL_INSTRUCTION: seMessage = L"Illegal instruction"; break;
		case EXCEPTION_NONCONTINUABLE_EXCEPTION: seMessage = L"Non-continuable exception"; break;
		case EXCEPTION_STACK_OVERFLOW: seMessage = L"Stack overflow"; break;
		case EXCEPTION_INVALID_DISPOSITION: seMessage = L"Invalid disposition"; break;
		case EXCEPTION_GUARD_PAGE: seMessage = L"Guard page"; break;
		case EXCEPTION_INVALID_HANDLE: seMessage = L"Invalid handle"; break;
		case CONTROL_C_EXIT: seMessage = L"DLL initialization failure"; break;
		default: seMessage = L"Unknown structured exception"; break;
	}

	LPWSTR source = NULL;
	try {
		std::wostringstream sourceStream = { };
		sourceStream << L"structured exception 0x" << std::hex << std::setw(sizeof(DWORD) * sizeof(WCHAR)) << std::setfill(L'0') << se << std::setfill(L' ') << std::setw(0) << std::dec;
		std::wstring sourceString = sourceStream.str();
		source = EzAllocArray<WCHAR>(sourceString.size() + 1);
		if (source == NULL) {
			throw NULL;
		}
		lstrcpyW(source, sourceString.c_str());
	}
	catch (...) {
		source = NULL;
	}

	LPWSTR message = ConstructMessage(seMessage, source, file, line);

	EzFree(&source);

	return EzError::EzError(message, 0, 0, 0, se);
}
EzError EzError::FromException(std::exception ex, LPCSTR file, UINT32 line) noexcept {
	LPWSTR exMessage = NULL;
	try {
		std::wostringstream exMessageStream = { };
		exMessageStream << ex.what();
		std::wstring exMessageString = exMessageStream.str();
		exMessage = EzAllocArray<WCHAR>(exMessageString.size() + 1);
		if (exMessage == NULL) {
			throw NULL;
		}
		lstrcpyW(exMessage, exMessageString.c_str());
	}
	catch (...) {
		exMessage = NULL;
	}

	LPWSTR message = ConstructMessage(exMessage, NULL, file, line);

	return EzError::EzError(message, 0, 0, 0, 0);
}
EzError EzError::FromMessageA(LPCSTR message, LPCSTR file, UINT32 line) noexcept {
	LPWSTR wideMessage = NULL;
	try {
		std::wostringstream wideMessageStream = { };
		wideMessageStream << message;
		std::wstring wideMessageString = wideMessageStream.str();
		wideMessage = EzAllocArray<WCHAR>(wideMessageString.size() + 1);
		if (wideMessage == NULL) {
			throw NULL;
		}
		lstrcpyW(wideMessage, wideMessageString.c_str());
	}
	catch (...) {
		wideMessage = NULL;
	}

	LPWSTR constructedMessage = ConstructMessage(wideMessage, NULL, file, line);

	return EzError::EzError(constructedMessage, 0, 0, 0, 0);
}
EzError EzError::FromMessageW(LPCWSTR message, LPCSTR file, UINT32 line) noexcept {
	LPWSTR constructedMessage = ConstructMessage(message, NULL, file, line);

	return EzError::EzError(constructedMessage, 0, 0, 0, 0);
}

static void SE_Translator(unsigned int code, EXCEPTION_POINTERS* pExp) noexcept {
	DWORD exceptionCode = 0xFFFFFFFF;
	try {
		if (pExp == NULL) {
			throw NULL;
		}
		if (pExp->ExceptionRecord == NULL) {
			throw NULL;
		}
		exceptionCode = pExp->ExceptionRecord->ExceptionCode;
	}
	catch (...) {
		exceptionCode = 0xFFFFFFFF;
	}
	throw EzError::FromSE(exceptionCode, __FILE__, __LINE__);
}
void EzError::SetSEHandler() noexcept {
	_set_se_translator(SE_Translator);
}

void EzClose(HANDLE* handle) {
	if (handle == NULL) {
		throw EzError::FromMessageW(L"handle must be a valid pointer to a HANDLE.", __FILE__, __LINE__);
	}
	if (handle == INVALID_HANDLE_VALUE) {
		return;
	}
	if (!CloseHandle(handle)) {
		throw EzError::FromCode(GetLastError(), __FILE__, __LINE__);
	}
	*handle = INVALID_HANDLE_VALUE;
}