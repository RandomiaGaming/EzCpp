// Approved 10/26/2024

#include "EzError.h"
#include <Windows.h>
#include <comdef.h>
#include <sstream>
#include <iomanip>

static constexpr LPCWSTR ErrorLogFilePath = L"C:\\ProgramData\\EzLog.txt";

static enum class ErrorSource : BYTE {
	CustomString = 0,
	DosErrorCode = 1,
	HResult = 2,
	NTStatus = 3,
};
static LPWSTR ConstructMessage(LPCWSTR errorMessage, ErrorSource sourceType = ErrorSource::CustomString, void* source = NULL, LPCSTR file = NULL, UINT32 line = 0xFFFFFFFF) noexcept {
	try {
		std::wostringstream messageStream = { };

		// Append file name
		if (file == NULL) {
			messageStream << L"ERROR in UnknownFile";
		}
		else {
			LPCSTR fileNameOnly = file + lstrlenA(file);
			while (fileNameOnly >= file && *fileNameOnly != '\\' && *fileNameOnly != '/') {
				fileNameOnly--;
			}
			messageStream << L"ERROR in " << (fileNameOnly + 1);
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
		if (sourceType == ErrorSource::DosErrorCode) {
			messageStream << L" from DOS error code 0x" << std::hex << std::setw(sizeof(DWORD) * 2) << std::setfill(L'0')
				<< *reinterpret_cast<DWORD*>(source)
				<< std::setfill(L' ') << std::setw(0) << std::dec;
		}
		else if (sourceType == ErrorSource::HResult) {
			messageStream << L" from HResult 0x" << std::hex << std::setw(sizeof(HRESULT) * 2) << std::setfill(L'0')
				<< *reinterpret_cast<HRESULT*>(source)
				<< std::setfill(L' ') << std::setw(0) << std::dec;
		}
		else if (sourceType == ErrorSource::NTStatus) {
			messageStream << L" from NTStatus 0x" << std::hex << std::setw(sizeof(NTSTATUS) * 2) << std::setfill(L'0')
				<< *reinterpret_cast<NTSTATUS*>(source)
				<< std::setfill(L' ') << std::setw(0) << std::dec;
		}

		// Append error message
		messageStream << L": " << errorMessage;
		UINT32 errorMessageLength = lstrlenW(errorMessage);
		if (errorMessageLength >= 2) {
			LPCWSTR lastTwoChars = errorMessage + (errorMessageLength - 2);
			if (lastTwoChars[0] != L'\r' || lastTwoChars[1] != L'\n') {
				messageStream << L"\r\n";
			}
		}

		// Copy string and return
		std::wstring messageString = messageStream.str();
		LPWSTR message = new WCHAR[messageString.size() + 1];
		lstrcpyW(message, messageString.c_str());
		return message;
	}
	catch (...) {
		return NULL;
	}
}

EzError::EzError(DWORD errorCode, LPCSTR file, UINT32 line) noexcept {
	try {
		_errorCode = errorCode;
		_hr = 0;
		_nt = 0;

		LPWSTR systemMessage = NULL;
		DWORD systemMessageLength = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, _errorCode, 0, reinterpret_cast<LPWSTR>(&systemMessage), 0, NULL);

		_message = ConstructMessage(systemMessage, ErrorSource::DosErrorCode, &_errorCode, file, line);

		LocalFree(systemMessage);
	}
	catch (...) {}
}
EzError::EzError(HRESULT hr, LPCSTR file, UINT32 line) noexcept {
	try {
		_errorCode = 0;
		_hr = hr;
		_nt = 0;

		LPWSTR systemMessage = NULL;
		DWORD systemMessageLength = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, _hr, 0, reinterpret_cast<LPWSTR>(&systemMessage), 0, NULL);

		if (systemMessageLength > 0) {
			_message = ConstructMessage(systemMessage, ErrorSource::HResult, &_hr, file, line);

			LocalFree(systemMessage);
		}
		else {
			_com_error comError(_hr);
			LPCWSTR comErrorMessage = comError.ErrorMessage();

			_message = ConstructMessage(comErrorMessage, ErrorSource::HResult, &_hr, file, line);
		}
	}
	catch (...) {}
}
EzError::EzError(NTSTATUS* pNt, LPCSTR file, UINT32 line) noexcept {
	try {
		_errorCode = 0;
		_nt = *pNt;
		_hr = HRESULT_FROM_NT(_nt);

		LPWSTR systemMessage = NULL;
		DWORD systemMessageLength = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, _hr, 0, reinterpret_cast<LPWSTR>(&systemMessage), 0, NULL);

		if (systemMessageLength > 0) {
			_message = ConstructMessage(systemMessage, ErrorSource::NTStatus, &_nt, file, line);

			LocalFree(systemMessage);
		}
		else {
			_com_error comError(_hr);
			LPCWSTR comErrorMessage = comError.ErrorMessage();

			_message = ConstructMessage(comErrorMessage, ErrorSource::NTStatus, &_nt, file, line);
		}
	}
	catch (...) {}
}
EzError::EzError(LPCSTR message, LPCSTR file, UINT32 line) noexcept {
	try {
		_errorCode = 0;
		_hr = 0;
		_nt = 0;

		UINT32 wideMessageLength = MultiByteToWideChar(CP_UTF8, 0, message, -1, NULL, 0);
		LPWSTR wideMessage = new WCHAR[wideMessageLength];
		MultiByteToWideChar(CP_UTF8, 0, message, -1, wideMessage, wideMessageLength);
		wideMessage[wideMessageLength - 1] = L'\0';

		_message = ConstructMessage(wideMessage, ErrorSource::CustomString, NULL, file, line);

		delete[] wideMessage;
	}
	catch (...) {}
}
EzError::EzError(LPCWSTR message, LPCSTR file, UINT32 line) noexcept {
	try {
		_errorCode = 0;
		_hr = 0;
		_nt = 0;

		_message = ConstructMessage(message, ErrorSource::CustomString, NULL, file, line);
	}
	catch (...) {}
}

EzError::EzError(const EzError& other) noexcept {
	_errorCode = other._errorCode;
	_hr = other._hr;
	_nt = other._nt;

	if (other._message != NULL) {
		size_t messageLength = lstrlenW(other._message) + 1;
		_message = new WCHAR[messageLength];
		lstrcpyW(_message, other._message);
	}
	else {
		_message = NULL;
	}
}
EzError& EzError::operator=(const EzError& other) noexcept {
	if (this != &other) {
		this->~EzError();

		_errorCode = other._errorCode;
		_hr = other._hr;
		_nt = other._nt;

		if (other._message != NULL) {
			size_t messageLength = lstrlenW(other._message) + 1;
			_message = new WCHAR[messageLength];
			lstrcpyW(_message, other._message);
		}
		else {
			_message = NULL;
		}
	}
	return *this;
}

void EzError::Print() const noexcept {
	try {
		HANDLE stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
		if (stdoutHandle == INVALID_HANDLE_VALUE) {
			// If this fails we need to give up
			goto printFailed;
		}

		CONSOLE_SCREEN_BUFFER_INFO consoleInfo = { };
		WORD savedAttributes = 0;
		if (!GetConsoleScreenBufferInfo(stdoutHandle, &consoleInfo)) {
			// Don't care about original color
		}
		else {
			savedAttributes = consoleInfo.wAttributes;
		}

		if (!SetConsoleTextAttribute(stdoutHandle, static_cast<WORD>(EzConsoleColor::Red))) {
			// Don't care about the color
		}

		int messageLength = lstrlenW(_message);
		if (messageLength == 0) {
			// If this fails assume the string is probably 64 characters long
			messageLength = 64;
		}

		DWORD charsWritten = 0;
		if (!WriteConsoleW(stdoutHandle, _message, messageLength, &charsWritten, NULL) || charsWritten != messageLength) {
			// Don't care if write fails or is a partial write
		}

		if (!SetConsoleTextAttribute(stdoutHandle, savedAttributes)) {
			// Don't care if restoring original color fails
		}
	}
	catch (...) {}

printFailed:
	try {
		// Try to open the log file
		// If we can't then create a new one
		// If that fails then try again without read access
		// If all else fails then just print the error don't write it to the log file.
		HANDLE logFile = CreateFileW(ErrorLogFilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (logFile == INVALID_HANDLE_VALUE) {
			logFile = CreateFileW(ErrorLogFilePath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			if (logFile == INVALID_HANDLE_VALUE) {
				goto writeFailed;
			}
		}

		LONGLONG fileSize = 0;
		if (!GetFileSizeEx(logFile, reinterpret_cast<PLARGE_INTEGER>(&fileSize))) {
			// Don't care just assume the file is 10 kilobytes.
			fileSize = 10240;
		}

		BYTE* fileContents = NULL;
		try {
			fileContents = new BYTE[fileSize];
		}
		catch (...) {
			// Don't care just write to the file only
			fileContents = NULL;
			fileSize = 0;
		}

		if (fileContents != NULL) {
			DWORD bytesRead = 0;
			if (!ReadFile(logFile, fileContents, fileSize, &bytesRead, NULL)) {
				// Don't care about failed reads
			}
			if (bytesRead != fileSize) {
				// If we could only read part of the file that's fine just be happy with what we got
				fileSize = bytesRead;
			}
		}

		// Move the file pointer to the beginning
		if (SetFilePointer(logFile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
			// If the pointer wont move then just write to where the pointer is now
			try {
				if (fileContents != NULL) {
					delete[] fileContents;
					fileContents = NULL;
				}
			}
			catch (...) {
				// Don't care if this fails just leak the memory
			}
			fileSize = 0;
		}

		int messageLength = lstrlenW(_message);
		if (messageLength == 0) {
			// If this fails assume the string is probably 64 characters long
			messageLength = 64;
		}

		DWORD bytesWrittenMessage = 0;
		if (!WriteFile(logFile, _message, messageLength * sizeof(WCHAR), &bytesWrittenMessage, NULL)) {
			// If we couldn't write to the file then give up
			if (!CloseHandle(logFile)) {
				// Don't care if the handle won't close
			}
			try {
				if (fileContents != NULL) {
					delete[] fileContents;
					fileContents = NULL;
				}
			}
			catch (...) {
				// Don't care if this fails just leak the memory
			}
			goto writeFailed;
		}
		if (bytesWrittenMessage != messageLength) {
			// Don't care if we only wrote half the message just be happy we wrote anything at all
		}

		DWORD bytesWrittenFile = 0;
		if (!WriteFile(logFile, fileContents, fileSize, &bytesWrittenFile, NULL) || bytesWrittenFile != fileSize) {
			// Don't care if we couldn't write the file contents
		}

		if (!CloseHandle(logFile)) {
			// Don't care if the handle won't close
		}

		try {
			if (fileContents != NULL) {
				delete[] fileContents;
				fileContents = NULL;
			}
		}
		catch (...) {
			// Don't care if this fails just leak the memory
		}
	}
	catch (...) {}
writeFailed:
	return;
}
EzError::~EzError() noexcept {
	try {
		if (_message != NULL) {
			try {
				delete[] _message;
			}
			catch (...) {}
			_message = NULL;
		}

		_errorCode = 0;
		_hr = 0;
		_nt = 0;
	}
	catch (...) {}
}

LPCWSTR EzError::GetMessage() const noexcept {
	try {
		return _message;
	}
	catch (...) {
		return NULL;
	}
}
DWORD EzError::GetErrorCode() const noexcept {
	try {
		return _errorCode;
	}
	catch (...) {
		return 0;
	}
}
HRESULT EzError::GetHR() const noexcept {
	try {
		return _hr;
	}
	catch (...) {
		return 0;
	}
}
NTSTATUS EzError::GetNT() const noexcept {
	try {
		return _nt;
	}
	catch (...) {
		return 0;
	}
}

void EzError::ThrowFromCode(DWORD errorCode, LPCSTR file, UINT32 line) noexcept {
	throw EzError(errorCode, file, line);
}
void EzError::ThrowFromHR(HRESULT hr, LPCSTR file, UINT32 line) noexcept {
	throw EzError(hr, file, line);
}
void EzError::ThrowFromNT(NTSTATUS nt, LPCSTR file, UINT32 line) noexcept {
	throw EzError(nt, file, line);
}