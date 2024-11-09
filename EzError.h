// Approved 10/29/2024

// NOTE
// To ensure SEH exceptions are thrown like normal C++ exceptions go to
// Solution > Properties > Configuration Properties > C/C++ > Code Generation > Enable C++ Exceptions
// and set it to "Yes with SEH Exceptions (/EHa)"

#pragma once
#include <Windows.h>
#include <exception>

class EzError final : public std::exception {
public:
	explicit EzError(DWORD errorCode, LPCSTR file = NULL, UINT32 line = 0xFFFFFFFF) noexcept;
	explicit EzError(HRESULT hr, LPCSTR file = NULL, UINT32 line = 0xFFFFFFFF) noexcept;
	explicit EzError(NTSTATUS* pNt, LPCSTR file = NULL, UINT32 line = 0xFFFFFFFF) noexcept;
	explicit EzError(LPCSTR message, LPCSTR file = NULL, UINT32 line = 0xFFFFFFFF) noexcept;
	~EzError() noexcept;
	void Print() const noexcept;
	LPCSTR what() const noexcept override;
	DWORD GetErrorCode() const noexcept;
	HRESULT GetHR() const noexcept;
	NTSTATUS GetNT() const noexcept;

	EzError(const EzError& other) noexcept;
	EzError& operator=(const EzError& other) noexcept;

	static void ThrowFromCode(DWORD errorCode, LPCSTR file = NULL, UINT32 line = 0xFFFFFFFF) noexcept;
	static void ThrowFromHR(HRESULT hr, LPCSTR file = NULL, UINT32 line = 0xFFFFFFFF) noexcept;
	static void ThrowFromNT(NTSTATUS nt, LPCSTR file = NULL, UINT32 line = 0xFFFFFFFF) noexcept;

private:
	LPSTR _message = NULL;
	DWORD _errorCode = 0;
	HRESULT _hr = 0;
	NTSTATUS _nt = 0;
};

enum class EzConsoleColor : WORD {
	Black = 0,
	DarkRed = FOREGROUND_RED,
	DarkGreen = FOREGROUND_GREEN,
	DarkBlue = FOREGROUND_BLUE,
	DarkYellow = FOREGROUND_RED | FOREGROUND_GREEN,
	DarkCyan = FOREGROUND_GREEN | FOREGROUND_BLUE,
	DarkMagenta = FOREGROUND_RED | FOREGROUND_BLUE,
	DarkGrey = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
	Grey = FOREGROUND_INTENSITY,
	Red = FOREGROUND_RED | FOREGROUND_INTENSITY,
	Green = FOREGROUND_GREEN | FOREGROUND_INTENSITY,
	Blue = FOREGROUND_BLUE | FOREGROUND_INTENSITY,
	Yellow = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
	Cyan = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
	Magenta = FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
	White = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY
};