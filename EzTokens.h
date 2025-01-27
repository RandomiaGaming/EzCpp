// Approved 11/14/2024

#pragma once
#include <Windows.h>
#include <ostream>

/*
Token Information Classes:

TokenUser
TokenGroups
TokenPrivileges
TokenOwner
TokenPrimaryGroup
TokenDefaultDacl
TokenSource
TokenType
TokenImpersonationLevel
TokenStatistics
TokenRestrictedSids
TokenSessionId
TokenGroupsAndPrivileges
TokenSessionReference
TokenSandBoxInert
TokenAuditPolicy
TokenOrigin
TokenElevationType
TokenLinkedToken
TokenElevation
TokenHasRestrictions
TokenAccessInformation
TokenVirtualizationAllowed
TokenVirtualizationEnabled
TokenIntegrityLevel
TokenUIAccess
TokenMandatoryPolicy
TokenLogonSid
TokenIsAppContainer
TokenCapabilities
TokenAppContainerSid
TokenAppContainerNumber
TokenUserClaimAttributes
TokenDeviceClaimAttributes
TokenRestrictedUserClaimAttributes
TokenRestrictedDeviceClaimAttributes
TokenDeviceGroups
TokenRestrictedDeviceGroups
TokenSecurityAttributes
TokenIsRestricted
TokenProcessTrustLevel
TokenPrivateNameSpace
TokenSingletonAttributes
TokenBnoIsolation
TokenChildProcessFlags
TokenIsLessPrivilegedAppContainer
TokenIsSandboxed
TokenIsAppSilo
TokenLoggingInformation
MaxTokenInfoClass

*/

/*
Token Information Types:

SID_AND_ATTRIBUTES					       = TokenUser
TOKEN_GROUPS*						       = TokenGroups
TOKEN_PRIVILEGES*					       = TokenPrivileges
PSID								       = TokenOwner
PSID								       = TokenPrimaryGroup
TOKEN_DEFAULT_DACL*					       = TokenDefaultDacl
TOKEN_SOURCE						       = TokenSource
TOKEN_TYPE							       = TokenType
SECURITY_IMPERSONATION_LEVEL		       = TokenImpersonationLevel
TOKEN_STATISTICS					       = TokenStatistics
TOKEN_GROUPS*						       = TokenRestrictedSids
DWORD								       = TokenSessionId
TOKEN_GROUPS_AND_PRIVILEGES			       = TokenGroupsAndPrivileges
void								       = TokenSessionReference
BOOL								       = TokenSandBoxInert
void								       = TokenAuditPolicy
LUID								       = TokenOrigin
TOKEN_ELEVATION_TYPE				       = TokenElevationType
HANDLE								       = TokenLinkedToken
BOOL								       = TokenElevation
BOOL								       = TokenHasRestrictions
TOKEN_ACCESS_INFORMATION			       = TokenAccessInformation
BOOL								       = TokenVirtualizationAllowed
BOOL								       = TokenVirtualizationEnabled
SID_AND_ATTRIBUTES					       = TokenIntegrityLevel
BOOL								       = TokenUIAccess
DWORD								       = TokenMandatoryPolicy
TOKEN_GROUPS*						       = TokenLogonSid
BOOL								       = TokenIsAppContainer
TOKEN_GROUPS*						       = TokenCapabilities
PSID								       = TokenAppContainerSid
DWORD								       = TokenAppContainerNumber
CLAIM_SECURITY_ATTRIBUTES_INFORMATION*     = TokenUserClaimAttributes
CLAIM_SECURITY_ATTRIBUTES_INFORMATION*     = TokenDeviceClaimAttributes
void								       = TokenRestrictedUserClaimAttributes
void								       = TokenRestrictedDeviceClaimAttributes
TOKEN_GROUPS*						       = TokenDeviceGroups
TOKEN_GROUPS*						       = TokenRestrictedDeviceGroups
CLAIM_SECURITY_ATTRIBUTES_INFORMATION*     = TokenSecurityAttributes
BOOL								       = TokenIsRestricted
PSID								       = TokenProcessTrustLevel
BOOL								       = TokenPrivateNameSpace
CLAIM_SECURITY_ATTRIBUTES_INFORMATION*     = TokenSingletonAttributes
TOKEN_BNO_ISOLATION_INFORMATION		       = TokenBnoIsolation
void								       = TokenChildProcessFlags
void								       = TokenIsLessPrivilegedAppContainer
BOOL								       = TokenIsSandboxed
void								       = TokenIsAppSilo
void								       = TokenLoggingInformation
void								       = MaxTokenInfoClass

*/

// Getting info about tokens
SID_AND_ATTRIBUTES EzGetTokenUser(HANDLE token);
TOKEN_GROUPS* EzGetTokenGroups(HANDLE token);
TOKEN_PRIVILEGES* EzGetTokenPrivileges(HANDLE token);
PSID EzGetTokenOwner(HANDLE token);
PSID EzGetTokenPrimaryGroup(HANDLE token);
TOKEN_DEFAULT_DACL* EzGetTokenDefaultDacl(HANDLE token);
TOKEN_SOURCE EzGetTokenSource(HANDLE token);
TOKEN_TYPE EzGetTokenType(HANDLE token);
SECURITY_IMPERSONATION_LEVEL EzGetTokenImpersonationLevel(HANDLE token);
TOKEN_STATISTICS EzGetTokenStatistics(HANDLE token);
TOKEN_GROUPS* EzGetTokenRestrictedSids(HANDLE token);
DWORD EzGetTokenSessionId(HANDLE token);
TOKEN_GROUPS_AND_PRIVILEGES EzGetTokenGroupsAndPrivileges(HANDLE token);
void EzGetTokenSessionReference(HANDLE token);
BOOL EzGetTokenSandBoxInert(HANDLE token);
void EzGetTokenAuditPolicy(HANDLE token);
LUID EzGetTokenOrigin(HANDLE token);
TOKEN_ELEVATION_TYPE EzGetTokenElevationType(HANDLE token);
HANDLE EzGetTokenLinkedToken(HANDLE token);
BOOL EzGetTokenElevation(HANDLE token);
BOOL EzGetTokenHasRestrictions(HANDLE token);
TOKEN_ACCESS_INFORMATION EzGetTokenAccessInformation(HANDLE token);
BOOL EzGetTokenVirtualizationAllowed(HANDLE token);
BOOL EzGetTokenVirtualizationEnabled(HANDLE token);
SID_AND_ATTRIBUTES EzGetTokenIntegrityLevel(HANDLE token);
BOOL EzGetTokenUIAccess(HANDLE token);
DWORD EzGetTokenMandatoryPolicy(HANDLE token);
TOKEN_GROUPS* EzGetTokenLogonSid(HANDLE token);
BOOL EzGetTokenIsAppContainer(HANDLE token);
TOKEN_GROUPS* EzGetTokenCapabilities(HANDLE token);
PSID EzGetTokenAppContainerSid(HANDLE token);
DWORD EzGetTokenAppContainerNumber(HANDLE token);
CLAIM_SECURITY_ATTRIBUTES_INFORMATION* EzGetTokenUserClaimAttributes(HANDLE token);
CLAIM_SECURITY_ATTRIBUTES_INFORMATION* EzGetTokenDeviceClaimAttributes(HANDLE token);
void EzGetTokenRestrictedUserClaimAttributes(HANDLE token);
void EzGetTokenRestrictedDeviceClaimAttributes(HANDLE token);
TOKEN_GROUPS* EzGetTokenDeviceGroups(HANDLE token);
TOKEN_GROUPS* EzGetTokenRestrictedDeviceGroups(HANDLE token);
CLAIM_SECURITY_ATTRIBUTES_INFORMATION* EzGetTokenSecurityAttributes(HANDLE token);
BOOL EzGetTokenIsRestricted(HANDLE token);
PSID EzGetTokenProcessTrustLevel(HANDLE token);
BOOL EzGetTokenPrivateNameSpace(HANDLE token);
CLAIM_SECURITY_ATTRIBUTES_INFORMATION* EzGetTokenSingletonAttributes(HANDLE token);
TOKEN_BNO_ISOLATION_INFORMATION EzGetTokenBnoIsolation(HANDLE token);
void EzGetTokenChildProcessFlags(HANDLE token);
void EzGetTokenIsLessPrivilegedAppContainer(HANDLE token);
BOOL EzGetTokenIsSandboxed(HANDLE token);
void EzGetTokenIsAppSilo(HANDLE token);
void EzGetTokenLoggingInformation(HANDLE token);
void EzGetMaxTokenInfoClass(HANDLE token);

// Setting info about tokens
void EzSetTokenUser(HANDLE token, SID_AND_ATTRIBUTES value);
void EzSetTokenGroups(HANDLE token, TOKEN_GROUPS* value);
void EzSetTokenPrivileges(HANDLE token, TOKEN_PRIVILEGES* value);
void EzSetTokenOwner(HANDLE token, PSID value);
void EzSetTokenPrimaryGroup(HANDLE token, PSID value);
void EzSetTokenDefaultDacl(HANDLE token, TOKEN_DEFAULT_DACL* value);
void EzSetTokenSource(HANDLE token, TOKEN_SOURCE value);
void EzSetTokenType(HANDLE token, TOKEN_TYPE value);
void EzSetTokenImpersonationLevel(HANDLE token, SECURITY_IMPERSONATION_LEVEL value);
void EzSetTokenStatistics(HANDLE token, TOKEN_STATISTICS value);
void EzSetTokenRestrictedSids(HANDLE token, TOKEN_GROUPS* value);
void EzSetTokenSessionId(HANDLE token, DWORD value);
void EzSetTokenGroupsAndPrivileges(HANDLE token, TOKEN_GROUPS_AND_PRIVILEGES value);
void EzSetTokenSessionReference(HANDLE token /* void value */);
void EzSetTokenSandBoxInert(HANDLE token, BOOL value);
void EzSetTokenAuditPolicy(HANDLE token /* void value */);
void EzSetTokenOrigin(HANDLE token, LUID value);
void EzSetTokenElevationType(HANDLE token, TOKEN_ELEVATION_TYPE value);
void EzSetTokenLinkedToken(HANDLE token, HANDLE value);
void EzSetTokenElevation(HANDLE token, BOOL value);
void EzSetTokenHasRestrictions(HANDLE token, BOOL value);
void EzSetTokenAccessInformation(HANDLE token, TOKEN_ACCESS_INFORMATION value);
void EzSetTokenVirtualizationAllowed(HANDLE token, BOOL value);
void EzSetTokenVirtualizationEnabled(HANDLE token, BOOL value);
void EzSetTokenIntegrityLevel(HANDLE token, SID_AND_ATTRIBUTES value);
void EzSetTokenUIAccess(HANDLE token, BOOL value);
void EzSetTokenMandatoryPolicy(HANDLE token, DWORD value);
void EzSetTokenLogonSid(HANDLE token, TOKEN_GROUPS* value);
void EzSetTokenIsAppContainer(HANDLE token, BOOL value);
void EzSetTokenCapabilities(HANDLE token, TOKEN_GROUPS* value);
void EzSetTokenAppContainerSid(HANDLE token, PSID value);
void EzSetTokenAppContainerNumber(HANDLE token, DWORD value);
void EzSetTokenUserClaimAttributes(HANDLE token, CLAIM_SECURITY_ATTRIBUTES_INFORMATION* value);
void EzSetTokenDeviceClaimAttributes(HANDLE token, CLAIM_SECURITY_ATTRIBUTES_INFORMATION* value);
void EzSetTokenRestrictedUserClaimAttributes(HANDLE token /* void value */);
void EzSetTokenRestrictedDeviceClaimAttributes(HANDLE token /* void value */);
void EzSetTokenDeviceGroups(HANDLE token, TOKEN_GROUPS* value);
void EzSetTokenRestrictedDeviceGroups(HANDLE token, TOKEN_GROUPS* value);
void EzSetTokenSecurityAttributes(HANDLE token, CLAIM_SECURITY_ATTRIBUTES_INFORMATION* value);
void EzSetTokenIsRestricted(HANDLE token, BOOL value);
void EzSetTokenProcessTrustLevel(HANDLE token, PSID value);
void EzSetTokenPrivateNameSpace(HANDLE token, BOOL value);
void EzSetTokenSingletonAttributes(HANDLE token, CLAIM_SECURITY_ATTRIBUTES_INFORMATION* value);
void EzSetTokenBnoIsolation(HANDLE token, TOKEN_BNO_ISOLATION_INFORMATION value);
void EzSetTokenChildProcessFlags(HANDLE token /* void value */);
void EzSetTokenIsLessPrivilegedAppContainer(HANDLE token /* void value */);
void EzSetTokenIsSandboxed(HANDLE token, BOOL value);
void EzSetTokenIsAppSilo(HANDLE token /* void value */);
void EzSetTokenLoggingInformation(HANDLE token /* void value */);
void EzSetMaxTokenInfoClass(HANDLE token /* void value */);

// Printing info about tokens
void EzPrintTokenUser(HANDLE token, std::wostream& outputStream);
void EzPrintTokenGroups(HANDLE token, std::wostream& outputStream);
void EzPrintTokenPrivileges(HANDLE token, std::wostream& outputStream);
void EzPrintTokenOwner(HANDLE token, std::wostream& outputStream);
void EzPrintTokenPrimaryGroup(HANDLE token, std::wostream& outputStream);
void EzPrintTokenDefaultDacl(HANDLE token, std::wostream& outputStream);
void EzPrintTokenSource(HANDLE token, std::wostream& outputStream);
void EzPrintTokenType(HANDLE token, std::wostream& outputStream);
void EzPrintTokenImpersonationLevel(HANDLE token, std::wostream& outputStream);
void EzPrintTokenStatistics(HANDLE token, std::wostream& outputStream);
void EzPrintTokenRestrictedSids(HANDLE token, std::wostream& outputStream);
void EzPrintTokenSessionId(HANDLE token, std::wostream& outputStream);
void EzPrintTokenGroupsAndPrivileges(HANDLE token, std::wostream& outputStream);
void EzPrintTokenSessionReference(HANDLE token, std::wostream& outputStream);
void EzPrintTokenSandBoxInert(HANDLE token, std::wostream& outputStream);
void EzPrintTokenAuditPolicy(HANDLE token, std::wostream& outputStream);
void EzPrintTokenOrigin(HANDLE token, std::wostream& outputStream);
void EzPrintTokenElevationType(HANDLE token, std::wostream& outputStream);
void EzPrintTokenLinkedToken(HANDLE token, std::wostream& outputStream);
void EzPrintTokenElevation(HANDLE token, std::wostream& outputStream);
void EzPrintTokenHasRestrictions(HANDLE token, std::wostream& outputStream);
void EzPrintTokenAccessInformation(HANDLE token, std::wostream& outputStream);
void EzPrintTokenVirtualizationAllowed(HANDLE token, std::wostream& outputStream);
void EzPrintTokenVirtualizationEnabled(HANDLE token, std::wostream& outputStream);
void EzPrintTokenIntegrityLevel(HANDLE token, std::wostream& outputStream);
void EzPrintTokenUIAccess(HANDLE token, std::wostream& outputStream);
void EzPrintTokenMandatoryPolicy(HANDLE token, std::wostream& outputStream);
void EzPrintTokenLogonSid(HANDLE token, std::wostream& outputStream);
void EzPrintTokenIsAppContainer(HANDLE token, std::wostream& outputStream);
void EzPrintTokenCapabilities(HANDLE token, std::wostream& outputStream);
void EzPrintTokenAppContainerSid(HANDLE token, std::wostream& outputStream);
void EzPrintTokenAppContainerNumber(HANDLE token, std::wostream& outputStream);
void EzPrintTokenUserClaimAttributes(HANDLE token, std::wostream& outputStream);
void EzPrintTokenDeviceClaimAttributes(HANDLE token, std::wostream& outputStream);
void EzPrintTokenRestrictedUserClaimAttributes(HANDLE token, std::wostream& outputStream);
void EzPrintTokenRestrictedDeviceClaimAttributes(HANDLE token, std::wostream& outputStream);
void EzPrintTokenDeviceGroups(HANDLE token, std::wostream& outputStream);
void EzPrintTokenRestrictedDeviceGroups(HANDLE token, std::wostream& outputStream);
void EzPrintTokenSecurityAttributes(HANDLE token, std::wostream& outputStream);
void EzPrintTokenIsRestricted(HANDLE token, std::wostream& outputStream);
void EzPrintTokenProcessTrustLevel(HANDLE token, std::wostream& outputStream);
void EzPrintTokenPrivateNameSpace(HANDLE token, std::wostream& outputStream);
void EzPrintTokenSingletonAttributes(HANDLE token, std::wostream& outputStream);
void EzPrintTokenBnoIsolation(HANDLE token, std::wostream& outputStream);
void EzPrintTokenChildProcessFlags(HANDLE token, std::wostream& outputStream);
void EzPrintTokenIsLessPrivilegedAppContainer(HANDLE token, std::wostream& outputStream);
void EzPrintTokenIsSandboxed(HANDLE token, std::wostream& outputStream);
void EzPrintTokenIsAppSilo(HANDLE token, std::wostream& outputStream);
void EzPrintTokenLoggingInformation(HANDLE token, std::wostream& outputStream);
void EzPrintMaxTokenInfoClass(HANDLE token, std::wostream& outputStream);
void EzPrintTokenInfo(HANDLE token, std::wostream& outputStream);

// Working with the current token
HANDLE EzOpenCurrentToken();
HANDLE EzDuplicateCurrentToken();

// Impersonating tokens
void EzImpersonate(HANDLE token);
void EzStopImpersonating();
void EzImpersonateWinLogon();
void EzImpersonateLsass();

// Enabling/disabling token privileges
LUID EzLookupPrivilege(LPCWSTR privilege);
void EzEnableAllPrivileges(HANDLE token);
void EzDisableAllPrivileges(HANDLE token);
void EzEnablePrivilege(HANDLE token, LUID privilege);
void EzDisablePrivilege(HANDLE token, LUID privilege);
BOOL EzTokenHasPrivilege(HANDLE token, LUID privilege);

// Starting processes with tokens
PROCESS_INFORMATION EzLaunchAsToken(HANDLE token, LPCWSTR exePath);
PROCESS_INFORMATION EzLaunchAsToken(HANDLE token);
PROCESS_INFORMATION EzLaunchAsUser(HANDLE token, LPCWSTR exePath);
PROCESS_INFORMATION EzLaunchAsUser(HANDLE token);
BOOL EzLaunchWithUAC(LPCWSTR exePath);
BOOL EzLaunchWithUAC();

// Token privilege escalation
void EzGrantUIAccessToToken(HANDLE token);
void EzMakeTokenInteractive(HANDLE token);
void EzGiveTokenSystemIntegrity(HANDLE token);
void EzStealCreateTokenPermission(HANDLE token);
HANDLE EzCreateGodToken();
BOOL EzIsGodToken(HANDLE token);