// Approved 11/14/2024

#include "EzTokens.h"
#include "EzError.h"
#include "EzHelper.h"

// Collapse All: Ctrl+M+O
// Toggle Collapse: Ctrl+M+L



// Getting info about tokens
static void* GetTokenInfo(HANDLE token, TOKEN_INFORMATION_CLASS desiredInfo) {
	DWORD length = 0;
	GetTokenInformation(token, desiredInfo, NULL, 0, &length);
	if (length == 0) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	void* output = new BYTE[length];
	if (!GetTokenInformation(token, desiredInfo, output, length, &length)) {
		delete[] output;
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	return output;
}

SID_AND_ATTRIBUTES EzGetTokenUser(HANDLE token) {
	TOKEN_USER* outputPtr = reinterpret_cast<TOKEN_USER*>(GetTokenInfo(token, TokenUser));
	SID_AND_ATTRIBUTES output = outputPtr->User;
	delete[] outputPtr;
	return output;
}
TOKEN_GROUPS* EzGetTokenGroups(HANDLE token) {
	return reinterpret_cast<TOKEN_GROUPS*>(GetTokenInfo(token, TokenGroups));
}
TOKEN_PRIVILEGES* EzGetTokenPrivileges(HANDLE token) {
	return reinterpret_cast<TOKEN_PRIVILEGES*>(GetTokenInfo(token, TokenPrivileges));
}
PSID EzGetTokenOwner(HANDLE token) {
	TOKEN_OWNER* outputPtr = reinterpret_cast<TOKEN_OWNER*>(GetTokenInfo(token, TokenOwner));
	PSID output = outputPtr->Owner;
	delete[] outputPtr;
	return output;
}
PSID EzGetTokenPrimaryGroup(HANDLE token) {
	TOKEN_PRIMARY_GROUP* outputPtr = reinterpret_cast<TOKEN_PRIMARY_GROUP*>(GetTokenInfo(token, TokenPrimaryGroup));
	PSID output = outputPtr->PrimaryGroup;
	delete[] outputPtr;
	return output;
}
TOKEN_DEFAULT_DACL* EzGetTokenDefaultDacl(HANDLE token) {
	return reinterpret_cast<TOKEN_DEFAULT_DACL*>(GetTokenInfo(token, TokenDefaultDacl));
}
TOKEN_SOURCE EzGetTokenSource(HANDLE token) {
	TOKEN_SOURCE* outputPtr = reinterpret_cast<TOKEN_SOURCE*>(GetTokenInfo(token, TokenSource));
	TOKEN_SOURCE output = *outputPtr;
	delete[] outputPtr;
	return output;
}
TOKEN_TYPE EzGetTokenType(HANDLE token) {
	TOKEN_TYPE* outputPtr = reinterpret_cast<TOKEN_TYPE*>(GetTokenInfo(token, TokenType));
	TOKEN_TYPE output = *outputPtr;
	delete[] outputPtr;
	return output;
}
SECURITY_IMPERSONATION_LEVEL EzGetTokenImpersonationLevel(HANDLE token) {
	SECURITY_IMPERSONATION_LEVEL* outputPtr = reinterpret_cast<SECURITY_IMPERSONATION_LEVEL*>(GetTokenInfo(token, TokenImpersonationLevel));
	SECURITY_IMPERSONATION_LEVEL output = *outputPtr;
	delete[] outputPtr;
	return output;
}
TOKEN_STATISTICS EzGetTokenStatistics(HANDLE token) {
	TOKEN_STATISTICS* outputPtr = reinterpret_cast<TOKEN_STATISTICS*>(GetTokenInfo(token, TokenStatistics));
	TOKEN_STATISTICS output = *outputPtr;
	delete[] outputPtr;
	return output;
}
TOKEN_GROUPS* EzGetTokenRestrictedSids(HANDLE token) {
	return reinterpret_cast<TOKEN_GROUPS*>(GetTokenInfo(token, TokenRestrictedSids));
}
DWORD EzGetTokenSessionId(HANDLE token) {
	DWORD* outputPtr = reinterpret_cast<DWORD*>(GetTokenInfo(token, TokenSessionId));
	DWORD output = *outputPtr;
	delete[] outputPtr;
	return output;
}
TOKEN_GROUPS_AND_PRIVILEGES EzGetTokenGroupsAndPrivileges(HANDLE token) {
	TOKEN_GROUPS_AND_PRIVILEGES* outputPtr = reinterpret_cast<TOKEN_GROUPS_AND_PRIVILEGES*>(GetTokenInfo(token, TokenGroupsAndPrivileges));
	TOKEN_GROUPS_AND_PRIVILEGES output = *outputPtr;
	delete[] outputPtr;
	return output;
}
BOOL EzGetTokenSandBoxInert(HANDLE token) {
	BOOL* outputPtr = reinterpret_cast<BOOL*>(GetTokenInfo(token, TokenSandBoxInert));
	BOOL output = *outputPtr;
	delete[] outputPtr;
	return output;
}
LUID EzGetTokenOrigin(HANDLE token) {
	TOKEN_ORIGIN* outputPtr = reinterpret_cast<TOKEN_ORIGIN*>(GetTokenInfo(token, TokenOrigin));
	LUID output = outputPtr->OriginatingLogonSession;
	delete[] outputPtr;
	return output;
}
TOKEN_ELEVATION_TYPE EzGetTokenElevationType(HANDLE token) {
	TOKEN_ELEVATION_TYPE* outputPtr = reinterpret_cast<TOKEN_ELEVATION_TYPE*>(GetTokenInfo(token, TokenElevationType));
	TOKEN_ELEVATION_TYPE output = *outputPtr;
	delete[] outputPtr;
	return output;
}
HANDLE EzGetTokenLinkedToken(HANDLE token) {
	TOKEN_LINKED_TOKEN* outputPtr = reinterpret_cast<TOKEN_LINKED_TOKEN*>(GetTokenInfo(token, TokenLinkedToken));
	HANDLE output = outputPtr->LinkedToken;
	delete[] outputPtr;
	return output;
}
BOOL EzGetTokenElevation(HANDLE token) {
	TOKEN_ELEVATION* outputPtr = reinterpret_cast<TOKEN_ELEVATION*>(GetTokenInfo(token, TokenElevation));
	BOOL output = outputPtr->TokenIsElevated;
	delete[] outputPtr;
	return output;
}
BOOL EzGetTokenHasRestrictions(HANDLE token) {
	BOOL* outputPtr = reinterpret_cast<BOOL*>(GetTokenInfo(token, TokenHasRestrictions));
	BOOL output = *outputPtr;
	delete[] outputPtr;
	return output;
}
TOKEN_ACCESS_INFORMATION EzGetTokenAccessInformation(HANDLE token) {
	TOKEN_ACCESS_INFORMATION* outputPtr = reinterpret_cast<TOKEN_ACCESS_INFORMATION*>(GetTokenInfo(token, TokenAccessInformation));
	TOKEN_ACCESS_INFORMATION output = *outputPtr;
	delete[] outputPtr;
	return output;
}
BOOL EzGetTokenVirtualizationAllowed(HANDLE token) {
	BOOL* outputPtr = reinterpret_cast<BOOL*>(GetTokenInfo(token, TokenVirtualizationAllowed));
	BOOL output = *outputPtr;
	delete[] outputPtr;
	return output;
}
BOOL EzGetTokenVirtualizationEnabled(HANDLE token) {
	BOOL* outputPtr = reinterpret_cast<BOOL*>(GetTokenInfo(token, TokenVirtualizationEnabled));
	BOOL output = *outputPtr;
	delete[] outputPtr;
	return output;
}
SID_AND_ATTRIBUTES EzGetTokenIntegrityLevel(HANDLE token) {
	TOKEN_MANDATORY_LABEL* outputPtr = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(GetTokenInfo(token, TokenIntegrityLevel));
	SID_AND_ATTRIBUTES output = outputPtr->Label;
	delete[] outputPtr;
	return output;
}
BOOL EzGetTokenUIAccess(HANDLE token) {
	BOOL* outputPtr = reinterpret_cast<BOOL*>(GetTokenInfo(token, TokenUIAccess));
	BOOL output = *outputPtr;
	delete[] outputPtr;
	return output;
}
DWORD EzGetTokenMandatoryPolicy(HANDLE token) {
	TOKEN_MANDATORY_POLICY* outputPtr = reinterpret_cast<TOKEN_MANDATORY_POLICY*>(GetTokenInfo(token, TokenMandatoryPolicy));
	DWORD output = outputPtr->Policy;
	delete[] outputPtr;
	return output;
}
TOKEN_GROUPS* EzGetTokenLogonSid(HANDLE token) {
	return reinterpret_cast<TOKEN_GROUPS*>(GetTokenInfo(token, TokenLogonSid));
}
BOOL EzGetTokenIsAppContainer(HANDLE token) {
	BOOL* outputPtr = reinterpret_cast<BOOL*>(GetTokenInfo(token, TokenIsAppContainer));
	BOOL output = *outputPtr;
	delete[] outputPtr;
	return output;
}
TOKEN_GROUPS* EzGetTokenCapabilities(HANDLE token) {
	return reinterpret_cast<TOKEN_GROUPS*>(GetTokenInfo(token, TokenCapabilities));
}
PSID EzGetTokenAppContainerSid(HANDLE token) {
	TOKEN_APPCONTAINER_INFORMATION* outputPtr = reinterpret_cast<TOKEN_APPCONTAINER_INFORMATION*>(GetTokenInfo(token, TokenAppContainerSid));
	PSID output = outputPtr->TokenAppContainer;
	delete[] outputPtr;
	return output;
}
DWORD EzGetTokenAppContainerNumber(HANDLE token) {
	DWORD* outputPtr = reinterpret_cast<DWORD*>(GetTokenInfo(token, TokenAppContainerNumber));
	DWORD output = *outputPtr;
	delete[] outputPtr;
	return output;
}
CLAIM_SECURITY_ATTRIBUTES_INFORMATION* EzGetTokenUserClaimAttributes(HANDLE token) {
	return reinterpret_cast<CLAIM_SECURITY_ATTRIBUTES_INFORMATION*>(GetTokenInfo(token, TokenUserClaimAttributes));
}
CLAIM_SECURITY_ATTRIBUTES_INFORMATION* EzGetTokenDeviceClaimAttributes(HANDLE token) {
	return reinterpret_cast<CLAIM_SECURITY_ATTRIBUTES_INFORMATION*>(GetTokenInfo(token, TokenDeviceClaimAttributes));
}
TOKEN_GROUPS* EzGetTokenDeviceGroups(HANDLE token) {
	return reinterpret_cast<TOKEN_GROUPS*>(GetTokenInfo(token, TokenDeviceGroups));
}
TOKEN_GROUPS* EzGetTokenRestrictedDeviceGroups(HANDLE token) {
	return reinterpret_cast<TOKEN_GROUPS*>(GetTokenInfo(token, TokenRestrictedDeviceGroups));
}
CLAIM_SECURITY_ATTRIBUTES_INFORMATION* EzGetTokenSecurityAttributes(HANDLE token) {
	return reinterpret_cast<CLAIM_SECURITY_ATTRIBUTES_INFORMATION*>(GetTokenInfo(token, TokenSecurityAttributes));
}
BOOL EzGetTokenIsRestricted(HANDLE token) {
	BOOL* outputPtr = reinterpret_cast<BOOL*>(GetTokenInfo(token, TokenIsRestricted));
	BOOL output = *outputPtr;
	delete[] outputPtr;
	return output;
}
PSID EzGetTokenProcessTrustLevel(HANDLE token) {
	PSID* outputPtr = reinterpret_cast<PSID*>(GetTokenInfo(token, TokenProcessTrustLevel));
	PSID output = *outputPtr;
	delete[] outputPtr;
	return output;
}
BOOL EzGetTokenPrivateNameSpace(HANDLE token) {
	BOOL* outputPtr = reinterpret_cast<BOOL*>(GetTokenInfo(token, TokenPrivateNameSpace));
	BOOL output = *outputPtr;
	delete[] outputPtr;
	return output;
}
CLAIM_SECURITY_ATTRIBUTES_INFORMATION* EzGetTokenSingletonAttributes(HANDLE token) {
	return reinterpret_cast<CLAIM_SECURITY_ATTRIBUTES_INFORMATION*>(GetTokenInfo(token, TokenSingletonAttributes));
}
TOKEN_BNO_ISOLATION_INFORMATION EzGetTokenBnoIsolation(HANDLE token) {
	TOKEN_BNO_ISOLATION_INFORMATION* outputPtr = reinterpret_cast<TOKEN_BNO_ISOLATION_INFORMATION*>(GetTokenInfo(token, TokenBnoIsolation));
	TOKEN_BNO_ISOLATION_INFORMATION output = *outputPtr;
	delete[] outputPtr;
	return output;
}
BOOL EzGetTokenIsSandboxed(HANDLE token) {
	BOOL* outputPtr = reinterpret_cast<BOOL*>(GetTokenInfo(token, TokenIsSandboxed));
	BOOL output = *outputPtr;
	delete[] outputPtr;
	return output;
}



// Setting info about tokens
static void SetTokenInfo(HANDLE token, TOKEN_INFORMATION_CLASS targetClass, void* newInfo, DWORD newInfoLength) {
	if (!SetTokenInformation(token, targetClass, newInfo, newInfoLength)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}
}

void EzSetTokenUser(HANDLE token, SID_AND_ATTRIBUTES value) {
	SetTokenInfo(token, TokenUser, &value, sizeof(SID_AND_ATTRIBUTES));
}
void EzSetTokenGroups(HANDLE token, TOKEN_GROUPS* value) {
	SetTokenInfo(token, TokenGroups, value, sizeof(TOKEN_GROUPS) + ((value->GroupCount - 1) * sizeof(SID_AND_ATTRIBUTES)));
}
void EzSetTokenPrivileges(HANDLE token, TOKEN_PRIVILEGES* value) {
	SetTokenInfo(token, TokenPrivileges, value, sizeof(TOKEN_PRIVILEGES) + ((value->PrivilegeCount - 1) * sizeof(LUID_AND_ATTRIBUTES)));
}
void EzSetTokenOwner(HANDLE token, PSID value) {
	SetTokenInfo(token, TokenOwner, &value, sizeof(PSID));
}
void EzSetTokenPrimaryGroup(HANDLE token, PSID value) {
	SetTokenInfo(token, TokenPrimaryGroup, &value, sizeof(PSID));
}
void EzSetTokenDefaultDacl(HANDLE token, TOKEN_DEFAULT_DACL* value) {
	SetTokenInfo(token, TokenDefaultDacl, &value, sizeof(TOKEN_DEFAULT_DACL));
}
void EzSetTokenSource(HANDLE token, TOKEN_SOURCE value) {
	SetTokenInfo(token, TokenSource, &value, sizeof(TOKEN_SOURCE));
}
void EzSetTokenType(HANDLE token, TOKEN_TYPE value) {
	SetTokenInfo(token, TokenType, &value, sizeof(TOKEN_TYPE));
}
void EzSetTokenImpersonationLevel(HANDLE token, SECURITY_IMPERSONATION_LEVEL value) {
	SetTokenInfo(token, TokenImpersonationLevel, &value, sizeof(SECURITY_IMPERSONATION_LEVEL));
}
void EzSetTokenStatistics(HANDLE token, TOKEN_STATISTICS value) {
	SetTokenInfo(token, TokenStatistics, &value, sizeof(TOKEN_STATISTICS));
}
void EzSetTokenRestrictedSids(HANDLE token, TOKEN_GROUPS* value) {
	SetTokenInfo(token, TokenRestrictedSids, &value, sizeof(TOKEN_GROUPS) + ((value->GroupCount - 1) * sizeof(SID_AND_ATTRIBUTES)));
}
void EzSetTokenSessionId(HANDLE token, DWORD value) {
	SetTokenInfo(token, TokenSessionId, &value, sizeof(DWORD));
}
void EzSetTokenGroupsAndPrivileges(HANDLE token, TOKEN_GROUPS_AND_PRIVILEGES value) {
	SetTokenInfo(token, TokenGroupsAndPrivileges, &value, sizeof(TOKEN_GROUPS_AND_PRIVILEGES));
}
void EzSetTokenSandBoxInert(HANDLE token, BOOL value) {
	SetTokenInfo(token, TokenSandBoxInert, &value, sizeof(BOOL));
}
void EzSetTokenOrigin(HANDLE token, LUID value) {
	SetTokenInfo(token, TokenOrigin, &value, sizeof(LUID));
}
void EzSetTokenElevationType(HANDLE token, TOKEN_ELEVATION_TYPE value) {
	SetTokenInfo(token, TokenElevationType, &value, sizeof(TOKEN_ELEVATION_TYPE));
}
void EzSetTokenLinkedToken(HANDLE token, HANDLE value) {
	SetTokenInfo(token, TokenLinkedToken, &value, sizeof(HANDLE));
}
void EzSetTokenElevation(HANDLE token, BOOL value) {
	SetTokenInfo(token, TokenElevation, &value, sizeof(BOOL));
}
void EzSetTokenHasRestrictions(HANDLE token, BOOL value) {
	SetTokenInfo(token, TokenHasRestrictions, &value, sizeof(BOOL));
}
void EzSetTokenAccessInformation(HANDLE token, TOKEN_ACCESS_INFORMATION value) {
	SetTokenInfo(token, TokenAccessInformation, &value, sizeof(TOKEN_ACCESS_INFORMATION));
}
void EzSetTokenVirtualizationAllowed(HANDLE token, BOOL value) {
	SetTokenInfo(token, TokenVirtualizationAllowed, &value, sizeof(BOOL));
}
void EzSetTokenVirtualizationEnabled(HANDLE token, BOOL value) {
	SetTokenInfo(token, TokenVirtualizationEnabled, &value, sizeof(BOOL));
}
void EzSetTokenIntegrityLevel(HANDLE token, SID_AND_ATTRIBUTES value) {
	SetTokenInfo(token, TokenIntegrityLevel, &value, sizeof(SID_AND_ATTRIBUTES));
}
void EzSetTokenUIAccess(HANDLE token, BOOL value) {
	SetTokenInfo(token, TokenUIAccess, &value, sizeof(BOOL));
}
void EzSetTokenMandatoryPolicy(HANDLE token, DWORD value) {
	SetTokenInfo(token, TokenMandatoryPolicy, &value, sizeof(DWORD));
}
void EzSetTokenLogonSid(HANDLE token, TOKEN_GROUPS* value) {
	SetTokenInfo(token, TokenLogonSid, value, sizeof(TOKEN_GROUPS) + ((value->GroupCount - 1) * sizeof(SID_AND_ATTRIBUTES)));
}
void EzSetTokenIsAppContainer(HANDLE token, BOOL value) {
	SetTokenInfo(token, TokenIsAppContainer, &value, sizeof(BOOL));
}
void EzSetTokenCapabilities(HANDLE token, TOKEN_GROUPS* value) {
	SetTokenInfo(token, TokenCapabilities, value, sizeof(TOKEN_GROUPS) + ((value->GroupCount - 1) * sizeof(SID_AND_ATTRIBUTES)));
}
void EzSetTokenAppContainerSid(HANDLE token, PSID value) {
	SetTokenInfo(token, TokenAppContainerSid, &value, sizeof(PSID));
}
void EzSetTokenAppContainerNumber(HANDLE token, DWORD value) {
	SetTokenInfo(token, TokenAppContainerNumber, &value, sizeof(DWORD));
}
void EzSetTokenUserClaimAttributes(HANDLE token, CLAIM_SECURITY_ATTRIBUTES_INFORMATION* value) {
	SetTokenInfo(token, TokenUserClaimAttributes, value, sizeof(CLAIM_SECURITY_ATTRIBUTES_INFORMATION));
}
void EzSetTokenDeviceClaimAttributes(HANDLE token, CLAIM_SECURITY_ATTRIBUTES_INFORMATION* value) {
	SetTokenInfo(token, TokenDeviceClaimAttributes, value, sizeof(CLAIM_SECURITY_ATTRIBUTES_INFORMATION));
}
void EzSetTokenDeviceGroups(HANDLE token, TOKEN_GROUPS* value) {
	SetTokenInfo(token, TokenDeviceGroups, value, sizeof(TOKEN_GROUPS) + ((value->GroupCount - 1) * sizeof(SID_AND_ATTRIBUTES)));
}
void EzSetTokenRestrictedDeviceGroups(HANDLE token, TOKEN_GROUPS* value) {
	SetTokenInfo(token, TokenRestrictedDeviceGroups, value, sizeof(TOKEN_GROUPS) + ((value->GroupCount - 1) * sizeof(SID_AND_ATTRIBUTES)));
}
void EzSetTokenSecurityAttributes(HANDLE token, CLAIM_SECURITY_ATTRIBUTES_INFORMATION* value) {
	SetTokenInfo(token, TokenSecurityAttributes, value, sizeof(CLAIM_SECURITY_ATTRIBUTES_INFORMATION));
}
void EzSetTokenIsRestricted(HANDLE token, BOOL value) {
	SetTokenInfo(token, TokenIsRestricted, &value, sizeof(BOOL));
}
void EzSetTokenProcessTrustLevel(HANDLE token, PSID value) {
	SetTokenInfo(token, TokenProcessTrustLevel, &value, sizeof(PSID));
}
void EzSetTokenPrivateNameSpace(HANDLE token, BOOL value) {
	SetTokenInfo(token, TokenPrivateNameSpace, &value, sizeof(BOOL));
}
void EzSetTokenSingletonAttributes(HANDLE token, CLAIM_SECURITY_ATTRIBUTES_INFORMATION* value) {
	SetTokenInfo(token, TokenSingletonAttributes, value, sizeof(CLAIM_SECURITY_ATTRIBUTES_INFORMATION));
}
void EzSetTokenBnoIsolation(HANDLE token, TOKEN_BNO_ISOLATION_INFORMATION value) {
	SetTokenInfo(token, TokenBnoIsolation, &value, sizeof(TOKEN_BNO_ISOLATION_INFORMATION));
}
void EzSetTokenIsSandboxed(HANDLE token, BOOL value) {
	SetTokenInfo(token, TokenIsSandboxed, &value, sizeof(BOOL));
}



// Printing info about tokens to an Ansi stream
void EzPrintTokenUserA(HANDLE token, std::ostream& outputStream) {
	try {
		SID_AND_ATTRIBUTES tokenUser = EzGetTokenUser(token);

		outputStream << "Token User:" << std::endl;
		outputStream << "    SID: "; EzPrintSidA(tokenUser.Sid, outputStream); outputStream << std::endl;
		outputStream << "    Attributes: "; EzPrintBinaryA(reinterpret_cast<BYTE*>(&tokenUser.Attributes), sizeof(DWORD), outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenGroupsA(HANDLE token, std::ostream& outputStream) {
	try {
		TOKEN_GROUPS* tokenGroups = EzGetTokenGroups(token);

		outputStream << "Token Groups [" << tokenGroups->GroupCount << "]:"; if (tokenGroups->GroupCount == 0) { outputStream << " None"; } outputStream << std::endl;
		for (DWORD i = 0; i < tokenGroups->GroupCount; i++)
		{
			if (i != 0) { outputStream << std::endl; }
			outputStream << "   SID: "; EzPrintSidA(tokenGroups->Groups[i].Sid, outputStream); outputStream << std::endl;
			outputStream << "   Attributes: "; EzPrintBinaryA(reinterpret_cast<BYTE*>(&tokenGroups->Groups[i].Attributes), sizeof(DWORD), outputStream); outputStream << std::endl;
		}

		delete[] tokenGroups;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenPrivilegesA(HANDLE token, std::ostream& outputStream) {
	try {
		TOKEN_PRIVILEGES* tokenPrivileges = EzGetTokenPrivileges(token);

		outputStream << "Token Privileges [" << tokenPrivileges->PrivilegeCount << "]:"; if (tokenPrivileges->PrivilegeCount == 0) { outputStream << " None"; } outputStream << std::endl;
		for (DWORD i = 0; i < tokenPrivileges->PrivilegeCount; i++)
		{
			if (i != 0) { outputStream << std::endl; }
			outputStream << "    LUID: "; EzPrintLuidA(tokenPrivileges->Privileges[i].Luid, outputStream); outputStream << std::endl;
			outputStream << "    Attributes: "; EzPrintBinaryA(reinterpret_cast<BYTE*>(&tokenPrivileges->Privileges[i].Attributes), 4, outputStream); outputStream << std::endl;
		}

		delete[] tokenPrivileges;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenOwnerA(HANDLE token, std::ostream& outputStream) {
	try {
		PSID tokenOwner = EzGetTokenOwner(token);

		outputStream << "Token Owner: "; EzPrintSidA(tokenOwner, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenPrimaryGroupA(HANDLE token, std::ostream& outputStream) {
	try {
		PSID tokenPrimaryGroup = EzGetTokenPrimaryGroup(token);

		outputStream << "Token Primary Group: "; EzPrintSidA(tokenPrimaryGroup, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenDefaultDaclA(HANDLE token, std::ostream& outputStream) {
	try {
		TOKEN_DEFAULT_DACL* tokenDefaultDacl = EzGetTokenDefaultDacl(token);

		if (tokenDefaultDacl->DefaultDacl == NULL) {
			outputStream << "Token Default DACL: NUL" << std::endl;
		}
		else {
			outputStream << "Token Default DACL:" << std::endl;
			outputStream << "    ACL Revision: " << tokenDefaultDacl->DefaultDacl->AclRevision << std::endl;
			outputStream << "    ACL Size: " << tokenDefaultDacl->DefaultDacl->AclSize << std::endl;
			outputStream << "    ACE List [" << tokenDefaultDacl->DefaultDacl->AceCount << "]:"; if (tokenDefaultDacl->DefaultDacl->AceCount == 0) { outputStream << " None"; } outputStream << std::endl;
			for (DWORD i = 0; i < tokenDefaultDacl->DefaultDacl->AceCount; i++)
			{
				if (i != 0) { outputStream << std::endl; }
				ACE_HEADER* currentACE = NULL;
				GetAce(tokenDefaultDacl->DefaultDacl, i, reinterpret_cast<void**>(&currentACE));
				outputStream << "    Type: " << currentACE->AceType << std::endl;
				outputStream << "    Flags: " << currentACE->AceFlags << std::endl;
				outputStream << "    Size: " << currentACE->AceSize << std::endl;
			}
		}

		delete[] tokenDefaultDacl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenSourceA(HANDLE token, std::ostream& outputStream) {
	try {
		TOKEN_SOURCE tokenSource = EzGetTokenSource(token);

		CHAR safeSourceName[9];
		memcpy(safeSourceName, tokenSource.SourceName, 8);
		safeSourceName[8] = '\0';

		outputStream << "Token Source:" << std::endl;
		outputStream << "    Name: " << safeSourceName << std::endl;
		outputStream << "    Identifier: "; EzPrintLuidA(tokenSource.SourceIdentifier, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenTypeA(HANDLE token, std::ostream& outputStream) {
	try {
		TOKEN_TYPE tokenType = EzGetTokenType(token);

		outputStream << "Token Type: ";
		if (tokenType == TokenPrimary) {
			outputStream << "Primary";
		}
		else if (tokenType == TokenImpersonation) {
			outputStream << "Impersonation";
		}
		else {
			outputStream << "Invalid";
		}
		outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenImpersonationLevelA(HANDLE token, std::ostream& outputStream) {
	try {
		TOKEN_TYPE tokenType = EzGetTokenType(token);
		if (tokenType != TokenImpersonation) {
			outputStream << "Token Impersonation Level: N/A" << std::endl;
			return;
		}

		SECURITY_IMPERSONATION_LEVEL tokenImpersonationLevel = EzGetTokenImpersonationLevel(token);

		outputStream << "Token Impersonation Level: ";
		if (tokenImpersonationLevel == SecurityAnonymous) {
			outputStream << "Anonymous";
		}
		else if (tokenImpersonationLevel == SecurityIdentification) {
			outputStream << "Identification";
		}
		else if (tokenImpersonationLevel == SecurityImpersonation) {
			outputStream << "Impersonation";
		}
		else if (tokenImpersonationLevel == SecurityDelegation) {
			outputStream << "Delegation";
		}
		else {
			outputStream << "Invalid";
		}
		outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenStatisticsA(HANDLE token, std::ostream& outputStream) {
	try {
		TOKEN_STATISTICS tokenStatistics = EzGetTokenStatistics(token);

		outputStream << "Token Statistics:" << std::endl;
		outputStream << "    Token ID: "; EzPrintLuidA(tokenStatistics.TokenId, outputStream); outputStream << std::endl;
		outputStream << "    Authentication ID: "; EzPrintLuidA(tokenStatistics.AuthenticationId, outputStream); outputStream << std::endl;
		outputStream << "    Token Type: ";
		if (tokenStatistics.TokenType == TokenPrimary) {
			outputStream << "Primary";
		}
		else if (tokenStatistics.TokenType == TokenImpersonation) {
			outputStream << "Impersonation";
		}
		else {
			outputStream << "Invalid";
		}
		outputStream << std::endl;
		if (tokenStatistics.TokenType != TokenImpersonation) {
			outputStream << "    Impersonation Level: N/A" << std::endl;
		}
		else {
			outputStream << "    Impersonation Level: ";
			if (tokenStatistics.ImpersonationLevel == SecurityAnonymous) {
				outputStream << "Anonymous";
			}
			else if (tokenStatistics.ImpersonationLevel == SecurityIdentification) {
				outputStream << "Identification";
			}
			else if (tokenStatistics.ImpersonationLevel == SecurityImpersonation) {
				outputStream << "Impersonation";
			}
			else if (tokenStatistics.ImpersonationLevel == SecurityDelegation) {
				outputStream << "Delegation";
			}
			else {
				outputStream << "Invalid";
			}
			outputStream << std::endl;
		}
		outputStream << "    Dynamic Charged: " << tokenStatistics.DynamicCharged << std::endl;
		outputStream << "    Dynamic Available: " << tokenStatistics.DynamicAvailable << std::endl;
		outputStream << "    Group Count: " << tokenStatistics.GroupCount << std::endl;
		outputStream << "    Privilege Count: " << tokenStatistics.PrivilegeCount << std::endl;
		outputStream << "    Modified ID: "; EzPrintLuidA(tokenStatistics.ModifiedId, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenRestrictedSidsA(HANDLE token, std::ostream& outputStream) {
	try {
		TOKEN_GROUPS* tokenRestrictedSids = EzGetTokenRestrictedSids(token);

		outputStream << "Token Restricted SIDs [" << tokenRestrictedSids->GroupCount << "]:"; if (tokenRestrictedSids->GroupCount == 0) { outputStream << " None"; } outputStream << std::endl;
		for (DWORD i = 0; i < tokenRestrictedSids->GroupCount; i++)
		{
			if (i != 0) { outputStream << std::endl; }
			outputStream << "    SID: "; EzPrintSidA(tokenRestrictedSids->Groups[i].Sid, outputStream); outputStream << std::endl;
			outputStream << "    Attributes: "; EzPrintBinaryA(reinterpret_cast<BYTE*>(&tokenRestrictedSids->Groups[i].Attributes), sizeof(DWORD), outputStream); outputStream << std::endl;
		}

		delete[] tokenRestrictedSids;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenSessionIdA(HANDLE token, std::ostream& outputStream) {
	try {
		DWORD tokenSessionId = EzGetTokenSessionId(token);

		outputStream << "Token Session ID: " << tokenSessionId << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenGroupsAndPrivilegesA(HANDLE token, std::ostream& outputStream) {
	try {
		outputStream << "Token Groups And Privileges: Information already printed." << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenSessionReferenceA(HANDLE token, std::ostream& outputStream) {
	try {
		// Always returns parameter incorrect.
		outputStream << "Token Session Refrences: Not supported" << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenSandBoxInertA(HANDLE token, std::ostream& outputStream) {
	try {
		BOOL tokenSandBoxInert = EzGetTokenSandBoxInert(token);

		outputStream << "Token Sand Box Inert: "; EzPrintBoolA(tokenSandBoxInert, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenAuditPolicyA(HANDLE token, std::ostream& outputStream) {
	try {
		// Always returns access denied.
		outputStream << "Token Audit Policy: Only accessible from kernel mode." << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenOriginA(HANDLE token, std::ostream& outputStream) {
	try {
		LUID tokenOrigin = EzGetTokenOrigin(token);

		outputStream << "Token Origin: "; EzPrintLuidA(tokenOrigin, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenElevationTypeA(HANDLE token, std::ostream& outputStream) {
	try {
		TOKEN_ELEVATION_TYPE tokenElevationType = EzGetTokenElevationType(token);

		outputStream << "Token Elevation Type: ";
		if (tokenElevationType == TokenElevationTypeDefault) {
			outputStream << "Default";
		}
		else if (tokenElevationType == TokenElevationTypeFull) {
			outputStream << "Full";
		}
		else if (tokenElevationType == TokenElevationTypeLimited) {
			outputStream << "Limited";
		}
		else {
			outputStream << "Invalid";
		}
		outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenLinkedTokenA(HANDLE token, std::ostream& outputStream) {
	try {
		HANDLE tokenLinkedToken = EzGetTokenLinkedToken(token);

		outputStream << "Token Linked Token: "; EzPrintHexA(reinterpret_cast<BYTE*>(&tokenLinkedToken), sizeof(HANDLE), outputStream); outputStream << std::endl;

		EzCloseHandleSafely(tokenLinkedToken);
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenElevationA(HANDLE token, std::ostream& outputStream) {
	try {
		BOOL tokenElevation = EzGetTokenElevation(token);

		outputStream << "Token Is Elevated: "; EzPrintBoolA(tokenElevation, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenHasRestrictionsA(HANDLE token, std::ostream& outputStream) {
	try {
		BOOL tokenHasRestrictions = EzGetTokenHasRestrictions(token);

		outputStream << "Token Has Restrictions: "; EzPrintBoolA(tokenHasRestrictions, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenAccessInformationA(HANDLE token, std::ostream& outputStream) {
	try {
		TOKEN_ACCESS_INFORMATION tokenAccessInformation = EzGetTokenAccessInformation(token);

		outputStream << "Token Access Information: TODO" << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenVirtualizationAllowedA(HANDLE token, std::ostream& outputStream) {
	try {
		BOOL tokenVirtualizationAllowed = EzGetTokenVirtualizationAllowed(token);

		outputStream << "Token Virtualization Allowed: "; EzPrintBoolA(tokenVirtualizationAllowed, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenVirtualizationEnabledA(HANDLE token, std::ostream& outputStream) {
	try {
		BOOL tokenVirtualizationEnabled = EzGetTokenVirtualizationEnabled(token);

		outputStream << "Token Virtualization Enabled: "; EzPrintBoolA(tokenVirtualizationEnabled, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenIntegrityLevelA(HANDLE token, std::ostream& outputStream) {
	try {
		SID_AND_ATTRIBUTES tokenIntegrityLevel = EzGetTokenIntegrityLevel(token);

		outputStream << "Token Integrity Level:" << std::endl;
		outputStream << "    SID: "; EzPrintSidA(tokenIntegrityLevel.Sid, outputStream); outputStream << std::endl;
		outputStream << "    Attributes: "; EzPrintBinaryA(reinterpret_cast<BYTE*>(&tokenIntegrityLevel.Attributes), sizeof(DWORD), outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenUIAccessA(HANDLE token, std::ostream& outputStream) {
	try {
		BOOL tokenUIAccess = EzGetTokenUIAccess(token);

		outputStream << "Token UI Access: "; EzPrintBoolA(tokenUIAccess, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenMandatoryPolicyA(HANDLE token, std::ostream& outputStream) {
	try {
		DWORD tokenMandatoryPolicy = EzGetTokenMandatoryPolicy(token);

		outputStream << "Token Mandatory Policy: " << tokenMandatoryPolicy << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenLogonSidA(HANDLE token, std::ostream& outputStream) {
	try {
		TOKEN_GROUPS* tokenLogonSid = EzGetTokenLogonSid(token);

		outputStream << "Token Logon Sids [" << tokenLogonSid->GroupCount << "]:"; if (tokenLogonSid->GroupCount == 0) { outputStream << " None"; } outputStream << std::endl;
		for (DWORD i = 0; i < tokenLogonSid->GroupCount; i++)
		{
			if (i != 0) { outputStream << std::endl; }
			outputStream << "    SID: "; EzPrintSidA(tokenLogonSid->Groups[i].Sid, outputStream); outputStream << std::endl;
			outputStream << "    Attributes: "; EzPrintBinaryA(reinterpret_cast<BYTE*>(&tokenLogonSid->Groups[i].Attributes), sizeof(DWORD), outputStream); outputStream << std::endl;
		}

		delete[] tokenLogonSid;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenIsAppContainerA(HANDLE token, std::ostream& outputStream) {
	try {
		BOOL tokenIsAppContainer = EzGetTokenIsAppContainer(token);

		outputStream << "Token Is App Container: "; EzPrintBoolA(tokenIsAppContainer, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenCapabilitiesA(HANDLE token, std::ostream& outputStream) {
	try {
		TOKEN_GROUPS* tokenCapabilities = EzGetTokenCapabilities(token);

		outputStream << "Token Capabilities [" << tokenCapabilities->GroupCount << "]:"; if (tokenCapabilities->GroupCount == 0) { outputStream << " None"; } outputStream << std::endl;
		for (DWORD i = 0; i < tokenCapabilities->GroupCount; i++)
		{
			if (i != 0) { outputStream << std::endl; }
			outputStream << "    SID: "; EzPrintSidA(tokenCapabilities->Groups[i].Sid, outputStream); outputStream << std::endl;
			outputStream << "    Attributes: "; EzPrintBinaryA(reinterpret_cast<BYTE*>(&tokenCapabilities->Groups[i].Attributes), sizeof(DWORD), outputStream); outputStream << std::endl;
		}

		delete[] tokenCapabilities;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenAppContainerSidA(HANDLE token, std::ostream& outputStream) {
	try {
		PSID tokenAppContainerSid = EzGetTokenAppContainerSid(token);

		outputStream << "Token App Container SID: "; EzPrintSidA(tokenAppContainerSid, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenAppContainerNumberA(HANDLE token, std::ostream& outputStream) {
	try {
		DWORD tokenAppContainerNumber = EzGetTokenAppContainerNumber(token);

		outputStream << "Token App Container Number: " << tokenAppContainerNumber << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenUserClaimAttributesA(HANDLE token, std::ostream& outputStream) {
	try {
		CLAIM_SECURITY_ATTRIBUTES_INFORMATION* tokenUserClaimAttributes = EzGetTokenUserClaimAttributes(token);

		outputStream << "Token User Claim Attributes:" << std::endl;
		outputStream << "    Version: " << tokenUserClaimAttributes->Version << std::endl;
		outputStream << "    Reserved: " << tokenUserClaimAttributes->Reserved << std::endl;
		outputStream << "    Attributes [" << tokenUserClaimAttributes->AttributeCount << "]:"; if (tokenUserClaimAttributes->AttributeCount == 0) { outputStream << " None"; } outputStream << std::endl;
		for (DWORD i = 0; i < tokenUserClaimAttributes->AttributeCount; i++)
		{
			CLAIM_SECURITY_ATTRIBUTE_V1 attribute = tokenUserClaimAttributes->Attribute.pAttributeV1[i];
			outputStream << "        Name: " << attribute.Name << std::endl;
			outputStream << "        Value Type: " << attribute.ValueType << std::endl;
			outputStream << "        Reserved: " << attribute.Reserved << std::endl;
			outputStream << "        Flags: "; EzPrintBinaryA(reinterpret_cast<BYTE*>(&attribute.Flags), sizeof(DWORD), outputStream); outputStream << std::endl;
			outputStream << "        Value Count: " << attribute.ValueCount << std::endl;
			outputStream << "        Values:" << std::endl;
			for (DWORD j = 0; j < attribute.ValueCount; j++)
			{
				outputStream << "            TODO" << std::endl;
			}
			outputStream << std::endl;
		}

		delete[] tokenUserClaimAttributes;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenDeviceClaimAttributesA(HANDLE token, std::ostream& outputStream) {
	try {
		CLAIM_SECURITY_ATTRIBUTES_INFORMATION* tokenDeviceClaimAttributes = EzGetTokenDeviceClaimAttributes(token);

		outputStream << "Token Device Claim Attributes: TODO" << std::endl;

		delete[] tokenDeviceClaimAttributes;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenRestrictedUserClaimAttributesA(HANDLE token, std::ostream& outputStream) {
	try {
		// Always returns parameter incorrect.
		outputStream << "Token Restricted User Claim Attributes: Not supported" << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenRestrictedDeviceClaimAttributesA(HANDLE token, std::ostream& outputStream) {
	try {
		// Always returns parameter incorrect.
		outputStream << "Token Restricted Device Claim Attributes: Not supported" << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenDeviceGroupsA(HANDLE token, std::ostream& outputStream) {
	try {
		TOKEN_GROUPS* tokenDeviceGroups = EzGetTokenDeviceGroups(token);

		outputStream << "Token Device Groups [" << tokenDeviceGroups->GroupCount << "]:"; if (tokenDeviceGroups->GroupCount == 0) { outputStream << " None"; } outputStream << std::endl;
		for (DWORD i = 0; i < tokenDeviceGroups->GroupCount; i++)
		{
			if (i != 0) { outputStream << std::endl; }
			outputStream << "    SID: "; EzPrintSidA(tokenDeviceGroups->Groups[i].Sid, outputStream); outputStream << std::endl;
			outputStream << "    Attributes: "; EzPrintBinaryA(reinterpret_cast<BYTE*>(&tokenDeviceGroups->Groups[i].Attributes), sizeof(DWORD), outputStream); outputStream << std::endl;
		}

		delete[] tokenDeviceGroups;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenRestrictedDeviceGroupsA(HANDLE token, std::ostream& outputStream) {
	try {
		// Always returns parameter incorrect.
		outputStream << "Token Restricted Device Groups: Not supported" << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenSecurityAttributesA(HANDLE token, std::ostream& outputStream) {
	try {
		CLAIM_SECURITY_ATTRIBUTES_INFORMATION* tokenSecurityAttributes = EzGetTokenSecurityAttributes(token);

		outputStream << "Token Security Attributes: TODO" << std::endl;

		delete[] tokenSecurityAttributes;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenIsRestrictedA(HANDLE token, std::ostream& outputStream) {
	try {
		BOOL tokenIsRestricted = EzGetTokenIsRestricted(token);

		outputStream << "Token Is Restricted: "; EzPrintBoolA(tokenIsRestricted, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenProcessTrustLevelA(HANDLE token, std::ostream& outputStream) {
	try {
		PSID tokenProcessTrustLevel = EzGetTokenProcessTrustLevel(token);

		outputStream << "Token Process Trust Level: "; EzPrintSidA(tokenProcessTrustLevel, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenPrivateNameSpaceA(HANDLE token, std::ostream& outputStream) {
	try {
		BOOL tokenPrivateNameSpace = EzGetTokenPrivateNameSpace(token);

		outputStream << "Token Private Name Space: "; EzPrintBoolA(tokenPrivateNameSpace, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenSingletonAttributesA(HANDLE token, std::ostream& outputStream) {
	try {
		CLAIM_SECURITY_ATTRIBUTES_INFORMATION* tokenSingletonAttributes = EzGetTokenSingletonAttributes(token);

		outputStream << "Token Singleton Attributes: TODO" << std::endl;

		delete[] tokenSingletonAttributes;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenBnoIsolationA(HANDLE token, std::ostream& outputStream) {
	try {
		TOKEN_BNO_ISOLATION_INFORMATION tokenBnoIsolation = EzGetTokenBnoIsolation(token);

		outputStream << "Token BNO Isolation:" << std::endl;
		outputStream << "    Prefix: "; if (tokenBnoIsolation.IsolationPrefix == NULL) { outputStream << "NUL"; }
		else { outputStream << tokenBnoIsolation.IsolationPrefix; } outputStream << std::endl;
		outputStream << "    Enabled: "; EzPrintBoolA(tokenBnoIsolation.IsolationEnabled, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenChildProcessFlagsA(HANDLE token, std::ostream& outputStream) {
	try {
		// Always returns parameter incorrect.
		outputStream << "Token Child Process Flags: Not supported" << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenIsLessPrivilegedAppContainerA(HANDLE token, std::ostream& outputStream) {
	try {
		// Always returns parameter incorrect.
		outputStream << "Token Is Less Privileged App Container: Not supported" << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenIsSandboxedA(HANDLE token, std::ostream& outputStream) {
	try {
		BOOL tokenIsSandboxed = EzGetTokenIsSandboxed(token);

		outputStream << "Token Is Sandboxed: "; EzPrintBoolA(tokenIsSandboxed, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenIsAppSiloA(HANDLE token, std::ostream& outputStream) {
	try {
		// Always returns parameter incorrect.
		outputStream << "Token Is App Silo: Not supported" << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenLoggingInformationA(HANDLE token, std::ostream& outputStream) {
	try {
		// Always returns parameter incorrect.
		outputStream << "Token Logging Information: Not supported" << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintMaxTokenInfoClassA(HANDLE token, std::ostream& outputStream) {
	try {
		// Always returns parameter incorrect.
		outputStream << "Max Token Info Class: Not supported" << std::endl;
	}
	catch (EzError error) { error.Print(); }
}



// Printing info about tokens to a Unicode stream
void EzPrintTokenUserW(HANDLE token, std::wostream& outputStream) {
	try {
		SID_AND_ATTRIBUTES tokenUser = EzGetTokenUser(token);

		outputStream << L"Token User:" << std::endl;
		outputStream << L"    SID: "; EzPrintSidW(tokenUser.Sid, outputStream); outputStream << std::endl;
		outputStream << L"    Attributes: "; EzPrintBinaryW(reinterpret_cast<BYTE*>(&tokenUser.Attributes), sizeof(DWORD), outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenGroupsW(HANDLE token, std::wostream& outputStream) {
	try {
		TOKEN_GROUPS* tokenGroups = EzGetTokenGroups(token);

		outputStream << L"Token Groups [" << tokenGroups->GroupCount << L"]:"; if (tokenGroups->GroupCount == 0) { outputStream << L" None"; } outputStream << std::endl;
		for (DWORD i = 0; i < tokenGroups->GroupCount; i++)
		{
			if (i != 0) { outputStream << std::endl; }
			outputStream << L"   SID: "; EzPrintSidW(tokenGroups->Groups[i].Sid, outputStream); outputStream << std::endl;
			outputStream << L"   Attributes: "; EzPrintBinaryW(reinterpret_cast<BYTE*>(&tokenGroups->Groups[i].Attributes), sizeof(DWORD), outputStream); outputStream << std::endl;
		}

		delete[] tokenGroups;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenPrivilegesW(HANDLE token, std::wostream& outputStream) {
	try {
		TOKEN_PRIVILEGES* tokenPrivileges = EzGetTokenPrivileges(token);

		outputStream << L"Token Privileges [" << tokenPrivileges->PrivilegeCount << L"]:"; if (tokenPrivileges->PrivilegeCount == 0) { outputStream << L" None"; } outputStream << std::endl;
		for (DWORD i = 0; i < tokenPrivileges->PrivilegeCount; i++)
		{
			if (i != 0) { outputStream << std::endl; }
			outputStream << L"    LUID: "; EzPrintLuidW(tokenPrivileges->Privileges[i].Luid, outputStream); outputStream << std::endl;
			outputStream << L"    Attributes: "; EzPrintBinaryW(reinterpret_cast<BYTE*>(&tokenPrivileges->Privileges[i].Attributes), 4, outputStream); outputStream << std::endl;
		}

		delete[] tokenPrivileges;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenOwnerW(HANDLE token, std::wostream& outputStream) {
	try {
		PSID tokenOwner = EzGetTokenOwner(token);

		outputStream << L"Token Owner: "; EzPrintSidW(tokenOwner, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenPrimaryGroupW(HANDLE token, std::wostream& outputStream) {
	try {
		PSID tokenPrimaryGroup = EzGetTokenPrimaryGroup(token);

		outputStream << L"Token Primary Group: "; EzPrintSidW(tokenPrimaryGroup, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenDefaultDaclW(HANDLE token, std::wostream& outputStream) {
	try {
		TOKEN_DEFAULT_DACL* tokenDefaultDacl = EzGetTokenDefaultDacl(token);

		if (tokenDefaultDacl->DefaultDacl == NULL) {
			outputStream << L"Token Default DACL: NULL" << std::endl;
		}
		else {
			outputStream << L"Token Default DACL:" << std::endl;
			outputStream << L"    ACL Revision: " << tokenDefaultDacl->DefaultDacl->AclRevision << std::endl;
			outputStream << L"    ACL Size: " << tokenDefaultDacl->DefaultDacl->AclSize << std::endl;
			outputStream << L"    ACE List [" << tokenDefaultDacl->DefaultDacl->AceCount << L"]:"; if (tokenDefaultDacl->DefaultDacl->AceCount == 0) { outputStream << L" None"; } outputStream << std::endl;
			for (DWORD i = 0; i < tokenDefaultDacl->DefaultDacl->AceCount; i++)
			{
				if (i != 0) { outputStream << std::endl; }
				ACE_HEADER* currentACE = NULL;
				GetAce(tokenDefaultDacl->DefaultDacl, i, reinterpret_cast<void**>(&currentACE));
				outputStream << L"    Type: " << currentACE->AceType << std::endl;
				outputStream << L"    Flags: " << currentACE->AceFlags << std::endl;
				outputStream << L"    Size: " << currentACE->AceSize << std::endl;
			}
		}

		delete[] tokenDefaultDacl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenSourceW(HANDLE token, std::wostream& outputStream) {
	try {
		TOKEN_SOURCE tokenSource = EzGetTokenSource(token);

		CHAR safeSourceName[9];
		memcpy(safeSourceName, tokenSource.SourceName, 8);
		safeSourceName[8] = '\0';

		outputStream << L"Token Source:" << std::endl;
		outputStream << L"    Name: " << safeSourceName << std::endl;
		outputStream << L"    Identifier: "; EzPrintLuidW(tokenSource.SourceIdentifier, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenTypeW(HANDLE token, std::wostream& outputStream) {
	try {
		TOKEN_TYPE tokenType = EzGetTokenType(token);

		outputStream << L"Token Type: ";
		if (tokenType == TokenPrimary) {
			outputStream << L"Primary";
		}
		else if (tokenType == TokenImpersonation) {
			outputStream << L"Impersonation";
		}
		else {
			outputStream << L"Invalid";
		}
		outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenImpersonationLevelW(HANDLE token, std::wostream& outputStream) {
	try {
		TOKEN_TYPE tokenType = EzGetTokenType(token);
		if (tokenType != TokenImpersonation) {
			outputStream << L"Token Impersonation Level: N/A" << std::endl;
			return;
		}

		SECURITY_IMPERSONATION_LEVEL tokenImpersonationLevel = EzGetTokenImpersonationLevel(token);

		outputStream << L"Token Impersonation Level: ";
		if (tokenImpersonationLevel == SecurityAnonymous) {
			outputStream << L"Anonymous";
		}
		else if (tokenImpersonationLevel == SecurityIdentification) {
			outputStream << L"Identification";
		}
		else if (tokenImpersonationLevel == SecurityImpersonation) {
			outputStream << L"Impersonation";
		}
		else if (tokenImpersonationLevel == SecurityDelegation) {
			outputStream << L"Delegation";
		}
		else {
			outputStream << L"Invalid";
		}
		outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenStatisticsW(HANDLE token, std::wostream& outputStream) {
	try {
		TOKEN_STATISTICS tokenStatistics = EzGetTokenStatistics(token);

		outputStream << L"Token Statistics:" << std::endl;
		outputStream << L"    Token ID: "; EzPrintLuidW(tokenStatistics.TokenId, outputStream); outputStream << std::endl;
		outputStream << L"    Authentication ID: "; EzPrintLuidW(tokenStatistics.AuthenticationId, outputStream); outputStream << std::endl;
		outputStream << L"    Token Type: ";
		if (tokenStatistics.TokenType == TokenPrimary) {
			outputStream << L"Primary";
		}
		else if (tokenStatistics.TokenType == TokenImpersonation) {
			outputStream << L"Impersonation";
		}
		else {
			outputStream << L"Invalid";
		}
		outputStream << std::endl;
		if (tokenStatistics.TokenType != TokenImpersonation) {
			outputStream << L"    Impersonation Level: N/A" << std::endl;
		}
		else {
			outputStream << L"    Impersonation Level: ";
			if (tokenStatistics.ImpersonationLevel == SecurityAnonymous) {
				outputStream << L"Anonymous";
			}
			else if (tokenStatistics.ImpersonationLevel == SecurityIdentification) {
				outputStream << L"Identification";
			}
			else if (tokenStatistics.ImpersonationLevel == SecurityImpersonation) {
				outputStream << L"Impersonation";
			}
			else if (tokenStatistics.ImpersonationLevel == SecurityDelegation) {
				outputStream << L"Delegation";
			}
			else {
				outputStream << L"Invalid";
			}
			outputStream << std::endl;
		}
		outputStream << L"    Dynamic Charged: " << tokenStatistics.DynamicCharged << std::endl;
		outputStream << L"    Dynamic Available: " << tokenStatistics.DynamicAvailable << std::endl;
		outputStream << L"    Group Count: " << tokenStatistics.GroupCount << std::endl;
		outputStream << L"    Privilege Count: " << tokenStatistics.PrivilegeCount << std::endl;
		outputStream << L"    Modified ID: "; EzPrintLuidW(tokenStatistics.ModifiedId, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenRestrictedSidsW(HANDLE token, std::wostream& outputStream) {
	try {
		TOKEN_GROUPS* tokenRestrictedSids = EzGetTokenRestrictedSids(token);

		outputStream << L"Token Restricted SIDs [" << tokenRestrictedSids->GroupCount << L"]:"; if (tokenRestrictedSids->GroupCount == 0) { outputStream << L" None"; } outputStream << std::endl;
		for (DWORD i = 0; i < tokenRestrictedSids->GroupCount; i++)
		{
			if (i != 0) { outputStream << std::endl; }
			outputStream << L"    SID: "; EzPrintSidW(tokenRestrictedSids->Groups[i].Sid, outputStream); outputStream << std::endl;
			outputStream << L"    Attributes: "; EzPrintBinaryW(reinterpret_cast<BYTE*>(&tokenRestrictedSids->Groups[i].Attributes), sizeof(DWORD), outputStream); outputStream << std::endl;
		}

		delete[] tokenRestrictedSids;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenSessionIdW(HANDLE token, std::wostream& outputStream) {
	try {
		DWORD tokenSessionId = EzGetTokenSessionId(token);

		outputStream << L"Token Session ID: " << tokenSessionId << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenGroupsAndPrivilegesW(HANDLE token, std::wostream& outputStream) {
	try {
		outputStream << L"Token Groups And Privileges: Information already printed." << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenSessionReferenceW(HANDLE token, std::wostream& outputStream) {
	try {
		// Always returns parameter incorrect.
		outputStream << L"Token Session Refrences: Not supported" << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenSandBoxInertW(HANDLE token, std::wostream& outputStream) {
	try {
		BOOL tokenSandBoxInert = EzGetTokenSandBoxInert(token);

		outputStream << L"Token Sand Box Inert: "; EzPrintBoolW(tokenSandBoxInert, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenAuditPolicyW(HANDLE token, std::wostream& outputStream) {
	try {
		// Always returns access denied.
		outputStream << L"Token Audit Policy: Only accessible from kernel mode." << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenOriginW(HANDLE token, std::wostream& outputStream) {
	try {
		LUID tokenOrigin = EzGetTokenOrigin(token);

		outputStream << L"Token Origin: "; EzPrintLuidW(tokenOrigin, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenElevationTypeW(HANDLE token, std::wostream& outputStream) {
	try {
		TOKEN_ELEVATION_TYPE tokenElevationType = EzGetTokenElevationType(token);

		outputStream << L"Token Elevation Type: ";
		if (tokenElevationType == TokenElevationTypeDefault) {
			outputStream << L"Default";
		}
		else if (tokenElevationType == TokenElevationTypeFull) {
			outputStream << L"Full";
		}
		else if (tokenElevationType == TokenElevationTypeLimited) {
			outputStream << L"Limited";
		}
		else {
			outputStream << L"Invalid";
		}
		outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenLinkedTokenW(HANDLE token, std::wostream& outputStream) {
	try {
		HANDLE tokenLinkedToken = EzGetTokenLinkedToken(token);

		outputStream << L"Token Linked Token: "; EzPrintHexW(reinterpret_cast<BYTE*>(&tokenLinkedToken), sizeof(HANDLE), outputStream); outputStream << std::endl;

		EzCloseHandleSafely(tokenLinkedToken);
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenElevationW(HANDLE token, std::wostream& outputStream) {
	try {
		BOOL tokenElevation = EzGetTokenElevation(token);

		outputStream << L"Token Is Elevated: "; EzPrintBoolW(tokenElevation, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenHasRestrictionsW(HANDLE token, std::wostream& outputStream) {
	try {
		BOOL tokenHasRestrictions = EzGetTokenHasRestrictions(token);

		outputStream << L"Token Has Restrictions: "; EzPrintBoolW(tokenHasRestrictions, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenAccessInformationW(HANDLE token, std::wostream& outputStream) {
	try {
		TOKEN_ACCESS_INFORMATION tokenAccessInformation = EzGetTokenAccessInformation(token);

		outputStream << L"Token Access Information: TODO" << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenVirtualizationAllowedW(HANDLE token, std::wostream& outputStream) {
	try {
		BOOL tokenVirtualizationAllowed = EzGetTokenVirtualizationAllowed(token);

		outputStream << L"Token Virtualization Allowed: "; EzPrintBoolW(tokenVirtualizationAllowed, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenVirtualizationEnabledW(HANDLE token, std::wostream& outputStream) {
	try {
		BOOL tokenVirtualizationEnabled = EzGetTokenVirtualizationEnabled(token);

		outputStream << L"Token Virtualization Enabled: "; EzPrintBoolW(tokenVirtualizationEnabled, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenIntegrityLevelW(HANDLE token, std::wostream& outputStream) {
	try {
		SID_AND_ATTRIBUTES tokenIntegrityLevel = EzGetTokenIntegrityLevel(token);

		outputStream << L"Token Integrity Level:" << std::endl;
		outputStream << L"    SID: "; EzPrintSidW(tokenIntegrityLevel.Sid, outputStream); outputStream << std::endl;
		outputStream << L"    Attributes: "; EzPrintBinaryW(reinterpret_cast<BYTE*>(&tokenIntegrityLevel.Attributes), sizeof(DWORD), outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenUIAccessW(HANDLE token, std::wostream& outputStream) {
	try {
		BOOL tokenUIAccess = EzGetTokenUIAccess(token);

		outputStream << L"Token UI Access: "; EzPrintBoolW(tokenUIAccess, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenMandatoryPolicyW(HANDLE token, std::wostream& outputStream) {
	try {
		DWORD tokenMandatoryPolicy = EzGetTokenMandatoryPolicy(token);

		outputStream << L"Token Mandatory Policy: " << tokenMandatoryPolicy << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenLogonSidW(HANDLE token, std::wostream& outputStream) {
	try {
		TOKEN_GROUPS* tokenLogonSid = EzGetTokenLogonSid(token);

		outputStream << L"Token Logon Sids [" << tokenLogonSid->GroupCount << L"]:"; if (tokenLogonSid->GroupCount == 0) { outputStream << L" None"; } outputStream << std::endl;
		for (DWORD i = 0; i < tokenLogonSid->GroupCount; i++)
		{
			if (i != 0) { outputStream << std::endl; }
			outputStream << L"    SID: "; EzPrintSidW(tokenLogonSid->Groups[i].Sid, outputStream); outputStream << std::endl;
			outputStream << L"    Attributes: "; EzPrintBinaryW(reinterpret_cast<BYTE*>(&tokenLogonSid->Groups[i].Attributes), sizeof(DWORD), outputStream); outputStream << std::endl;
		}

		delete[] tokenLogonSid;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenIsAppContainerW(HANDLE token, std::wostream& outputStream) {
	try {
		BOOL tokenIsAppContainer = EzGetTokenIsAppContainer(token);

		outputStream << L"Token Is App Container: "; EzPrintBoolW(tokenIsAppContainer, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenCapabilitiesW(HANDLE token, std::wostream& outputStream) {
	try {
		TOKEN_GROUPS* tokenCapabilities = EzGetTokenCapabilities(token);

		outputStream << L"Token Capabilities [" << tokenCapabilities->GroupCount << L"]:"; if (tokenCapabilities->GroupCount == 0) { outputStream << L" None"; } outputStream << std::endl;
		for (DWORD i = 0; i < tokenCapabilities->GroupCount; i++)
		{
			if (i != 0) { outputStream << std::endl; }
			outputStream << L"    SID: "; EzPrintSidW(tokenCapabilities->Groups[i].Sid, outputStream); outputStream << std::endl;
			outputStream << L"    Attributes: "; EzPrintBinaryW(reinterpret_cast<BYTE*>(&tokenCapabilities->Groups[i].Attributes), sizeof(DWORD), outputStream); outputStream << std::endl;
		}

		delete[] tokenCapabilities;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenAppContainerSidW(HANDLE token, std::wostream& outputStream) {
	try {
		PSID tokenAppContainerSid = EzGetTokenAppContainerSid(token);

		outputStream << L"Token App Container SID: "; EzPrintSidW(tokenAppContainerSid, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenAppContainerNumberW(HANDLE token, std::wostream& outputStream) {
	try {
		DWORD tokenAppContainerNumber = EzGetTokenAppContainerNumber(token);

		outputStream << L"Token App Container Number: " << tokenAppContainerNumber << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenUserClaimAttributesW(HANDLE token, std::wostream& outputStream) {
	try {
		CLAIM_SECURITY_ATTRIBUTES_INFORMATION* tokenUserClaimAttributes = EzGetTokenUserClaimAttributes(token);

		outputStream << L"Token User Claim Attributes:" << std::endl;
		outputStream << L"    Version: " << tokenUserClaimAttributes->Version << std::endl;
		outputStream << L"    Reserved: " << tokenUserClaimAttributes->Reserved << std::endl;
		outputStream << L"    Attributes [" << tokenUserClaimAttributes->AttributeCount << L"]:"; if (tokenUserClaimAttributes->AttributeCount == 0) { outputStream << L" None"; } outputStream << std::endl;
		for (DWORD i = 0; i < tokenUserClaimAttributes->AttributeCount; i++)
		{
			CLAIM_SECURITY_ATTRIBUTE_V1 attribute = tokenUserClaimAttributes->Attribute.pAttributeV1[i];
			outputStream << L"        Name: " << attribute.Name << std::endl;
			outputStream << L"        Value Type: " << attribute.ValueType << std::endl;
			outputStream << L"        Reserved: " << attribute.Reserved << std::endl;
			outputStream << L"        Flags: "; EzPrintBinaryW(reinterpret_cast<BYTE*>(&attribute.Flags), sizeof(DWORD), outputStream); outputStream << std::endl;
			outputStream << L"        Value Count: " << attribute.ValueCount << std::endl;
			outputStream << L"        Values:" << std::endl;
			for (DWORD j = 0; j < attribute.ValueCount; j++)
			{
				outputStream << L"            TODO" << std::endl;
			}
			outputStream << std::endl;
		}

		delete[] tokenUserClaimAttributes;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenDeviceClaimAttributesW(HANDLE token, std::wostream& outputStream) {
	try {
		CLAIM_SECURITY_ATTRIBUTES_INFORMATION* tokenDeviceClaimAttributes = EzGetTokenDeviceClaimAttributes(token);

		outputStream << L"Token Device Claim Attributes: TODO" << std::endl;

		delete[] tokenDeviceClaimAttributes;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenRestrictedUserClaimAttributesW(HANDLE token, std::wostream& outputStream) {
	try {
		// Always returns parameter incorrect.
		outputStream << L"Token Restricted User Claim Attributes: Not supported" << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenRestrictedDeviceClaimAttributesW(HANDLE token, std::wostream& outputStream) {
	try {
		// Always returns parameter incorrect.
		outputStream << L"Token Restricted Device Claim Attributes: Not supported" << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenDeviceGroupsW(HANDLE token, std::wostream& outputStream) {
	try {
		TOKEN_GROUPS* tokenDeviceGroups = EzGetTokenDeviceGroups(token);

		outputStream << L"Token Device Groups [" << tokenDeviceGroups->GroupCount << L"]:"; if (tokenDeviceGroups->GroupCount == 0) { outputStream << L" None"; } outputStream << std::endl;
		for (DWORD i = 0; i < tokenDeviceGroups->GroupCount; i++)
		{
			if (i != 0) { outputStream << std::endl; }
			outputStream << L"    SID: "; EzPrintSidW(tokenDeviceGroups->Groups[i].Sid, outputStream); outputStream << std::endl;
			outputStream << L"    Attributes: "; EzPrintBinaryW(reinterpret_cast<BYTE*>(&tokenDeviceGroups->Groups[i].Attributes), sizeof(DWORD), outputStream); outputStream << std::endl;
		}

		delete[] tokenDeviceGroups;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenRestrictedDeviceGroupsW(HANDLE token, std::wostream& outputStream) {
	try {
		// Always returns parameter incorrect.
		outputStream << L"Token Restricted Device Groups: Not supported" << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenSecurityAttributesW(HANDLE token, std::wostream& outputStream) {
	try {
		CLAIM_SECURITY_ATTRIBUTES_INFORMATION* tokenSecurityAttributes = EzGetTokenSecurityAttributes(token);

		outputStream << L"Token Security Attributes: TODO" << std::endl;

		delete[] tokenSecurityAttributes;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenIsRestrictedW(HANDLE token, std::wostream& outputStream) {
	try {
		BOOL tokenIsRestricted = EzGetTokenIsRestricted(token);

		outputStream << L"Token Is Restricted: "; EzPrintBoolW(tokenIsRestricted, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenProcessTrustLevelW(HANDLE token, std::wostream& outputStream) {
	try {
		PSID tokenProcessTrustLevel = EzGetTokenProcessTrustLevel(token);

		outputStream << L"Token Process Trust Level: "; EzPrintSidW(tokenProcessTrustLevel, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenPrivateNameSpaceW(HANDLE token, std::wostream& outputStream) {
	try {
		BOOL tokenPrivateNameSpace = EzGetTokenPrivateNameSpace(token);

		outputStream << L"Token Private Name Space: "; EzPrintBoolW(tokenPrivateNameSpace, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenSingletonAttributesW(HANDLE token, std::wostream& outputStream) {
	try {
		CLAIM_SECURITY_ATTRIBUTES_INFORMATION* tokenSingletonAttributes = EzGetTokenSingletonAttributes(token);

		outputStream << L"Token Singleton Attributes: TODO" << std::endl;

		delete[] tokenSingletonAttributes;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenBnoIsolationW(HANDLE token, std::wostream& outputStream) {
	try {
		TOKEN_BNO_ISOLATION_INFORMATION tokenBnoIsolation = EzGetTokenBnoIsolation(token);

		outputStream << L"Token BNO Isolation:" << std::endl;
		outputStream << L"    Prefix: "; if (tokenBnoIsolation.IsolationPrefix == NULL) { outputStream << L"NULL"; }
		else { outputStream << tokenBnoIsolation.IsolationPrefix; } outputStream << std::endl;
		outputStream << L"    Enabled: "; EzPrintBoolW(tokenBnoIsolation.IsolationEnabled, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenChildProcessFlagsW(HANDLE token, std::wostream& outputStream) {
	try {
		// Always returns parameter incorrect.
		outputStream << L"Token Child Process Flags: Not supported" << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenIsLessPrivilegedAppContainerW(HANDLE token, std::wostream& outputStream) {
	try {
		// Always returns parameter incorrect.
		outputStream << L"Token Is Less Privileged App Container: Not supported" << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenIsSandboxedW(HANDLE token, std::wostream& outputStream) {
	try {
		BOOL tokenIsSandboxed = EzGetTokenIsSandboxed(token);

		outputStream << L"Token Is Sandboxed: "; EzPrintBoolW(tokenIsSandboxed, outputStream); outputStream << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenIsAppSiloW(HANDLE token, std::wostream& outputStream) {
	try {
		// Always returns parameter incorrect.
		outputStream << L"Token Is App Silo: Not supported" << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintTokenLoggingInformationW(HANDLE token, std::wostream& outputStream) {
	try {
		// Always returns parameter incorrect.
		outputStream << L"Token Logging Information: Not supported" << std::endl;
	}
	catch (EzError error) { error.Print(); }
}
void EzPrintMaxTokenInfoClassW(HANDLE token, std::wostream& outputStream) {
	try {
		// Always returns parameter incorrect.
		outputStream << L"Max Token Info Class: Not supported" << std::endl;
	}
	catch (EzError error) { error.Print(); }
}



// General printing functions to print all info
void EzPrintTokenInfoA(HANDLE token, std::ostream& outputStream) {
	outputStream << "Token Handle: "; EzPrintHexA(reinterpret_cast<BYTE*>(&token), sizeof(HANDLE), outputStream); outputStream << std::endl << std::endl;

	EzPrintTokenUserA(token, outputStream); outputStream << std::endl;
	EzPrintTokenGroupsA(token, outputStream); outputStream << std::endl;
	EzPrintTokenPrivilegesA(token, outputStream); outputStream << std::endl;
	EzPrintTokenOwnerA(token, outputStream); outputStream << std::endl;
	EzPrintTokenPrimaryGroupA(token, outputStream); outputStream << std::endl;
	EzPrintTokenDefaultDaclA(token, outputStream); outputStream << std::endl;
	EzPrintTokenSourceA(token, outputStream); outputStream << std::endl;
	EzPrintTokenTypeA(token, outputStream); outputStream << std::endl;
	EzPrintTokenImpersonationLevelA(token, outputStream); outputStream << std::endl;
	EzPrintTokenStatisticsA(token, outputStream); outputStream << std::endl;
	EzPrintTokenRestrictedSidsA(token, outputStream); outputStream << std::endl;
	EzPrintTokenSessionIdA(token, outputStream); outputStream << std::endl;
	EzPrintTokenGroupsAndPrivilegesA(token, outputStream); outputStream << std::endl;
	EzPrintTokenSessionReferenceA(token, outputStream); outputStream << std::endl;
	EzPrintTokenSandBoxInertA(token, outputStream); outputStream << std::endl;
	EzPrintTokenAuditPolicyA(token, outputStream); outputStream << std::endl;
	EzPrintTokenOriginA(token, outputStream); outputStream << std::endl;
	EzPrintTokenElevationTypeA(token, outputStream); outputStream << std::endl;
	EzPrintTokenLinkedTokenA(token, outputStream); outputStream << std::endl;
	EzPrintTokenElevationA(token, outputStream); outputStream << std::endl;
	EzPrintTokenHasRestrictionsA(token, outputStream); outputStream << std::endl;
	EzPrintTokenAccessInformationA(token, outputStream); outputStream << std::endl;
	EzPrintTokenVirtualizationAllowedA(token, outputStream); outputStream << std::endl;
	EzPrintTokenVirtualizationEnabledA(token, outputStream); outputStream << std::endl;
	EzPrintTokenIntegrityLevelA(token, outputStream); outputStream << std::endl;
	EzPrintTokenUIAccessA(token, outputStream); outputStream << std::endl;
	EzPrintTokenMandatoryPolicyA(token, outputStream); outputStream << std::endl;
	EzPrintTokenLogonSidA(token, outputStream); outputStream << std::endl;
	EzPrintTokenIsAppContainerA(token, outputStream); outputStream << std::endl;
	EzPrintTokenCapabilitiesA(token, outputStream); outputStream << std::endl;
	EzPrintTokenAppContainerSidA(token, outputStream); outputStream << std::endl;
	EzPrintTokenAppContainerNumberA(token, outputStream); outputStream << std::endl;
	EzPrintTokenUserClaimAttributesA(token, outputStream); outputStream << std::endl;
	EzPrintTokenDeviceClaimAttributesA(token, outputStream); outputStream << std::endl;
	EzPrintTokenRestrictedUserClaimAttributesA(token, outputStream); outputStream << std::endl;
	EzPrintTokenRestrictedDeviceClaimAttributesA(token, outputStream); outputStream << std::endl;
	EzPrintTokenDeviceGroupsA(token, outputStream); outputStream << std::endl;
	EzPrintTokenRestrictedDeviceGroupsA(token, outputStream); outputStream << std::endl;
	EzPrintTokenSecurityAttributesA(token, outputStream); outputStream << std::endl;
	EzPrintTokenIsRestrictedA(token, outputStream); outputStream << std::endl;
	EzPrintTokenProcessTrustLevelA(token, outputStream); outputStream << std::endl;
	EzPrintTokenPrivateNameSpaceA(token, outputStream); outputStream << std::endl;
	EzPrintTokenSingletonAttributesA(token, outputStream); outputStream << std::endl;
	EzPrintTokenBnoIsolationA(token, outputStream); outputStream << std::endl;
	EzPrintTokenChildProcessFlagsA(token, outputStream); outputStream << std::endl;
	EzPrintTokenIsLessPrivilegedAppContainerA(token, outputStream); outputStream << std::endl;
	EzPrintTokenIsSandboxedA(token, outputStream); outputStream << std::endl;
	EzPrintTokenIsAppSiloA(token, outputStream); outputStream << std::endl;
	EzPrintTokenLoggingInformationA(token, outputStream); outputStream << std::endl;
	EzPrintMaxTokenInfoClassA(token, outputStream); outputStream << std::endl;
}
void EzPrintTokenInfoW(HANDLE token, std::wostream& outputStream) {
	outputStream << L"Token Handle: "; EzPrintHexW(reinterpret_cast<BYTE*>(&token), sizeof(HANDLE), outputStream); outputStream << std::endl << std::endl;

	EzPrintTokenUserW(token, outputStream); outputStream << std::endl;
	EzPrintTokenGroupsW(token, outputStream); outputStream << std::endl;
	EzPrintTokenPrivilegesW(token, outputStream); outputStream << std::endl;
	EzPrintTokenOwnerW(token, outputStream); outputStream << std::endl;
	EzPrintTokenPrimaryGroupW(token, outputStream); outputStream << std::endl;
	EzPrintTokenDefaultDaclW(token, outputStream); outputStream << std::endl;
	EzPrintTokenSourceW(token, outputStream); outputStream << std::endl;
	EzPrintTokenTypeW(token, outputStream); outputStream << std::endl;
	EzPrintTokenImpersonationLevelW(token, outputStream); outputStream << std::endl;
	EzPrintTokenStatisticsW(token, outputStream); outputStream << std::endl;
	EzPrintTokenRestrictedSidsW(token, outputStream); outputStream << std::endl;
	EzPrintTokenSessionIdW(token, outputStream); outputStream << std::endl;
	EzPrintTokenGroupsAndPrivilegesW(token, outputStream); outputStream << std::endl;
	EzPrintTokenSessionReferenceW(token, outputStream); outputStream << std::endl;
	EzPrintTokenSandBoxInertW(token, outputStream); outputStream << std::endl;
	EzPrintTokenAuditPolicyW(token, outputStream); outputStream << std::endl;
	EzPrintTokenOriginW(token, outputStream); outputStream << std::endl;
	EzPrintTokenElevationTypeW(token, outputStream); outputStream << std::endl;
	EzPrintTokenLinkedTokenW(token, outputStream); outputStream << std::endl;
	EzPrintTokenElevationW(token, outputStream); outputStream << std::endl;
	EzPrintTokenHasRestrictionsW(token, outputStream); outputStream << std::endl;
	EzPrintTokenAccessInformationW(token, outputStream); outputStream << std::endl;
	EzPrintTokenVirtualizationAllowedW(token, outputStream); outputStream << std::endl;
	EzPrintTokenVirtualizationEnabledW(token, outputStream); outputStream << std::endl;
	EzPrintTokenIntegrityLevelW(token, outputStream); outputStream << std::endl;
	EzPrintTokenUIAccessW(token, outputStream); outputStream << std::endl;
	EzPrintTokenMandatoryPolicyW(token, outputStream); outputStream << std::endl;
	EzPrintTokenLogonSidW(token, outputStream); outputStream << std::endl;
	EzPrintTokenIsAppContainerW(token, outputStream); outputStream << std::endl;
	EzPrintTokenCapabilitiesW(token, outputStream); outputStream << std::endl;
	EzPrintTokenAppContainerSidW(token, outputStream); outputStream << std::endl;
	EzPrintTokenAppContainerNumberW(token, outputStream); outputStream << std::endl;
	EzPrintTokenUserClaimAttributesW(token, outputStream); outputStream << std::endl;
	EzPrintTokenDeviceClaimAttributesW(token, outputStream); outputStream << std::endl;
	EzPrintTokenRestrictedUserClaimAttributesW(token, outputStream); outputStream << std::endl;
	EzPrintTokenRestrictedDeviceClaimAttributesW(token, outputStream); outputStream << std::endl;
	EzPrintTokenDeviceGroupsW(token, outputStream); outputStream << std::endl;
	EzPrintTokenRestrictedDeviceGroupsW(token, outputStream); outputStream << std::endl;
	EzPrintTokenSecurityAttributesW(token, outputStream); outputStream << std::endl;
	EzPrintTokenIsRestrictedW(token, outputStream); outputStream << std::endl;
	EzPrintTokenProcessTrustLevelW(token, outputStream); outputStream << std::endl;
	EzPrintTokenPrivateNameSpaceW(token, outputStream); outputStream << std::endl;
	EzPrintTokenSingletonAttributesW(token, outputStream); outputStream << std::endl;
	EzPrintTokenBnoIsolationW(token, outputStream); outputStream << std::endl;
	EzPrintTokenChildProcessFlagsW(token, outputStream); outputStream << std::endl;
	EzPrintTokenIsLessPrivilegedAppContainerW(token, outputStream); outputStream << std::endl;
	EzPrintTokenIsSandboxedW(token, outputStream); outputStream << std::endl;
	EzPrintTokenIsAppSiloW(token, outputStream); outputStream << std::endl;
	EzPrintTokenLoggingInformationW(token, outputStream); outputStream << std::endl;
	EzPrintMaxTokenInfoClassW(token, outputStream); outputStream << std::endl;
}