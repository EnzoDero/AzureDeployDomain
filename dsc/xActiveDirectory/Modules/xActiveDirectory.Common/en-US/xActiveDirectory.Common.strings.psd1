# Localized resources for helper module xActiveDirectory.Common.

ConvertFrom-StringData @'
    WasExpectingDomainController        = The operating system product type code returned 2, which indicates that this is domain controller, but was unable to retrieve the domain controller object. (ADCOMMON0001)
    FailedEvaluatingDomainController    = Could not evaluate if the node is a domain controller. (ADCOMMON0002)
    EvaluatePropertyState               = Evaluating the state of the property '{0}'. (ADCOMMON0003)
    PropertyInDesiredState              = The parameter '{0}' is in desired state. (ADCOMMON0004)
    PropertyNotInDesiredState           = The parameter '{0}' is not in desired state. (ADCOMMON0005)
    ArrayDoesNotMatch                   = One or more values in an array does not match the desired state. Details of the changes are below. (ADCOMMON0006)
    ArrayValueThatDoesNotMatch          = {0} - {1} (ADCOMMON0007)
    PropertyValueOfTypeDoesNotMatch     = {0} value does not match. Current value is '{1}', but expected the value '{2}'. (ADCOMMON0008)
    UnableToCompareType                 = Unable to compare the type {0} as it is not handled by the Test-DscPropertyState cmdlet. (ADCOMMON0009)
    RoleNotFoundError                   = Please ensure that the PowerShell module for role '{0}' is installed. (ADCOMMON0010)
    MembersAndIncludeExcludeError       = The '{0}' and '{1}' and/or '{2}' parameters conflict. The '{0}' parameter should not be used in any combination with the '{1}' and '{2}' parameters. (ADCOMMON0011)
    MembersIsNullError                  = The Members parameter value is null. The '{0}' parameter must be provided if neither '{1}' nor '{2}' is provided. (ADCOMMON0012)
    IncludeAndExcludeConflictError      = The member '{0}' is included in both '{1}' and '{2}' parameter values. The same member must not be included in both '{1}' and '{2}' parameter values. (ADCOMMON0014)
    IncludeAndExcludeAreEmptyError      = The '{0}' and '{1}' parameters are either both null or empty.  At least one member must be specified in one of these parameters. (ADCOMMON0015)
    RecycleBinRestoreFailed             = Restoring {0} ({1}) from the recycle bin failed. Error message: {2}. (ADCOMMON0017)
    EmptyDomainError                    = No domain name retrieved for group member {0} in group {1}. (ADCOMMON0018)
    CheckingMembers                     = Checking for '{0}' members. (ADCOMMON0019)
    MembershipCountMismatch             = Membership count is not correct. Expected '{0}' members, actual '{1}' members. (ADCOMMON0020)
    MemberNotInDesiredState             = Member '{0}' is not in the desired state. (ADCOMMON0021)
    RemovingDuplicateMember             = Removing duplicate member '{0}' definition. (ADCOMMON0022)
    MembershipInDesiredState            = Membership is in the desired state. (ADCOMMON0023)
    MembershipNotDesiredState           = Membership is NOT in the desired state. (ADCOMMON0024)
    CheckingSite                        = Checking for site '{0}'. (ADCOMMON0026)
    FindInRecycleBin                    = Finding objects in the recycle bin matching the filter {0}. (ADCOMMON0027)
    FoundRestoreTargetInRecycleBin      = Found object {0} ({1}) in the recycle bin as {2}. Attempting to restore the object. (ADCOMMON0028)
    RecycleBinRestoreSuccessful         = Successfully restored object {0} ({1}) from the recycle bin. (ADCOMMON0029)
    AddingGroupMember                   = Adding member '{0}' from domain '{1}' to AD group '{2}'. (ADCOMMON0030)
    PropertyMapArrayIsWrongType         = An object in the property map array is not of the type [System.Collections.Hashtable]. (ADCOMMON0031)
    CreatingNewADPSDrive                = Creating new AD: PSDrive. (ADCOMMON0032)
    CreatingNewADPSDriveError           = Error creating AD: PS Drive. (ADCOMMON0033)
    PropertyTypeInvalidForDesiredValues = Property 'DesiredValues' must be either a [System.Collections.Hashtable], [CimInstance] or [PSBoundParametersDictionary]. The type detected was {0}. (ADCOMMON0034)
    PropertyTypeInvalidForValuesToCheck = If 'DesiredValues' is a CimInstance, then property 'ValuesToCheck' must contain a value. (ADCOMMON0035)
    PropertyValidationError             = Expected to find an array value for property {0} in the current values, but it was either not present or was null. This has caused the test method to return false. (ADCOMMON0036)
    PropertiesDoesNotMatch              = Found an array for property {0} in the current values, but this array does not match the desired state. Details of the changes are below. (ADCOMMON0037)
    PropertyThatDoesNotMatch            = {0} - {1} (ADCOMMON0038)
    ValueOfTypeDoesNotMatch             = {0} value for property {1} does not match. Current state is '{2}' and desired state is '{3}'. (ADCOMMON0039)
    UnableToCompareProperty             = Unable to compare property {0} as the type {1} is not handled by the Test-DscParameterState cmdlet. (ADCOMMON0040)
    StartProcess                        = Started the process with id {0} using the path '{1}', and with a timeout value of {2} seconds. (ADCOMMON0041)
'@
