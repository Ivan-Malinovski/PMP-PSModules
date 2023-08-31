$AuthToken = "AA94E553-2A84-47B3-8C56-9A4D4B90BAF7"

# PasswordManagerPro.psm1

# Base URL for the Password Manager Pro API
$BaseURL = "https://localhost:7272/restapi/json/v1"

# Creates account in the Privileged accounts (vp02) resource
function Invoke-PMPAccountCreation {
    param(
        [Parameter(Mandatory=$true)]
        [string]$AccountName
    )

    $Headers = @{
        "AUTHTOKEN" = $AuthToken
        "Content-Type" = "text/json"
    }


    $value = @{
        INPUT_DATA = @"
{
    "operation": {
        "Details": {
            "ACCOUNTLIST": [
                {
                    "ACCOUNTNAME": "$AccountName",
                    "PASSWORD": "$AccountName",
                    "ACCOUNTPASSWORDPOLICY": "Strong",
                    "RECORD_RDP_SESSIONS": true,
                    "RECORD_CLI_SESSIONS": true,
                    "DISABLE_PASSWORD_RESETS": true,
                    "CONFIGURE_PASSWORD_RESET": true,
                    "ACCOUNT_RESOURCE_GROUP_IDS": ["3002", "3003"],
                    "IIS_WEB_CONFIG_RESET": false,
                    "IIS_APP_POOL_RESTART": false,
                    "IIS_APP_POOL_RESET": false,
                    "SERVICES_RESTART": false,
                    "SERVICES_RESET": false,
                    "SCHEDULED_TASK_RESET": true,
                    "NOTES": "Created by API User"
                }
            ]
        }
    }
}
"@
    }

    $response = Invoke-WebRequest -Uri "$BaseURL/resources/2/accounts" -Headers $Headers -Method Post -Body $value
    return $response.content
}

# Provided account name, returns ID of an account in the Privileged accounts (vp02) resource
# Run after Invoke-PMPAccountCreation with the AccountName
function Get-PMPResourceID {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Account,
        [Parameter(Mandatory=$false)]
        [string]$Resource
    )

    $Headers = @{
        "AUTHTOKEN" = $AuthToken
        "Content-Type" = "text/json"
    }


    $Resource = "Privileged accounts (vp02)"
    $url = "$BaseURL/resources/getResourceIdAccountId?RESOURCENAME=Privileged accounts (XXXXX)&ACCOUNTNAME=$AccountName"

    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
    return ($response | select -ExpandProperty operation).Details #| select -ExpandProperty RESOURCEID
}


function Get-PMPUserID {
    param(
        [Parameter(Mandatory=$true)]
        [string]$UserName
    )

    $Headers = @{
        "AUTHTOKEN" = $AuthToken
        "Content-Type" = "text/json"
    }

    $url = "$BaseURL/user/getUserId?USERNAME=MLNVSKI\$UserName"

    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
    return ($response | select -ExpandProperty operation).Details | select -ExpandProperty USERID
}


# Shares PMP account with the provided User ID
function Share-PMPAccount {
    param(
        [Parameter(Mandatory=$true)]
        [string]$AccountID,

        [Parameter(Mandatory=$true)]
        [ValidateSet("view", "modify", "revoke")]
        [string]$AccessType,

        [Parameter(Mandatory=$true)]
        [int]$UserID
    )

    $Headers = @{
        "AUTHTOKEN" = $AuthToken
        "Content-Type" = "text/json"
    }

    # Hardcoded resource ID
    $ResourceID = "2"
    $url = "$BaseURL/resources/$ResourceID/accounts/$AccountID/share"

    # Construct the input data

    $value = @{
        INPUT_DATA = @"
{
    "operation": {
        "Details": {
            "ACCESSTYPE": "$AccessType",
            "USERID": "$UserID"
        }
    }
}
"@
    }

    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Put -Body $value
    return $response.operation
}


function newPMPAdmin ($NameInput,$ShareWith) {
    # First create account in PMP
    Invoke-PMPAccountCreation -AccountName $NameInput
    
    # Then get ID of the new account
    $ID = Get-PMPResourceID -AccountName $NameInput | select -ExpandProperty AccountID

    # Create name of person it should be shared with
    $ShareName = $NameInput.replace('2','1').replace('3','1')

    # Get ID of person it shares with
    $ShareID = Get-PMPUserId -Username $ShareWith

    # Shares new PMP account with the corresponding User
    Share-PMPAccount -AccountID $ID -UserID $ShareID -AccessType view
}


add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
