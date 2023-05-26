Function Get-ADACL
{
    [CmdletBinding(DefaultParameterSetName = 'Root')]
    Param
    (
        [Parameter(Mandatory = $true,
            ParameterSetName = 'Path',
            HelpMessage = 'Enter a path or DN of an AD Object',
            Position = 0)]
        [string]$Path,
        [Parameter(Mandatory = $true,
            ParameterSetName = 'Path',
            HelpMessage = 'Accepts an Active Directory object',
            Position = 0)]
        [Microsoft.ActiveDirectory.Management.ADObject]$ADObject,
        [Parameter(Mandatory = $true,
            ParameterSetName = 'Root',
            DefaultParameterSet = $true,
            HelpMessage = 'Used to retrieve the ACL for the Root Domain Naming Context',
            Position = 0)]
        [switch]$DomainRoot
    )
    Begin
    {
        # Class that will be used to represent the security principal and corresponding AD rights::
        class IdentityAcl {
            [string]$SecurityPrincipal
            [string]$ActiveDirectoryRights
            [string]$InheritedObjectType
            [string]$InheritanceType
            [string[]]$AttributeName

            IdentityAcl($prinName, $adRights,$inheritedObjectType,$inheritanceType,$attributeName) {
                $this.SecurityPrincipal = $prinName
                $this.ActiveDirectoryRights = $adRights
                $this.InheritedObjectType = $inheritedObjectType
                $this.InheritanceType = $inheritanceType
                $this.AttributeName = $attributeName
            }
        }

        $ADRootDSE = Get-ADRootDSE
        $aclPath = ''

        #Query Schema for object types and their GUIDs
        $adTypeGUIDTable = @{}
        $GetADObjectParameter=@{
            SearchBase=$ADRootDSE.SchemaNamingContext
            LDAPFilter='(SchemaIDGUID=*)'
            Properties=@("Name", "SchemaIDGUID")
        }
        Get-ADObject @GetADObjectParameter | ForEach-Object { 
            If (! $adTypeGUIDTable.ContainsKey(([GUID]$_.SchemaIDGUID)))
            {
                $adTypeGUIDTable.Add(([GUID]$_.SchemaIDGUID),$_.Name) 
            }  
        }

        $ADObjExtPar=@{
            SearchBase="CN=Extended-Rights,$($ADRootDSE.ConfigurationNamingContext)"
            LDAPFilter='(ObjectClass=ControlAccessRight)'
            Properties=@("Name", "RightsGUID")
        }

        Get-ADObject @ADObjExtPar |ForEach-Object { 
            If (! $adTypeGUIDTable.ContainsKey(([GUID]$_.RightsGUID)))
            {
                $adTypeGUIDTable.Add(([GUID]$_.RightsGUID),$_.Name) 
            }
        }
    }
    Process
    {
        
        Select ($PSCmdlet.ParameterSetName)
        {
            Path { $aclPath = $Path }
            ADObject {$aclPath = ('AD:\{0}' -f $ADObject.DistinguishedName)}
            default {$aclPath = ('AD:\{0}' -f $ADRootDSE.RootDomainNamingContext)}
        }
    
        $adRightsLabel = @{Label="ADRights";Expression={$PSItem.ActiveDirectoryRights -Split ', '}}
        $adRightsUIDLabel = @{Label="ADRightsUID";Expression={"{0}-{1}-{2}-{3}" -f $PSItem.IdentityReference,$PSItem.ActiveDirectoryRights, $PSItem.InheritedObjectType, $PSItem.InheritanceType}}

        $aclData = Get-Acl -Path $aclPath | Select-Object -ExpandProperty Access | Select-Object -Property *, $adRightsLabel, $adRightsUIDLabel

        $aclResults = New-Object -TypeName 'System.Collections.Generic.List[IdentityAcl]'

        $aclData | Group-Object -Property ADRightsUID | ForEach-Object {

            $firstACE = $_.Group[0]
            [string]$idFullName = $firstACE.IdentityReference
            $idName = $idFullName.Replace(($env:USERDOMAIN + "\"), "")

            $attributeNameList = $_.Group | ForEach-Object {
                If ($adTypeGUIDTable.ContainsKey($_.ObjectType))
                {
                    $attributeName = $adTypeGUIDTable.Item($_.ObjectType)
                }
                Else
                {
                    If ($_.ObjectType -eq '00000000-0000-0000-0000-000000000000')
                    {
                        $attributeName = 'All Properties'
                    }
                    Else
                    {
                        $attributeName = $_.ObjectType
                    }
                }
                Write-Output $attributeName
            }

            If ($adTypeGUIDTable.ContainsKey($firstACE.InheritedObjectType))
            {
                $inheritedObjectType = $adTypeGUIDTable.Item($firstACE.InheritedObjectType)
            }
            Else
            {
                If ($firstACE.InheritedObjectType -eq '00000000-0000-0000-0000-000000000000')
                {
                    $inheritedObjectType = 'This Object'
                }
                Else
                {
                    $inheritedObjectType = $firstACE.InheritedObjectType
                }
            }        

            $auditResults.add([IdentityAcl]::new($idFullName, $firstACE.ActiveDirectoryRights,$inheritedObjectType,$firstACE.InheritanceType,$attributeNameList))
        }
    }
}
