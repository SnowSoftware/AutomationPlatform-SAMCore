# activity functions

function Add-SAMProvisioningMember {
    <#
            .SYNOPSIS
            Installs software by adding a user or computer to a deployment container.
   
            .DESCRIPTION
            Installs software by adding a user or computer to a deployment container. By default this function adds a user or computer to an AD group.

            Referenced from AP Activity: Install Software

            .EXAMPLE
            Add-SAMProvisioningMember -User 'CN=John Doe,OU=Users,DC=MyDomain,DC=local' -DeploymentContainer 'CN=MyApplicationGroup,OU=Deployment,DC=MyDomain,DC=local'
            Adds the user "John Doe" to the group "MyApplicationGroup" which will be used when deploying the software "MyApplication".
    #>
    [CmdletBinding()]
    param(
        # Distinguished name of the user.
        [string]
        $User,
        
        # Distinguished name of the computer.
        [string]
        $Computer,
        
        # Distinguished name of the group to add the user or computer to.
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $DeploymentContainer,
        
        # Type of deployment. Options are user or computer.
        [Parameter(Mandatory=$true)]
        [ValidateSet("User", "Computer")]
        [string]
        $DeploymentType,
        
        # Optional parameter which contains the full application details from Snow License Manager as a json string.
        # This information can be used when creating custom functions where the information in Automation Platform is not enough.
        # By default this parameter is not used.
        [ValidateNotNullOrEmpty()]
        [string]
        $ApplicationDetails
    )

    Process
    {
        Import-Module -Name ActiveDirectory
        
        # if different deployment methods are needed for users and computers, this is where the separation can be done
        if ($DeploymentType -eq 'User') {
            Write-Host 'Deployment type: User'
            if ([string]::IsNullOrEmpty($User)) {
                Throw 'For deployment type User the user parameter cannot be empty.'
            }
            Add-ADGroupMember -Identity $DeploymentContainer -Members $User
        }
        elseif ($DeploymentType -eq 'Computer'){
            Write-Host 'Deployment type: Computer'
            if ([string]::IsNullOrEmpty($Computer)) {
                Throw 'For deployment type Computer the computer parameter cannot be empty.'
            }
            Add-ADGroupMember -Identity $DeploymentContainer -Members $Computer
        }
        
    }
}

function Remove-SAMProvisioningMember {
    <#
            .SYNOPSIS
            Uninstalls software by removing a user or computer from a deployment container.
   
            .DESCRIPTION
            Uninstalls software by removing a user or computer from a deployment container. By default this function removes a user or computer from an AD group.
            
            Referenced from AP Activity: Install Software

            .EXAMPLE
            Remove-SAMProvisioningMember -User 'CN=John Doe,OU=Users,DC=MyDomain,DC=local' -DeploymentContainer 'CN=MyApplicationGroup,OU=Deployment,DC=MyDomain,DC=local'
            Removes the user "John Doe" from the group "MyApplicationGroup" which will be used when uninstalling the software "MyApplication".
    #>
    [CmdletBinding()]
    param(
        # Distinguished name of the user.
        [string]
        $User,
        
        # Distinguished name of the computer.
        [string]
        $Computer,
        
        # Distinguished name of the group to remove the user or computer from.
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $DeploymentContainer,
        
        # Type of deployment. Options are user or computer.
        [Parameter(Mandatory=$true)]
        [ValidateSet("User", "Computer")]
        [string]
        $DeploymentType,
        
        # Optional parameter which contains the full application details from Snow License Manager as a json string.
        # This information can be used when creating custom functions where the information in Automation Platform is not enough.
        # By default this parameter is not used.
        [ValidateNotNullOrEmpty()]
        [string]
        $ApplicationDetails
    )
  
    Import-Module ActiveDirectory
    
    # if different deployment methods are needed for users and computers, this is where the separation can be done
    if ($DeploymentType -eq 'User') {
        Write-Host 'Deployment type: User'
        if ([string]::IsNullOrEmpty($User)) {
            Throw 'For deployment type User the user parameter cannot be empty.'
        }
        Remove-ADGroupMember -Identity $DeploymentContainer -Members $User -Confirm:$false
    }
    elseif ($DeploymentType -eq 'Computer'){
        Write-Host 'Deployment type: Computer'
        if ([string]::IsNullOrEmpty($Computer)) {
            Throw 'For deployment type Computer the computer parameter cannot be empty.'
        }
        $Computer = "$Computer$"
        Remove-ADGroupMember -Identity $DeploymentContainer -Members $Computer -Confirm:$false
    }
    
}

# PowerShell Webservice functions

function Get-SAMProvisioningMember {
    <#
            .SYNOPSIS
            Retrieves members from a deployment container (AD group).
   
            .DESCRIPTION
            Retrieves members as SamAccountName from a deployment container. 
            This output need to be SamAccountName since we need to be able to compare with the output from Snow License Manager.

            Referenced from PowerShell web service: Get compliance info

            .INPUTS
            String containing the identity of the deployment container (AD Group)

            .OUTPUTS
            Array of members as string (SamAccountName)

            .EXAMPLE
            Get-SAMProvisioningMember -DeploymentContainer 'CN=MyApplicationGroup,CN=DeploymentGroups,DC=Fabrikam,DC=com'

            Returns the members of the group MyApplicationGroup
    #>
    [CmdletBinding()]
    param(
        # Distinguished name of the group to check membership in.
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $DeploymentContainer
    )
    
    Import-Module ActiveDirectory
    
    Get-ADGroupMember -Identity $DeploymentContainer -ErrorAction Stop | Select-Object -ExpandProperty SamAccountName
}

# Inventory service functions

function Get-SAMInstalledSoftware {
    <#
            .SYNOPSIS
            Gets a list of installed software (AD group membership) for an AD account based on an array of provisioning targets
   
            .DESCRIPTION
            Checks if the AD account is a member of any of the items in the ProvisioningTarget array and returns those provisioning targets with the property DistinguishedName.

            Referenced from inventory service: SAM Installed Software

            .OUTPUTS
            Array of objects with the property DistinguishedName

            .EXAMPLE
            Get-SAMInstalledSoftware -Parent 'MyDomain\MyUser' -DeploymentContainer 'CN=MyApplicationGroup,CN=DeploymentGroups,DC=Fabrikam,DC=com'

            Returns an object with the DistinguishedName property 'CN=MyApplicationGroup,CN=DeploymentGroups,DC=Fabrikam,DC=com' if the user MyUser is a member of it.
    #>
    [CmdletBinding()]
    param(
        # User or computer (domain\username)
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Parent, 
        
        # Array of distinguished names of the deployment containers (AD groups)
        [Parameter(Mandatory=$true)]
        [string[]]
        $DeploymentContainer
    )

    Import-Module -Name ActiveDirectory -ErrorAction Stop

    try {
        $ParentDistinguishedName = ConvertTo-SAMUserIdentity -InputObject $Parent
    } 
    catch {
        try {
            $ParentDistinguishedName = ConvertTo-SAMComputerIdentity -InputObject "$($Parent.split('\')[-1])$"
        }
        catch {
            Throw "Unable to convert AD object: $Parent"
        }
    }
    
    $parentMemberof = Get-ADObject -Identity $ParentDistinguishedName -Properties memberof | Select-Object -ExpandProperty memberof
    $matches = [System.Linq.Enumerable]::intersect([string[]]$parentMemberof, $DeploymentContainer)
    
    $result = @()
    foreach ($match in $matches) {
        $result += $match 
    }
    $result
}

# conversion functions

function ConvertTo-SAMOwnerIdentity {
    <#
            .SYNOPSIS
            Converts AD user to SamAccountName

            .DESCRIPTION
            Gets an AD user from Active Directory and returns the SamAccountName for that user.
            This function is made to be used when setting the service owner on a service in Automation Platform.

            Referenced from scheduled task: SLM - Import Applications

            .OUTPUTS
            System.String

            .EXAMPLE
            ConvertTo-SAMOwnerIdentity -InputObject 'myuser@mydomain.com'
            
            Returns the string 'MyDomain\MyUser'.
    #>
    [CmdletBinding()]
    param(
        # The ad object (user) to search for.
        # Supported ad object formats are:
        # * Username/SamAccountName
        # * UPN (username@domainName)
        # * DistinguishedName
        # * Common Name
        # * Down-level logon name (domainname\username)
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $InputObject
    )
    
    Import-Module APCommon
    
    [array]$adobject = FindADObject -adObject $InputObject -InformationVariable $null -filterTypes 'user'
    
    if (!$adobject) {
        Throw "Could not find AD user '$InputObject'"
    } 
    elseif ($adobject.count -ne 1) {
        Throw "Could not find one unique AD user matching '$InputObject'"
    } 
    else {
        $adobject[0].SamAccountName
    } 
}

function ConvertTo-SAMApproverIdentity {
    <#
            .SYNOPSIS
            Converts AD user to DistinguishedName

            .DESCRIPTION
            Gets an AD user from Active Directory and returns the Distinguished Name for that user.
            This function is made to be used when configuring the approver in Automation Platform.

            Referenced from scheduled task: SLM - Import Applications

            .OUTPUTS
            System.String

            .EXAMPLE
            ConvertTo-SAMApproverIdentity -InputObject 'MyDomain\MyUser'
            
            Returns the string 'CN=MyUser,OU=Users,DC=MyDomain,DC=local'.
            
    #>
    [CmdletBinding()]
    param(
        # The name of the ad user to search for.
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $InputObject
    )
    
    Import-Module APCommon
    
    [array]$adobject = FindADObject -adObject $InputObject -InformationVariable $null -filterTypes 'user'
    
    if (!$adobject) {
        Throw "Could not find AD user '$InputObject'"
    } 
    elseif ($adobject.count -ne 1) {
        Throw "Could not find one unique AD user matching '$InputObject'"
    } 
    else {
        $adobject[0].DistinguishedName
    } 
}

function ConvertTo-SAMDeploymentContainerIdentity {
    <#
            .SYNOPSIS
            Converts AD group to DistinguishedName

            .DESCRIPTION
            Gets an AD group from Active Directory and returns the Distinguished Name for that group.
            This function is made to be used when configuring the deployment container in Automation Platform.

            Referenced from scheduled task: SLM - Import Applications

            .OUTPUTS
            System.String

            .EXAMPLE
            ConvertTo-SAMDeploymentContainerIdentity -InputObject 'MyGroup'
            
            Returns the string 'CN=MyGroup,OU=ApplicationGroups,DC=MyDomain,DC=local'.
    #>
    [CmdletBinding()]
    param(
        # The name of the ad group to search for.
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $InputObject
    )
    
    Import-Module APCommon
    
    [array]$adobject = FindADObject -adObject $InputObject -InformationVariable $null -filterTypes 'group'
    
    if (!$adobject) {
        Throw "Could not find AD group '$InputObject'"
    } 
    elseif ($adobject.count -ne 1) {
        Throw "Could not find one unique AD group matching '$InputObject'"
    } 
    else {
        $adobject[0].DistinguishedName
    } 
}

function ConvertTo-SAMUserIdentity {
    <#
            .SYNOPSIS
            Converts AD user to DistinguishedName

            .DESCRIPTION
            Gets an AD user from Active Directory and returns the Distinguished Name for that user.
            This function is made to be used in inventory services in Automation Platform.

            Referenced from inventory service: SAM Installed Software

            .OUTPUTS
            System.String

            .EXAMPLE
            ConvertTo-SAMUserIdentity -InputObject 'MyUser'
            
            Returns the string 'CN=MyUser,OU=Users,DC=MyDomain,DC=local'.
    #>
    [CmdletBinding()]
    param(
        # The name of the ad user to search for.
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $InputObject
    )
    
    Import-Module APCommon
    
    [array]$adobject = FindADObject -adObject $InputObject -InformationVariable $null -filterTypes 'user'
    
    if (!$adobject) {
        Throw "Could not find AD user '$InputObject'"
    } 
    elseif ($adobject.count -ne 1) {
        Throw "Could not find one unique AD user matching '$InputObject'"
    } 
    else {
        $adobject[0].DistinguishedName
    } 
}

function ConvertTo-SAMComputerIdentity {
    <#
            .SYNOPSIS
            Converts AD computer to DistinguishedName

            .DESCRIPTION
            Gets an AD computer from Active Directory and returns the Distinguished Name for that computer.
            This function is made to be used in inventory services in Automation Platform.

            Referenced from inventory service: SAM Installed Software

            .OUTPUTS
            System.String

            .EXAMPLE
            ConvertTo-SAMUserIdentity -InputObject 'MyComputer'
            
            Returns the string 'CN=MyComputer,OU=Computers,DC=MyDomain,DC=local'.
    #>
    [CmdletBinding()]
    param(
        # The name of the ad user to search for.
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $InputObject
    )
    
    Import-Module APCommon
    
    [array]$adobject = FindADObject -adObject $InputObject -InformationVariable $null -filterTypes 'computer'
    
    if (!$adobject) {
        Throw "Could not find AD computer '$InputObject'"
    } 
    elseif ($adobject.count -ne 1) {
        Throw "Could not find one unique AD computer matching '$InputObject'"
    } 
    else {
        $adobject[0].DistinguishedName
    } 
}

# Import functions

function Test-SAMProvisioningItem {
    <#
            .SYNOPSIS
            Validates if a provisioning item (user, computer or group) exists.
   
            .DESCRIPTION
            Validates if a provisioning item exists and returns an object with two properties:
            - Validated
            Set to true if the item is validated.
            - Message
            Contains a message explaining why an object cannot be found or simply a string stating that the item is ok. This property is made to be used for error handling.

            Referenced from scheduled task: SLM - Import Applications

            .OUTPUTS
            String containing distinguished name

            .EXAMPLE
            Convertto-SAMDistinguishedName -InputObject 'Domain\MyUser'

            Returns the distinguished name of the user MyUser.
    #>
    [CmdletBinding()]
    param(
        # Name of user or group, including domain if needed (example: domain\username or just username)
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Item,
        
        # Type of object to validate. Computer, User, or Group
        [Parameter(Mandatory=$true)]
        [ValidateSet("User","Computer","Group")]
        [string]
        $Type
    )
    
    Import-Module -Name APCommon -ErrorAction Stop
    
    $ADGroupValidation = Test-APADItem -Item $Item -Type $type
    
    if (-not $ADGroupValidation.Validated) {
        Throw "Failed to validate AD group ""$Item"": $($ADGroupValidation.Message)"
    }
    
    $ADGroupValidation

}

function Get-SAMDeploymentType {
     <#
            .SYNOPSIS
            Returns deployment type as a string based on an Snow License Manager application.
   
            .DESCRIPTION
            Accepts an application object which has been converted from the Snow License Manager API containing the ComputerGroup and UserGroup properties.
            Returns a string containing either 'Computer' or 'User'.
    
            Referenced from scheduled task: SLM - Import Applications

            .OUTPUTS
            String containing either 'Computer' or 'User'

            .EXAMPLE
            Get-SAMDeploymentType -ApplicationDetails $SLMApp

            Returns the deployment type from the SLM application.
    #>
    [CmdletBinding()]
    param(
        # Application object converted from the SLM API containing ComputerGroup and UserGroup properties
        [Parameter(Mandatory=$true)]
        [psobject]
        $ApplicationDetails
    )
    
    if ($ApplicationDetails.ComputerGroup) {
        $deploymentType = 'Computer'
    } 
    elseif ($ApplicationDetails.UserGroup){
        $deploymentType = 'User'
    } 
    else {
        Write-Error 'Unable to get deployment type. ComputerGroup or UserGroup need to be set.'
    }
    $deploymentType
    
}

function Remove-SAMTemplateWorkflow {
    <#
            .SYNOPSIS
            Adds workflows to be unlinked to an APService object
   
            .DESCRIPTION
            This function accepts a SLMApp object and an APService object. The function will check the publish level and UninstallOption properties of the SLMApp object and add workflows marked for removal if needed.
            The APService object can then be used when importing a new service based on a template service. The workflows in the template service will be unlinked in the imported service according to what the UnlinkWorkflows property contains.

            Referenced from scheduled task: SLM - Import Applications

            .OUTPUTS
            psobject containing the APService with workflows marked for removal (if any) in the UnlinkWorkflows property.

            .EXAMPLE
            $APService = Remove-SAMTemplateWorkflow -SLMApp $SLMApp -Service $APService

            Returns the APService object with the UnlinkWorkflos property populated with workflows to be removed.
    #>
    [CmdletBinding()]
    param (
        # SLM application, as returned by the Get-SLMStoreApplications function
        [Parameter(Mandatory=$true)]
        [psobject]
        $SLMApp,
        
        # AP Service object. Use Get-APServiceImportObject to create a new AP Service object
        [Parameter(Mandatory=$true)]
        [psobject]
        $Service
    )

    # Install Software
    if ($SLMApp.PublishLevel -eq 'Uninstall') {
        $Service.UnlinkWorkflows += New-Object -TypeName psobject -Property @{ 'Name' = 'Install software' } 
    }
    
    # Uninstall Software
    if ($SLMApp.PublishLevel -eq 'Install') {
        $Service.UnlinkWorkflows += New-Object -TypeName psobject -Property @{ 'Name' = 'Uninstall software' } 
    }
    
    # Extend Subscription
    if ($SLMApp.UninstallOption -ne 'TimeBased') {
        $Service.UnlinkWorkflows += New-Object -TypeName psobject -Property @{ 'Name' = 'Extend Subscription' } 
    }
    elseif ((([string]::IsNullOrEmpty($SLMApp.SubscriptionExtensionsDays)) -or ($SLMApp.SubscriptionExtensionsDays -eq '0'))) {
        $Service.UnlinkWorkflows += New-Object -TypeName psobject -Property @{ 'Name' = 'Extend Subscription' } 
    }

    #return service object
    $Service

}

function Disable-SAMTemplateActivity {
    <#
            .SYNOPSIS
            Adds workflow activities to be disabled to an APService object
   
            .DESCRIPTION
            This function accepts a SLMApp object and an APService object. The function will check the UninstallOption, OrganizationalApproval and ApplicationOwnerApproval properties of the SLMApp object to figure out if any workflow activities need to be disabled.
            References to workflow activities will be added to the APService objects property DisableWorkflowActivities.
            The APService object can then be used when importing a new service based on a template service. The workflow activitites in the template service will be disabled in the imported service according to what the DisableWorkflowActivities property contains.

            Referenced from scheduled task: SLM - Import Applications

            .OUTPUTS
            psobject containing the APService with workflow activitites marked to be disabled (if any) in the DisableWorkflowActivities property.

            .EXAMPLE
            $APService = Disable-SAMTemplateActivity -SLMApp $SLMApp -Service $APService

            Returns the APService object with the DisableWorkflowActivities property populated with workflow activitites to be disabled.
    #>
    [CmdletBinding()]
    param (
        # SLM application, as returned by the Get-SLMStoreApplications function
        [Parameter(Mandatory=$true)]
        [psobject]
        $SLMApp,
        
        # AP Service object. Use Get-APServiceImportObject to create a new AP Service object
        [Parameter(Mandatory=$true)]
        [psobject]
        $Service
    )
    
    # Install Software -> Subscription
    
    if ($SLMApp.UninstallOption -ne 'TimeBased') {
        $Service.DisableWorkflowActivities += New-SAMWorkflowActivity -WorkflowName 'Install software' -WorkflowActivityPrio 7 # Subscription
    }
    
    # Approval
    
    # If organizational approval is set to False, disable the first two activities in the Install software workflow
    if (-not ($SLMApp.OrganizationalApproval)) {
        $Service.DisableWorkflowActivities += New-SAMWorkflowActivity -WorkflowName 'Install software' -WorkflowActivityPrio 1 # Workflow activity displayname 'Wait for organizational approval'
        $Service.DisableWorkflowActivities += New-SAMWorkflowActivity -WorkflowName 'Install software' -WorkflowActivityPrio 2 # Workflow activity displayname 'Organizational approval'
    }

    # If application owner approval is set to False, disable the second two activities in the Install software workflow
    if (-not $SLMApp.ApplicationOwnerApproval) {
        $Service.DisableWorkflowActivities += New-SAMWorkflowActivity -WorkflowName 'Install software' -WorkflowActivityPrio 3 # Workflow activity displayname 'Wait for application owner approval'
        $Service.DisableWorkflowActivities += New-SAMWorkflowActivity -WorkflowName 'Install software' -WorkflowActivityPrio 4 # Workflow activity displayname 'Application owner approval'
    } 

    # Uninstall Software -> Approval
    # If "Let the user approve uninstall" is not selected in SLM, disable the approval steps on the cancel workflow
    if (-not [string]::IsNullOrEmpty($Service.UserUninstallApproval)) {
        if (-not $Service.UserUninstallApproval) {
            # The user will not get to approve uninstall invoked from reharvest
            $Service.DisableWorkflowActivities += New-SAMWorkflowActivity -WorkflowName 'Uninstall software' -WorkflowActivityPrio 1 # Workflow activity displayname 'Task'
            $Service.DisableWorkflowActivities += New-SAMWorkflowActivity -WorkflowName 'Uninstall software' -WorkflowActivityPrio 2 # Workflow activity displayname 'Approval (task)'
        }
    }


    # return service object
    $Service
}

function New-SAMWorkflowActivity {
    <#
            .SYNOPSIS
            Creates a new WorkflowActivity object adapted for the SAM Automation template service
   
            .DESCRIPTION
            This function creates a new WorkflowActivity object which can be used to disable workflow activities when importing services in SAM Automation.
            The structure of the object is adapted to how AP expects workflow activities to look.

            Referenced from scheduled task: SLM - Import Applications

            .OUTPUTS
            psobject containing the the reference to a workflow activity.

            .EXAMPLE
            $Service.DisableWorkflowActivities += New-SAMWorkflowActivity -WorkflowName 'Install software' -WorkflowActivityPrio 3

            Returns a workflow activity reference to the workflow 'Install software' with priority 3 (step 3 in the workflow).
    #>
    param (
        # Name of the workflow which the activity is connected to
        [Parameter(Mandatory=$true)]
        [ValidateSet('Install Software',
                     'Uninstall Software',
                     'Extend Subscription')]
        [string]
        $WorkflowName,
    
        # Priority of the activity in the workflow (workflow step)
        [Parameter(Mandatory=$true)]
        [int]
        $WorkflowActivityPrio
    )

    $workflow                  = New-Object -TypeName psobject -Property @{ 'Name' = $WorkflowName }
    $workflowActivities        = New-Object -TypeName psobject -Property @{ 'Prio' = $WorkflowActivityPrio }
    
    New-Object -TypeName psobject -Property @{ 
        'Workflow'           = $workflow
        'WorkflowActivities' = @($workflowActivities) 
    }
}

function Import-SAMServiceImage {
    <#
            .SYNOPSIS
            Downloads an application image from SLM and returns the Uri
   
            .DESCRIPTION
            Downloads an application image from SLM and returns the relative Uri to the downloaded image.
            If the application does not have an image configured in SLM the function will return "noImage".
   
            Referenced from scheduled task: SLM - Import Applications

            .OUTPUTS
            string with image uri

            .EXAMPLE
            $ImageUri = Import-SAMServiceImage -SLMApp $SLMApp -SLMUri $SLMUri -SLMCreds $SLMCreds -APRootFolder $APRootFolder

    #>
    [CmdletBinding()]
    param(
        # The SLM App object as returned from the Get-SLMStoreApplications function 
        [Parameter(Mandatory=$true)]
        [psobject]
        $SLMApp,
        
        # The uri to SLM (example: http://slm.domain.local)
        [Parameter(Mandatory=$true)]
        [string]
        $SLMUri,
        
        # Credential to SLM which has permissions to the Upload folder in SLM
        [Parameter(Mandatory=$true)]
        [pscredential]
        $SLMCreds,
        
        # The root folder for AP. Usually the value from setting SnowAutomationPlatformRootFolder in AP.
        [Parameter(Mandatory=$true)]
        [string]
        $APRootFolder
    )
    
    $APRelativeRootImageUri = '/StaticContent/ServiceImages/'
    $APImageFolder = $APRootFolder + 'WebSite\StaticContent\ServiceImages\'
    
    # verify that the folder where we want to store the images for each service exist, otherwise create it
    if (-not (Test-Path -Path $APImageFolder)) {
        try {
            New-Item -ItemType Directory -Path $APImageFolder -Force
        }
        catch {
            Write-Error "Unable to create folder for service images ($APImageFolder). Exception: $($_.Exception.Message)"
        }
    }
    
    # Download image from SLM and set the Url
    # if no image is specified, use "noImage" to get the placeholder image instead
    if ($SLMApp.ImageName.Trim().Length -gt 0) {
        try {
            $SLMImageUrl = $SLMUri + "/Upload/Store/Images/" + $SLMApp.ImageName
            $APImagePath = $APImageFolder + $SLMApp.ImageName
            $APImageUri  = $APRelativeRootImageUri + $SLMApp.ImageName
            Invoke-WebRequest -Uri $SLMImageUrl -OutFile $APImagePath -Credential $SLMCreds -ErrorAction Stop
            $return = $APImageUri
        }
        catch {
            $return = 'noImage'
            Write-Error "Unable to download application image for $($SLMApp.Name). Exception: $_"
        }
    } else {
        $return = 'noImage'
    }

    # return the app object
    $return
}


# Reharvest functions
function Get-SAMMemberSID {
    <#
            .SYNOPSIS
            Gets the members of a container and returns the SID of all members
   
            .DESCRIPTION
            Gets the members of a container and returns the SID of all members

            Referenced from scheduled task: SLM - Reharvest Applications

            .OUTPUTS
            StringArray containing SIDs

            .EXAMPLE
            Get-SAMMemberSID -container 'MyContainer'

            This will return an object containing Name and SIDs of members in the MyCollection collection

            
    #>
    [CmdletBinding()]
    param(
        # Name of Collection
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Collection
    )
    
    Import-Module ActiveDirectory

    $CollectionMemberSID = Get-ADGroupMember -Identity $Collection | Select-object -Property Name,@{Name='SID';Expression={$_.SID.Value}}

    $CollectionMemberSID
}

function Confirm-SAMProvisioningMembership {
    <#
            .SYNOPSIS
            This function will verify that input $object is a member of the $container collection
   
            .DESCRIPTION
            This function gets the members of a container and compares this list to the input object.
            It will always return a object with the properties Verified and VerifiedStatus

            Referenced from scheduled task: SLM - Reharvest Applications

            .OUTPUTS
            psobject

            .EXAMPLE
            Confirm-SAMProvisioningMembership -container 'MyContainer' -Object 'MyUser'

            If 'MyUser' is a member of 'MyContainer'
            This will return an object containing Verified = $True and 
            VerifiedStatus = 'Verified container membership.'

            .EXAMPLE
            Confirm-SAMProvisioningMembership -container 'MyContainer' -Object 'MyUser'

            If 'MyUser' is not a member of 'MyContainer'
            This will return an object containing Verified = $False and 
            VerifiedStatus = "$Object is not a member of $Container"
            
    #>
    [CmdletBinding()]
    Param(
        [string]$Object,
        [string]$Container
    )

    $EnumeratedGroupMembers = Get-SAMMemberSID -Collection $Container

    if ( ($EnumeratedGroupMembers.SID -notcontains $Object) -and ($EnumeratedGroupMembers.Name -notcontains $Object) ) {
        New-Object -TypeName psobject -Property @{
            Verified = $False
            VerifiedStatus = "$Object is not a member of $Container"
        }
    }
    else {
        New-Object -TypeName psobject -Property @{
            Verified = $True
            VerifiedStatus = 'Verified container membership.'
        }
    }
}