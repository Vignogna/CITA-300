# Import active directory module for runnig AD cmdlets
Import-Module activedirectory

#Store the data from bulk-users2.csv in $ADUsers variable
$ADUsers = Import-csv C:\Users\vignog162\Desktop\PowerShell\bulk_users2.csv

#Loop through each row containing user details in the csv file
foreach ($User in $ADUsers)
{
    #Read user data from each field in each row and assign the data to a variable as below
    $Username = $User.username
    $Firstname = $User.firstname
    $Lastname = $User.lastname
    $OU = $User.ou
    $email = $User.email
    $streetaddress = $User.streetaddress
    $city = $User.city
    $postalcode = $User.postalcode
    $state = $User.state
    $country = $User.country
    $telephone = $User.telephone
    $jobtitle = $User.jobtitle
    $company = $User.company
    $department = $User.department
    $Password  = $User.Password
    $secPw = ConvertTo-SecureString -String $Password -AsPlainText -Force
    #$password = [System.Web.Security.Membership];;GeneratePassword((Get-Randon - Minimum 20 - Maximum 32), 3)
 
    
    if (Get-ADUser -F {SamAccountName -eq $Username})
    {
        Write-Warning "A user account with $Username already exists in active directory."
    }
    else
    {
        New-ADUser `
        -SamAccountName $Username `
        -UserPrincipalName "$Username@vignogna.local" `
        -Name "$Firstname $Lastname" `
        -GivenName $Firstname `
        -Surname $Lastname `
        -Enabled $True `
        -DisplayName "$Lastname, $Firstname" `
        -Path $OU `
        -City $city `
        -Company $company `
        -State $state `
        -PostalCode $postalcode `
        -Country $country `
        -StreetAddress $streetaddress `
        -OfficePhone $telephone `
        -EmailAddress $email `
        -Title $jobtitle `
        -Department $department `
        -AccountPassword $secPw `
    }
}

$DirectoryToCreate = "C:\Parent-Directory\$Username\"

if(-not (Test-Path -LiteralPath $DirectoryToCreate))
{
    try {
        New-Item -Path $DirectoryToCreate -ItemType Directory -ErrorAction Stop | Out-Null
    }
    catch{
        Write-Error -Message "Unable to create directory '$DirectoryToCreate'. Error was: $_ " -ErrorAction Stop
    }
    "Successfully created '$DirectoryToCreate'."
}
else {
    "Directory already exists for $Username"
}

$SMBToCreate = "C:\Parent-Directory\$Username\"

if(!(Get-SmbShare -Name $Username -ea 0))
{
    New-SmbShare -Name $Username -Path $SMBToCreate -FullAccess "vignogna\administrator" -ReadAccess "vignogna\$Username"
}

Enable-PSRemoting
Enable-WSManCredSSP -Role Server # -Role client -delegatecomputer web.vignogna.local

Enter-PSSession -ComputerName web.vignogna.local `
-Authentication Credssp -Credential vignogna\vignog162 #mightbewrong

if ($null -eq (Get-PSSnapin -Name MailEnable.Provision.Command -ErrorAction SilentlyContinue) )
{
    Add-PSSnapin MailEnable.Provision.Command
}
New-MailEnableMailbox -Mailbox "$Username" -Domain "vignogna.local" -Password "$Password" -Right "USER"


Write-Output $Username
$Label1 = "*****USERNAME*****"
$Label2 = $Username

$Label1 >> c:\user_onboard_info.txt
$Label2 >> c:\user_onboard_info.txt

$ErrorActionPreference = "SilentlyContinue"
Write-Output $Password
$Label3 = "*****PASSWORD*****"
$Label4 = $Password

$Label3 >> c:\user_onboard_info.txt
$Label4 >> c:\user_onboard_info.txt
$ErrorActionPreference = "SilentlyContinue"

#$gmailCred = Get-Credential
#$sendMailParams = @{
    #From = 'vignog@vignogna.local'
    #To = '$Username@vignogna.local'
    #Subject = 'some subject'
    #Body = 'some body'
    #SMTPServer = 'vignogna.local'
    #SMPTPort = 25
    #UseSsl = $false
    #Credential = $gmailCred
#}

$filterdate = (Get-Date).AddDays(-1).Date
Get-ADUser -Filter {created -ge $filterdate} -Properties created | Select-Object Name,Created | Sort-Object created -Descending
