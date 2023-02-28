<# 
  Author: Brandon C. Brin
  Date: 09/29/2015 - 10:00
  
.SYNOPSIS
Finds unknown security principals for files and folders.

.DESCRIPTION
Prints location of unknown security principals within ACLs for files and folders, and removes them.

.PARAMETER Recurse
Recurse all subdirectories, other

.EXAMPLE
Get-UnknownSecPrincipal -Path "\\contoso.com\share\hr" -Recurse -Remove
#>
#workflow Get-UnknownSecPrincipal {
function Get-UnknownSecPrincipal {
param(
	[String]$Path = "\\contoso.com\share\hr",
	[Switch]$Recurse,
	[Switch]$Remove
)

    if(Test-Path -Path $Path) {
	    if($Recurse) {
		    $targets = Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue -ErrorVariable pathTooLong
	    }
	    else {
		    $targets = Get-ChildItem -Path $Path -ErrorAction SilentlyContinue -ErrorVariable pathTooLong
	    }

        if($Remove) { 
	        Find-UnknownSecPrincipal -Path $Path -Remove
		    }
		 else {
			Find-UnknownSecPrincipal -Path $Path
		 }
	
		#foreach -parallel ($target in $targets.FullName) {
	    foreach ($target in $targets.FullName) {
		    Write-Progress -Activity "Searching ACLs" -Status "Checking $($target)"
		    if($Remove) {
			    Find-UnknownSecPrincipal -Path $target -Remove
		    }
		    else {
			    Find-UnknownSecPrincipal -Path $target
		    }
		    $i++
	    }
	    $i=0
	
	    foreach ($longPath in $pathTooLong) {
		    Write-Output ("Path exceeds max length:" + $longPath.TargetObject)
	    }
    }
    else {
        Write-Warning "Invalid path specified."
    }
}

<# 
  Author: Brandon C. Brin
  Date: 09/29/2015 - 10:00
  
.SYNOPSIS
Helper function for Find-UnknownSecurityPrincipals. 

.DESCRIPTION
Finds unknown security principals within ACLs for the given path and its immidiate child items only. Removes those principals if -Remove is specified.

.EXAMPLE
Find-UnknownSecPrincipal -Path "C:\TEST" -Recurse -Remove
#>
Function Find-UnknownSecPrincipal {
param(
	$Path = "\\contoso.com\home",
	[Switch]$Remove
)
    
    if(Test-Path -Path $Path) {
	    $acl = Get-ACL -Path $Path -ErrorAction SilentlyContinue -ErrorVariable geterr

        if($geterr) {
            Write-Output ("Error accessing ACLs for:" + $Path)
            Break
        }

        if($acl.Owner -like "O:S-1-5*") {
            Write-Warning ("Directory owned by unknown security principal. Cannot remove ACL for:" + $Path)
        }
        else {
	        foreach ($member in $acl.Access) {
		        if($member.IdentityReference.Value -like "S-1-5*") {
			        Write-Output $Path
			        if($Remove) {
				        Write-Output ("Removing ACL for user: " + $member.IdentityReference.Value)
				        $acl.RemoveAccessRule($member) | Out-Null
			        }	
		        }
	        }

	        Set-Acl -Path $Path -AclObject $acl -ErrorAction SilentlyContinue -ErrorVariable seterr
            if($seterr) {
                Write-Output ("Error setting ACLs for:" + $Path)
                Break
            }
        }
    }
    else {
        Write-Warning "Invalid path provided."
    }
}

<# 
  Author: Brandon C. Brin
  Date: 08/12/2015 - 15:45
  
.SYNOPSIS
Lists directories with ACL inheritance disabled.

.DESCRIPTION
Prints list of directories which have inherited permissions disabled.

.PARAMETER Path
Path to directory to check for disabled inheritance.

.EXAMPLE
Find-DisabledInheritance -Path "\\contoso.com\\shared"
#>
Function Find-DisabledInheritance {
[Cmdletbinding()]
param (
    $Path = "\\contoso.com\shared"
)
    if(Test-Path -Path $Path) {
        $items = Get-ChildItem -Path $Path -Force -ErrorAction SilentlyContinue -ErrorVariable err -Recurse -Directory 
        $i = 0
        foreach ($item in $items) {
		    Write-Progress -act "Searching For Disabled Inheritance" -status "Checking $item" -percent ($i/ $items.count*100)
		    $acl = Get-Acl -Path $item.FullName
		
		    if($acl.AreAccessRulesProtected) {			
			    $outpath = $item.Fullname
			    Write-Output "Inheritance Disabled: $outpath"
		    }
		    $i++
          }
   
         foreach ($errors in $err) {
			    try { 
                    New-PSDrive -Name T -PSProvider FileSystem -Root $errors.TargetObject -Persist -ErrorVariable $mapError | Out-Null
                }
                catch {
                    Write-Output ("Error mapping:" + $mapError)
                    Break
                }
                        
                $acls = Get-ChildItem -Path "T:\" -Recurse -ErrorAction SilentlyContinue -ErrorVariable err1 | Get-Acl | Where { $_.AreAccessRulesProtected -eq $true}
                foreach ($acl in $acls) {
                    Write-Output ("Inheritance disabled: " + $acl.PSPath)
                }
                foreach ($errors1 in $err1) {
                    Write-Output ("Error reading:" + $errors1.TargetObject)
                }

			    Remove-PSDrive -Name T	
	     }
    }
    else {
        Write-Warning "Invalid path specified."
    }
}

<# 
  Author: Brandon C. Brin
  Date: 08/11/2015 - 14:30
  
.SYNOPSIS
Generates ACL report for given path.

.DESCRIPTION
Generates CSV report consisting of path, user, rights, ACLType, Inheritance, and Propogation.

.PARAMETER Path
Desired directory to generate report from.

.PARAMETER Recurse
Recurse all subfolders and files.

.EXAMPLE
Get-ACLReport -Path "\\contoso.com\shared\legal"

.EXAMPLE 1
Get-ACLReport -Path "\\legis.local\shared\legal\2015" -Recurse
#>
Function Get-ACLReport {
[Cmdletbinding()]
param (
    $Path = "\\contoso.com\shared\legal",
	$Destination = ".\",
    [Switch]$Recurse
)

    if(Test-Path -Path $Path) {
        $item = Get-Item -Path $Path
        $fileline = @()

        #get root acls first
        $acl = Get-Acl -Path $item
        $access = $acl.Access
        $out = New-Object -TypeName PSObject 

        foreach ($entry in $access) { 
             $out = New-Object -TypeName PSObject 
             Add-Member -InputObject $out -Type NoteProperty -Name Path $Path
             Add-Member -InputObject $out -Type NoteProperty -Name User $entry.IdentityReference
             Add-Member -InputObject $out -Type NoteProperty -Name Rights $entry.FileSystemRights
             Add-Member -InputObject $out -Type NoteProperty -Name ACLType $entry.AccessControlType
             Add-Member -InputObject $out -Type NoteProperty -Name Inheritance $entry.InheritanceFlags
             Add-Member -InputObject $out -Type NoteProperty -Name Propogation $entry.PropagationFlags
             $fileline += $out
         }


        if($Recurse) {
	        $homepaths = Get-ChildItem -Path $Path -Force -Recurse | Select -ExpandProperty FullName
        }
        else {
            $homepaths = Get-ChildItem -Path $Path -Force | Select -ExpandProperty FullName
        }        

        #iterate through children
        foreach ($homepath in $homepaths) {
            $acl = Get-Acl -Path $homepath
            $access = $acl.Access

            foreach ($entry in $access) { 
                $out = New-Object -TypeName PSObject 
                Add-Member -InputObject $out -Type NoteProperty -Name Path $homepath
                Add-Member -InputObject $out -Type NoteProperty -Name User $entry.IdentityReference
                Add-Member -InputObject $out -Type NoteProperty -Name Rights $entry.FileSystemRights
                Add-Member -InputObject $out -Type NoteProperty -Name ACLType $entry.AccessControlType
                Add-Member -InputObject $out -Type NoteProperty -Name Inheritance $entry.InheritanceFlags
                Add-Member -InputObject $out -Type NoteProperty -Name Propogation $entry.PropagationFlags
                $fileline += $out
            }
        }
        
        $date = Get-Date
        $filename = $Destination + "ACLReport_" + $date.Year + $date.Month + $date.Day + ".csv" 
        $fileline | ConvertTo-Csv -NoTypeInformation | Out-File $filename
    }
    else {
        Write-Warning "Invalid path provided."
    }
}

<# 
  Author: Brandon C. Brin
  Date: 09/18/2015 - 16:30
  
.SYNOPSIS
Prints owner of file or folder.

.DESCRIPTION
Prints the owner of the file or folder specified. 

.PARAMETER Path
Path to file or folder.

.PARAMETER IncludeChildren
Include child items of provided path.

.PARAMETER IgnoreAdmin
Exclude objects which are owned by BUILTIN\Administrators from output.
#>
Function Get-Owner {
[Cmdletbinding()]
param (
    $Path = "\\contoso.com\home\johndoe",
    [Switch]$IncludeChildren,
	[Switch]$IgnoreAdmin
)

    if(Test-Path -Path $Path) {
	    $item = Get-Item -Path $Path
        $fileline = @()

	    if($item.PSIsContainer) {
	       if($IncludeChildren) {
			   $paths = Get-ChildItem -Path $path     
               #get top level path owner first
               $acl = Get-Acl -Path $item.FullName
               $out = New-Object -TypeName PSObject 
               Add-Member -InputObject $out -Type NoteProperty -Name Name $item.Name
               Add-Member -InputObject $out -Type NoteProperty -Name Owner $acl.Owner
               $fileline += $out
	       }
	       else {
		       $paths = $item        
           }

           #get owner of 1st level child items
	       foreach ($path in $paths) {
                $acl = Get-Acl -LiteralPath $path.Fullname
                $out = New-Object -TypeName PSObject 
                Add-Member -InputObject $out -Type NoteProperty -Name Name $path.Name
                Add-Member -InputObject $out -Type NoteProperty -Name Owner $acl.Owner
                $fileline += $out
		   }
	    }

	    else {
	       if($IncludeChildren) {
			    Write-Output ("Cannot recurse. Path provided is not a directory.")  
	       }
           else { 
	            $acl = Get-Acl -Path $item.FullName
                $out = New-Object -TypeName PSObject 
                Add-Member -InputObject $out -Type NoteProperty -Name Name $item.Name
                Add-Member -InputObject $out -Type NoteProperty -Name Owner $acl.Owner
                $fileline += $out
		   }
	    }
        Write-Output $fileline
    }
    else {
        Write-Warning "Invalid path specified."
    }    
}

<# 
  Author: Brandon C. Brin
  Date: 10/19/2015 - 23:30
  
.SYNOPSIS
Disables permissions inheritance on specified directory.

.DESCRIPTION
Sets the SetAccessRuleProtection property on the ACL for the specified directory.

.PARAMETER Path
Path of directory to disable permissions inheritance.
#>
Function Set-DisabledInheritance {
[Cmdletbinding()]
param( 
	$path = "\\contoso.com\share\subfolder"
)
	if(Test-Path -Path $path) {
		$acl = Get-Acl -LiteralPath $path
		$acl.SetAccessRuleProtection($True,$False)
		Set-Acl -LiteralPath $path -AclObject $acl
	}
    else {
        Write-Warning "Invalid path specified."
    }
}


<# 
  Author: Brandon C. Brin
  Date: 09/24/2015 - 16:30
  
.SYNOPSIS
Sets specified user as owner of specified folder and child items.

.DESCRIPTION
Sets user as owner of the specified folder and all child items.

.PARAMETER Path
Path to object to set ownership.

.PARAMETER Recurse
Set ownership on all child objects.

.EXAMPLE
Set-AdminAsOwner -User "luser" -Path "\\contoso.com\home\johndoe"
#>
Function Set-AdminAsOwner {
[Cmdletbinding()]
param(
	$Path = ".\",
	[Switch]$Recurse 
)
    $Owner = (New-Object System.Security.Principal.NTAccount("BUILTIN","Administrators"))

    if(Test-Path -Path $Path) {
		$acl = Get-Acl -Path $Path -ErrorAction Stop
		$acl.SetOwner($Owner)
		Set-Acl -Path $Path -AclObject $acl
	
		if($Recurse -and (Get-Item -Path $Path).IsPSContainer) {
			$Paths = Get-ChildItem -Path $Path -ErrorVariable $err -ErrorAction SilentlyContinue -Recurse
		
			foreach ($Path in $Paths) {
				if(!(Test-Path -Path $Path.FullName)) {
					Write-Output ("Problem with: " + $Path.FullName)
				}
				$acl = Get-Acl -Path $Path.FullName
				if($acl -eq $null) {
					Write-Output ("Problem with: " + $Path.FullName)
					Break
				}
				$acl.SetOwner($Owner)
				Set-Acl -Path $Path.FullName -AclObject $acl
			}
		
			foreach ($error in $err) {
				Write-Output ("Path too long: " + $error.TargetObject)
			}
		}
        else {
            if($Recurse) {
                Write-Warning "Unable to Recurse: Specified path is not a directory."
            }
        }
	}
    else {
        Write-Warning "Invalid path specified."
    }
}    


<# 
  Author: Brandon C. Brin
  Date: 10/29/2015 - 12:30
  
.SYNOPSIS
Finds object path names which exceeds the path length restrictions.

.DESCRIPTION
Prints object files names which exceed 260 characters. Also recursively searches for object names which exceed the maximum path length.

.PARAMETER Path
Path to check length restrictions.

.PARAMETER Recurse
Search all child objects.

.EXAMPLE
Find-PathTooLong -Path "\\contoso.com\home"
#>
Function Find-PathTooLong {
[Cmdletbinding()]
param (
	$Path = "\\contoso.com\shared\hr"
)
    if(Test-Path -Path $Path) {
	    $files = Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue -ErrorVariable err
	    foreach ($er in $err) {
		    Write-Output $er.TargetObject
	    }
	
	    $i = 0
	    foreach ($file in $files) {
		    Write-Progress -act "Searching ACLs" -status "checking $file.FullName" -percent ($i/ $files.count*100) 
		 
		    try {
			    $acl = Get-Acl -Path $file.FullName 
		    }
		     catch { 
				    Write-Output $file.FullName 
			    }
		    $i++  
	    }
    }
    else {
        Write-Warning "Invalid path specified."
    }
}


<# 
  Author: Brandon C. Brin
  Date: 10/12/2015 - 14:33
  
.SYNOPSIS
Sets specified user as owner of object specified.

.DESCRIPTION
Sets specified user as the owner of the specified object.

.PARAMETER Path 
Path to object

.PARAMETER User
LEGIS user to set as owner.

.PARAMETER Recurse
If directory, recurse child items.

.EXAMPLE
Set-Owner -User "luser" -Path "\\contoso.com\home\johndoe"
#>
Function Set-Owner {
[Cmdletbinding()]
param(
	$Path = "\\contoso.com\home\johndoe",
	$user = "johndoe",
	[Switch]$Recurse
	
)
		$newOwner = New-Object System.Security.Principal.NTAccount("LEGIS",$user)
		
        if(Test-Path -Path $Path) {
		    #top level
		    $acl = Get-Acl -Path $Path
		    $acl.SetOwner($newOwner)
		    Set-Acl -Path $Path -AclObject $acl
		
		    if($Recurse) {
			    #children
			    $folders = Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue -ErrorVariable err -Force
			    $i = 0
			    foreach ($folder in $folders.FullName) {
				    Write-Progress -act "Setting new owner" -status "Modifying $folder" -percent ($i/ $folders.count*100)
				    $acl = Get-Acl -LiteralPath $folder -ErrorAction SilentlyContinue
				    if($acl -eq $null) {
					    Write-Output ("ACL error for " + $folder) 
				    }
				    else {
				    $acl.SetOwner($newOwner)
				    Set-Acl -LiteralPath $folder -AclObject $acl
				    }
				    $i++
			    }
			
			    #print path errors
			    foreach ($record in $err) {
				    Write-Output ("Path too long:" + $record.TargetObject)
			    }
		    }
		    else {
			    if((!((Get-Item -Path $path).PSIsContainer)) -and $Recurse) {
				    Write-Warning ("The specified path is not a directory.")
			    }
		    }
        }
        else {
            Write-Warning "Invalid path specified" 
        }
	}

