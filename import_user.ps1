# Script de création d'Utilisateur
 
#Déclaration des variables
$Domain = "DC"  # Déclarez ici votre Domaine
$Ext = "lan"  # Déclarez ici l'extension (com, info, lan, local....)
$Server ="FQDN.lan"  # Déclarez ici le serveur d'exécution
$FQDN ="@FQDN"  # Déclarez ici le nom du Domaine précédé de "@" cela servira pour la création du UserPrincipalName
$LogFolder = "C:\LogImmobulus" # Déclarez ici l'emplacement du répertoire de Log
$Folder = "Logname" # Déclarez ici le nom du répertoire de Log
$LogFile = "C:\path\LogScript.txt" # Déclarez ici l'emplacement du fichiers de Log du script
$File = "LogScript.txt" # Déclarez ici le nom du fichier de Log du script
$LogError = "C:\path\LogError.txt" # Déclarez ici l'emplacement du fichier d'erreur global
$LogCatch = "C:\path\LogCatch.txt" # Déclarez ici l'emplacement du fichier de gestion de l'erreur
$FileCatch = "LogCatch.txt" # Déclarez ici le nom du fichier de gestion de l'erreur
$CSV = "C:\Users\Administrateur\Desktop\test.csv" # Déclarez ici le chemin d'accès à votre fichier csv
 
 
# Avant de commencer nous allons créer un répertoire et un fichier pour les logs
if (!(Test-Path $logfolder)) {
 
    New-Item -Name $Folder -Path C:\ -type directory
    New-Item -Name $File -Path $LogFolder -type file
    New-Item -Name $FileCatch -Path $LogFolder -type file
    Write-Output "Le dossier $Folder n'existait pas, création du Dossier $Folder, du fichier $File et $FileCatch" | Add-Content $LogFile
                                }
Else {
    Write-Output "Le dossier $Folder existe déjà!" | Add-Content $LogFile
        }
 
# Import du module Active Directory et import du fichier csv
 
Import-Module ActiveDirectory
 
Import-Csv -Delimiter ";" -Path $CSV | ForEach-Object {
    $OU =$_."OrganizationalUnit"
 
    # Test de la présence de l'unité d'organisation et création si elle n'existe pas
 
    if ((Get-ADOrganizationalUnit -Filter {Name -eq $OU}) -eq $null) {
        Write-Output "l'unité d'organisation $OU n'existe pas, création de la nouvelle Unité d'organisation" | Add-Content $LogFile
        Try {
            New-ADOrganizationalUnit -Name $OU -Path "DC=$Domain,DC=$Ext" -ErrorAction Stop -ErrorVariable eOU
                }
        Catch{
            "Une erreur $eOU a eu lieu à $((Get-Date).DateTime)"  | Add-Content $LogCatch
                }
        Finally{
            "Fin de l'opération Ajout d'une OU"
                }
                                                                        }
    Else {
        Write-Output "l'unité d'organisation $OU existe déjà" | Add-Content $LogFile
            }
    $User =$_."SamAccountName"
    $DisplayName =$_."DisplayName"
    $GivenName =$_."GivenName"
    $Name =$_."Name"
    $SamAccountName =$_."SamAccountName"
    $Surname =$_."Surname"
    $EmailAddress =$_."EmailAdress"
    $OfficePhone  =$_."OfficePhone"
 
    # Test de la présence de l'utilisateur et création si il n'existe pas
 
    if ((Get-ADUser -Filter {SamAccountName -eq $User}) -eq $null) {
        Write-Output "l'utilisateur $User n'existe pas, création du nouvel utilisateur" | Add-Content $LogFile
        Try {
            New-ADUser -DisplayName:$DisplayName -GivenName:$GivenName -Name:$Name -EmailAddress:$EmailAddress -OfficePhone:$OfficePhone -Path:"OU=$OU,DC=$Domain,DC=$Ext" -SamAccountName:$SamAccountName -Server:"$Server" -Surname:$Surname -Type:"user" -UserPrincipalName:"$SamAccountName$FQDN"  -AccountPassword:(ConvertTo-SecureString -AsPlainText "enterpasswordforusers" -Force) -Enabled:$true -AccountNotDelegated:$false -AllowReversiblePasswordEncryption:$false -CannotChangePassword:$false -PasswordNeverExpires:$true -ChangePasswordAtLogon:$true -ErrorAction Stop -ErrorVariable eUser
                }
    Catch{
        "L'erreur $eUser s'est produite à $((Get-Date).DateTime)" | Add-Content $LogCatch
            }
    Finally{
        "Fin de l'opération Ajout d'un Utilisateur"
            }
                                                                        }
    Else {
        Write-Output "l'utilisateur existe déjà" | Add-Content $LogFile
            }
                                                                                                                    }
 
# Récupérations des erreurs
 
$Error > $LogError
