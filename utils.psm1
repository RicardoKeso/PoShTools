<#
.NOTES
    Author:  RicardoKeso (ricardokeso@ricardokeso.com)
    Criacao: 20230519
    UltimaAtualizacao: 20230519
#>

function Utils_GetSHA256 { # Versoes do posh < 3 não contem a funcao get-filehash
    param (
        [string]$caminho
    );

    $sha256 = New-Object -TypeName System.Security.Cryptography.SHA256CryptoServiceProvider;
    $hash = [System.BitConverter]::ToString($sha256.ComputeHash([System.IO.File]::ReadAllBytes($caminho)));
    
    return $hash.Replace("-", "");
}


function Utils_EnviarEmail {

    <#
    .NOTES
        Nome            : Funcao: EnviarEmail
        Autor           : RicardoKeso (ricardokeso@ricardokeso.com)
        Prerequisitos   : PowerShell V2.0 ou Superior
        Criacao         : 20210428

    .SYNOPSIS 

    .DESCRIPTION
        Enviar E-Mail 

    .EXAMPLE
        EnviarEmail -remetente "teste@teste.com" -destinatario "ricardokeso@ricardokeso.com" -titulo "teste" -mensagem "Funciona!!!" -senhaRemetente "senhaAqui" -nomeRemetente "TESTE";

    .LINK
        https://www.ricardokeso.com
        
    #>

    param (
        [parameter(Mandatory = $true)][String]$remetente, 
        [parameter(Mandatory = $true)][String]$destinatario, 
        [parameter(Mandatory = $true)][String]$titulo, 
        [parameter(Mandatory = $true)][String]$mensagem, 
        [parameter(Mandatory = $true)][String]$senhaRemetente,
        [String]$nomeRemetente,
        [String]$anexo
    );

    $poshVersion = ($true, $false)[!($PSVersionTable["PSVersion"].Major -eq 2)];
    $SMTPSrv = "smtp.gmail.com";
    $SMTPPorta = "587";

    if (!$poshVersion){
        try {
            $senhaSec = ConvertTo-SecureString -String $senhaRemetente -ErrorAction Stop;
            $credencial = New-Object System.Management.Automation.PSCredential($remetente, $senhaSec);
        } catch {
            Write-Output "A senha esta incorreta ou nao esta criptografada.";
            Break;
        }
    } else {
        $credencial = New-Object System.Net.NetworkCredential($remetente, $senhaRemetente);
    }

    $mensagem += "`n`n`nEmail enviado por: ($($env:ComputerName + " \ " + $env:UserName)).";

    $message = New-Object System.Net.Mail.MailMessage;
    $message.subject = $titulo;
    $message.body = $mensagem;
    $message.IsBodyHtml = $false;
    $message.to.add($destinatario);
    $message.from = $nomeRemetente + " " + $remetente;
    if($anexo){$message.attachments.add($anexo)}

    try {        
        $smtp = New-Object System.Net.Mail.SmtpClient($SMTPSrv, $SMTPPorta);
        $smtp.UseDefaultCredentials = $false;
        $smtp.Credentials = $credencial;
        $smtp.EnableSsl = $true;
        $smtp.send($message);
        Write-Output -InputObject "Email enviado.";
    }
    catch {
        Write-Output "Credenciais incorretas.";
        Break;
    }
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Export-ModuleMember -Function Utils_GetSHA256;
Export-ModuleMember -Function Utils_EnviarEmail;


<#
function DownUtils_RK {
    param (
        [string]$caminho
    );

    $arquivo = "utils.psm1";
    $down = "https://raw.githubusercontent.com/RicardoKeso/PoShTools/master/$($arquivo)";

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
        (Invoke-WebRequest -Uri $down).Content | Out-File ($env:Temp + "\" + $arquivo);
        Import-Module ($env:Temp + "\" + $arquivo) -Force;

        if ( -not (Test-Path -Path ($caminho + $arquivo)) ) {
            Copy-Item -Path ($env:Temp + "\" + $arquivo) -Destination $caminho;
        }
        elseif ( (Utils_GetSHA256 -caminho ($env:Temp + "\" + $arquivo)) -ne (Utils_GetSHA256 -caminho ($caminho + $arquivo)) ) {
            Copy-Item -Path ($env:Temp + "\" + $arquivo) -Destination $caminho -Force;
        }

        return $arquivo;
    }
    catch {
        "$(Get-Date) - Falha no download do arquivo: $($arquivo)" | Out-File ($caminho + "log.txt") -Append;
        return $null;
    }
}
#>