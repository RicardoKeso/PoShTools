<#
.NOTES
    Author:  RicardoKeso (ricardokeso@ricardokeso.com)
    Criacao: 20230519
    UltimaAtualizacao: 20230519
#>

function Utils_GetSHA256 {
    # Versoes do posh < 3 não contem a funcao get-filehash
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
        [parameter(Mandatory = $true)][String]$nomeRemetente,
        [String]$anexo
    );

    $poshVersion = ($true, $false)[!($PSVersionTable["PSVersion"].Major -eq 2)];
    $SMTPSrv = "smtp.gmail.com";
    $SMTPPorta = "587";

    if (!$poshVersion) {
        try {
            $senhaSec = ConvertTo-SecureString -String $senhaRemetente -ErrorAction Stop;
            $credencial = New-Object System.Management.Automation.PSCredential($remetente, $senhaSec);
        }
        catch {
            Write-Output -InputObject "A senha esta incorreta ou nao esta criptografada.";
            Break;
        }
    }
    else {
        $credencial = New-Object System.Net.NetworkCredential($remetente, $senhaRemetente);
    }

    $mensagem += "`n`n`nEmail enviado por: '$($env:UserName)' via computador: '$($env:ComputerName)'.";

    $message = New-Object System.Net.Mail.MailMessage;
    $message.subject = $titulo;
    $message.body = $mensagem;
    $message.IsBodyHtml = $false;
    $message.to.add($destinatario);
    $message.from = $nomeRemetente + " " + $remetente;
    if ($anexo) { $message.attachments.add($anexo) }

    try {
        $smtp = New-Object System.Net.Mail.SmtpClient($SMTPSrv, $SMTPPorta);
        $smtp.UseDefaultCredentials = $false;
        $smtp.Credentials = $credencial;
        $smtp.EnableSsl = $true;
        $smtp.send($message);

        Write-Output -InputObject "Email enviado.";
    }
    catch {
        # Write-Output "Credenciais incorretas.";
        # $Error[0].Exception.Message | Out-File $([string]$MyInvocation.MyCommand + ".log");
        Write-Output -InputObject ($Error[0].Exception.Message);
    }
}

function Utils_Compactar_7Zip {
    param (
        [string]$arquivoDestino,
        [string[]]$arquivosOrigem
    );

    $arquivoDestino = $($arquivoDestino + ".7z");
    $argumentos = @("a", "-bd", "-mmt8", "-mx1", "-t7z", "-m0=lzma2", $arquivoDestino, $arquivosOrigem);
    $compactador = "C:\Program Files\7-Zip\7z.exe";

    if (Test-Path $compactador) {
        try {
            & $compactador $argumentos;
            return $true;
        }
        catch {
            $Error[0].Exception.Message | Out-File $([string]$MyInvocation.MyCommand + ".log");
            return $false;
        }
    }
}

function Utils_CriptografarSenha {

    <#
    .NOTES
        Nome            : Funcao: CriptografarSenha
        Autor           : RicardoKeso (ricardokeso@ricardokeso.com)
        Prerequisitos   : PowerShell V2.0 ou Superior
        Criacao         : 20210428

    .SYNOPSIS 

    .DESCRIPTION
        1-Criptografar senha convertendo-a em StringSegura em texto plano;
        2-Utiliza como parametro interno a dataHora do host, gerando senhas diferentes porem validas;
        3-Cada host gera uma criptografia diferente para a mesma senha;
        4-A criptografia so e valida para para o usuario que a gerou;
        5-So pode ser descriptografada obdecendo os itens 3 e 4 desta lista;

    .EXAMPLE
        CriptografarSenha -senha "suaSenha";

    .LINK
        https://www.ricardokeso.com
        
    #>

    param (
        [String]$senha
    );

    if ($senha) {
        $pwdSeg = ConvertTo-SecureString -AsPlainText $senha -Force;
    } 
    else {
        $pwdSeg = Read-Host -AsSecureString -Prompt "Senha a ser criptografada";
    }
    
    Write-Output -InputObject $(ConvertFrom-SecureString -SecureString $pwdSeg);
}

function Utils_DescriptografarSenha {

    <#
    .NOTES
        Nome            : Funcao: DescriptografarSenha
        Autor           : RicardoKeso (ricardokeso@ricardokeso.com)
        Prerequisitos   : PowerShell V2.0 ou Superior
        Criacao         : 20230607

    .SYNOPSIS 

    .DESCRIPTION
        1-Desriptografar senha a partir do texto plano resultante de StringSegura;
        2-Cada host gera uma criptografia diferente para a mesma senha;
        3-A criptografia so e valida para para o usuario que a gerou;
        4-So pode ser descriptografada obdecendo os itens 2 e 3 desta lista;

    .EXAMPLE
        DescriptografarSenha -criptoPlana "stringSegura";

    .LINK
        https://www.ricardokeso.com
        
    #>

    param (
        $criptoPlana
    );

    try {
        if ($criptoPlana) {
            $objCripto = $criptoPlana | ConvertTo-SecureString
            return [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($objCripto));
        } 
    }
    catch {
        $Error[0].Exception.Message;
    }
}

function Utils_PadronizarCaminhoUNC {

    <#
    .NOTES
        Nome            : Funcao: PadronizarCaminhoUNC
        Autor           : RicardoKeso (ricardokeso@ricardokeso.com)
        Prerequisitos   : 
        Criacao         : 20210502

    .SYNOPSIS 

    .DESCRIPTION
        Garantir que o caminho UNC sempre finalize com uma contra-barra(barra invertida)

    .EXAMPLE
        PadronizarCaminhoUNC -caminho "\\pasta\compartilhada";

    .LINK
        https://www.ricardokeso.com
        
    #>

    param(
        [String]$caminho
    );

    $lastChar = $caminho.Substring($caminho.Length - 1)

    if ($lastChar -ne '\') {
        $caminho += '\'
    }

    return $caminho;
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Export-ModuleMember -Function Utils_GetSHA256;
Export-ModuleMember -Function Utils_EnviarEmail;
Export-ModuleMember -Function Utils_Compactar_7Zip;
Export-ModuleMember -Function Utils_CriptografarSenha;
Export-ModuleMember -Function Utils_DescriptografarSenha;
Export-ModuleMember -Function Utils_PadronizarCaminhoUNC;

<#

# Funcao para realizar o download desse script automaticamente

$caminhoScripts = "";

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

$arquivo = DownUtils_RK -caminho $caminhoScripts;

if (Test-Path ($caminhoScripts + $arquivo)) {
    Import-Module ($caminhoScripts + $arquivo) -Force;
}
#>